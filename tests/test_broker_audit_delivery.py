import concurrent.futures
import threading
import time

import pytest

from azazel_mio.broker import CapabilityBroker, CapabilitySpec
from azazel_mio.contracts import MioCapabilityRequest


def request(number=1):
    return MioCapabilityRequest(f'request-{number}', 'trace-1', 'query_recent_alerts',
                                purpose_hypothesis_ids=('h1',))


def wait_until(predicate):
    deadline = time.monotonic() + 2
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(.001)


def test_slow_sink_does_not_extend_handler_timeout_and_preserves_record():
    entered = threading.Event()
    release = threading.Event()
    records = []

    def sink(record):
        entered.set()
        release.wait(2)
        records.append(record)

    broker = CapabilityBroker({'query_recent_alerts': CapabilitySpec(
        handler=lambda _: {'value': 1, 'evidence_refs': ['ev:ssh:1']},
        timeout_seconds=.03, source_component='edge-local')}, audit_sink=sink)
    try:
        start = time.monotonic()
        result = broker.submit(request())
        elapsed = time.monotonic() - start
        assert elapsed < .15
        assert entered.wait(1)
        assert not release.is_set()
        assert result.ok and result.data == {'value': 1}
        assert 'audit_sink_queued' in result.limitations
    finally:
        release.set()
    wait_until(lambda: broker.audit_delivery_stats()['delivered'] == 1)
    assert records == list(broker.audit_records())
    assert records[0]['request_id'].startswith('h:')
    assert records[0]['trace_id'] == 'trace-1'
    assert records[0]['purpose_hypothesis_ids'] == ['h1']
    assert records[0]['source_component'] == 'edge-local'


def test_hung_sink_concurrent_cycles_have_bounded_queue_worker_and_visible_loss():
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def sink(record):
        calls.append(threading.get_ident())
        entered.set()
        release.wait(2)

    broker = CapabilityBroker(audit_sink=sink, audit_capacity=2)
    try:
        assert 'audit_sink_queued' in broker.submit(request()).limitations
        assert entered.wait(1)
        cycles = [broker.for_new_cycle() for _ in range(40)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda pair: pair[1].submit(request(pair[0] + 2)), enumerate(cycles)))
        stats = broker.audit_delivery_stats()
        assert stats['pending'] == 2
        assert stats['worker_running'] == 1
        assert stats['accepted'] == 3
        assert stats['dropped'] == 38
        assert len(calls) == 1
        assert sum('audit_sink_full' in r.limitations for r in results) == 38
        assert all(r.status == 'rejected' and not r.data for r in results)
    finally:
        release.set()
    wait_until(lambda: broker.audit_delivery_stats()['worker_running'] == 0)
    assert broker.audit_delivery_stats()['delivered'] == 3
    assert len(set(calls)) == 1


def test_sink_failure_and_local_eviction_are_observable():
    def sink(_):
        raise RuntimeError('private sink failure')

    broker = CapabilityBroker(audit_sink=sink, audit_capacity=1)
    result = broker.submit(request())
    wait_until(lambda: broker.audit_delivery_stats()['failed'] == 1)
    assert result.status == 'rejected'
    assert 'audit_sink_queued' in result.limitations
    broker.submit(request(2))
    wait_until(lambda: broker.audit_delivery_stats()['failed'] == 2)
    stats = broker.audit_delivery_stats()
    assert stats['local_evicted'] == 1
    assert stats['dropped'] == 0
    assert len(broker.audit_records()) == 1


def test_audit_worker_start_failure_is_returned_and_counted(monkeypatch):
    def fail_start(_):
        raise RuntimeError('cannot start worker')

    monkeypatch.setattr(threading.Thread, 'start', fail_start)
    broker = CapabilityBroker(audit_sink=lambda _: None)
    result = broker.submit(request())
    assert result.status == 'rejected'
    assert 'audit_sink_startup_uncertain' in result.limitations
    assert len(broker.audit_records()) == 1
    stats = broker.audit_delivery_stats()
    assert stats['dropped'] == 0
    assert stats['pending'] == stats['accepted'] == stats['worker_reserved'] == 1
    assert stats['worker_running'] == 0
    assert stats['startup_uncertain'] == stats['start_failures'] == 1


def test_audit_start_interrupt_reserves_slot_fail_closed(monkeypatch):
    import pytest

    def interrupt_start(_):
        raise KeyboardInterrupt()

    broker = CapabilityBroker(audit_sink=lambda _: None, audit_capacity=2)
    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, 'start', interrupt_start)
        with pytest.raises(KeyboardInterrupt):
            broker.submit(request())
    assert 'audit_sink_startup_uncertain' in broker.submit(request(2)).limitations
    assert 'audit_sink_full' in broker.submit(request(3)).limitations
    stats = broker.audit_delivery_stats()
    assert stats['pending'] == stats['accepted'] == 2
    assert stats['worker_running'] == 0
    assert stats['startup_uncertain'] == stats['worker_reserved'] == stats['start_attempts'] == 1
    assert stats['dropped'] == 1


def test_audit_start_then_interrupt_retains_single_worker_and_admission(monkeypatch):
    import pytest

    original_start = threading.Thread.start
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def sink(_):
        calls.append(threading.get_ident())
        entered.set()
        release.wait(2)

    def start_then_interrupt(worker):
        original_start(worker)
        raise KeyboardInterrupt()

    broker = CapabilityBroker(audit_sink=sink, audit_capacity=2)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(threading.Thread, 'start', start_then_interrupt)
            with pytest.raises(KeyboardInterrupt):
                broker.submit(request())
        assert entered.wait(1)
        assert 'audit_sink_queued' in broker.submit(request(2)).limitations
        assert 'audit_sink_queued' in broker.submit(request(3)).limitations
        assert 'audit_sink_full' in broker.submit(request(4)).limitations
        stats = broker.audit_delivery_stats()
        assert stats['worker_running'] == 1
        assert stats['pending'] == 2
        assert stats['accepted'] == 3
        assert stats['dropped'] == 1
        assert len(calls) == 1
    finally:
        release.set()
    wait_until(lambda: broker.audit_delivery_stats()['worker_running'] == 0)
    assert broker.audit_delivery_stats()['delivered'] == 3
    assert len(set(calls)) == 1


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_delayed_unobservable_bootstrap_keeps_one_start_reservation(monkeypatch, failure):
    import _thread
    import pytest

    original_start = threading.Thread.start
    original_bootstrap = threading.Thread._bootstrap
    bootstrap_entered = threading.Event()
    resume_bootstrap = threading.Event()
    delivered = []
    attempts = []

    def gated_bootstrap(worker):
        bootstrap_entered.set()
        assert resume_bootstrap.wait(2)
        original_bootstrap(worker)

    def interrupted_start(worker):
        attempts.append(worker)
        _thread.start_new_thread(original_start, (worker,))
        assert bootstrap_entered.wait(1)
        assert worker.ident is None and not worker.is_alive()
        raise failure()

    broker = CapabilityBroker(audit_sink=lambda record: delivered.append(record), audit_capacity=2)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(threading.Thread, '_bootstrap', gated_bootstrap)
            patch.setattr(threading.Thread, 'start', interrupted_start)
            if issubclass(failure, Exception):
                assert 'audit_sink_startup_uncertain' in broker.submit(request()).limitations
            else:
                with pytest.raises(failure):
                    broker.submit(request())
            for number in range(2, 30):
                result = broker.submit(request(number))
                assert ('audit_sink_startup_uncertain' if number == 2 else 'audit_sink_full') in result.limitations
            assert len(attempts) == 1
            stats = broker.audit_delivery_stats()
            assert stats['pending'] == 2
            assert stats['worker_running'] == 0
            assert stats['worker_reserved'] == stats['startup_uncertain'] == stats['start_attempts'] == 1
            assert stats['dropped'] == 27
    finally:
        resume_bootstrap.set()
    wait_until(lambda: broker.audit_delivery_stats()['delivered'] == 2)
    assert len(delivered) == 2
    assert broker.audit_delivery_stats()['startup_uncertain'] == 0


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt, SystemExit])
def test_completed_target_keeps_reservation_until_thread_termination(monkeypatch, failure):
    original_start = threading.Thread.start
    original_run = threading.Thread.run
    target_returned = threading.Event()
    release_teardown = threading.Event()
    workers = []
    records = []
    active = 0
    maximum_active = 0

    def sink(record):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        records.append(record)
        active -= 1

    def delayed_teardown(worker):
        workers.append(worker)
        original_run(worker)
        if len(workers) == 1:
            target_returned.set()
            assert release_teardown.wait(2)

    def start_then_raise(worker):
        original_start(worker)
        if failure is not None:
            raise failure()

    broker = CapabilityBroker(audit_sink=sink, audit_capacity=2)
    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, 'run', delayed_teardown)
        patch.setattr(threading.Thread, 'start', start_then_raise)
        try:
            if failure is not None and not issubclass(failure, Exception):
                with pytest.raises(failure):
                    broker.submit(request())
            else:
                broker.submit(request())
            assert target_returned.wait(1)
            assert workers[0].is_alive()
            for number in range(2, 20):
                start = time.monotonic()
                result = broker.submit(request(number))
                assert time.monotonic() - start < .15
                assert ('audit_sink_queued' if number < 4 else 'audit_sink_full') in result.limitations
            stats = broker.audit_delivery_stats()
            assert stats['worker_running'] == 0
            assert stats['worker_reserved'] == stats['start_attempts'] == 1
            assert stats['pending'] == 2
            assert stats['accepted'] == 3
            assert stats['dropped'] == 16
            assert len(workers) == len(records) == 1
        finally:
            release_teardown.set()
        workers[0].join(1)
        assert not workers[0].is_alive()
        # A full queue must not prevent reaping the terminated owner and
        # launching its successor to deliver the already accepted records.
        patch.setattr(threading.Thread, 'start', original_start)
        broker.submit(request(20))
        wait_until(lambda: broker.audit_delivery_stats()['delivered'] == 3)
        assert len(workers) == 2
        assert maximum_active == 1
        assert len(records) == 3
        assert len({record['request_id'] for record in records}) == 3
