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


@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_constructor_start_failure_retains_single_reservation(monkeypatch, failure):
    attempts = []

    def fail_start(worker):
        attempts.append(worker)
        raise failure()

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, 'start', fail_start)
        if not issubclass(failure, Exception):
            with pytest.raises(failure):
                CapabilityBroker(audit_sink=lambda _: None)
            assert len(attempts) == 1
            return
        broker = CapabilityBroker(audit_sink=lambda _: None, audit_capacity=2)
    cycles = [broker.for_new_cycle() for _ in range(20)]
    results = [cycle.submit(request(i)) for i, cycle in enumerate(cycles)]
    assert sum('audit_sink_full' in result.limitations for result in results) == 18
    assert len(attempts) == 1
    stats = broker.audit_delivery_stats()
    assert stats['pending'] == stats['accepted'] == 2
    assert stats['worker_reserved'] == stats['startup_uncertain'] == stats['start_attempts'] == stats['start_failures'] == 1


def test_standard_start_delayed_bootstrap_cannot_block_submit_or_duplicate_workers(monkeypatch):
    original_bootstrap = threading.Thread._bootstrap
    bootstrap_entered = threading.Event()
    release = threading.Event()
    captured = []
    constructed = []
    records = []

    def gated_bootstrap(worker):
        if worker.name == 'mio-audit-sink':
            delivery = worker._target.__self__
            captured.append((worker, next(iter(delivery.owners))))
            bootstrap_entered.set()
            assert release.wait(2)
        original_bootstrap(worker)

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, '_bootstrap', gated_bootstrap)
        constructor = threading.Thread(target=lambda: constructed.append(CapabilityBroker(
            {'query_recent_alerts': CapabilitySpec(handler=lambda _: {'value': 1},
             timeout_seconds=.05, max_calls_per_cycle=100)}, max_total_calls=100,
            audit_sink=lambda record: records.append(record), audit_capacity=2)))
        constructor.start()  # Standard Thread.start, also for the audit worker.
        try:
            assert bootstrap_entered.wait(1)
            worker, broker = captured[0]
            assert worker.ident is None and not worker.is_alive()
            start = time.monotonic()
            result = broker.submit(request())
            assert time.monotonic() - start < .05
            assert result.ok
            cycles = [broker.for_new_cycle() for _ in range(20)]
            for number, cycle in enumerate(cycles):
                start = time.monotonic()
                cycle.submit(request(number + 2))
                assert time.monotonic() - start < .05
            assert len(captured) == 1
            stats = broker.audit_delivery_stats()
            assert stats['pending'] == 2
            assert stats['start_attempts'] == stats['worker_reserved'] == stats['startup_uncertain'] == 1
        finally:
            release.set()
        constructor.join(1)
        assert not constructor.is_alive()
        wait_until(lambda: broker.audit_delivery_stats()['delivered'] == 2)
        # Successful construction also leaves submit independent of startup.
        start = time.monotonic()
        broker.submit(request(30))
        assert time.monotonic() - start < .05
        assert len(captured) == 1


def test_dispatcher_retires_after_all_family_owners_are_collected():
    import gc
    import weakref

    broker = CapabilityBroker(audit_sink=lambda _: None)
    cycle = broker.for_new_cycle()
    worker = broker._audit_delivery.worker
    owner = weakref.ref(broker)
    descendant = weakref.ref(cycle)
    del broker
    gc.collect()
    assert owner() is None
    assert worker.is_alive()  # The descendant still owns the same dispatcher.
    del cycle
    gc.collect()
    assert descendant() is None
    worker.join(1)
    assert not worker.is_alive()


@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_constructor_start_then_raise_keeps_exact_worker_and_retires(monkeypatch, failure):
    import gc

    original_start = threading.Thread.start
    workers = []

    def start_then_raise(worker):
        workers.append(worker)
        original_start(worker)
        raise failure()

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, 'start', start_then_raise)
        if issubclass(failure, Exception):
            broker = CapabilityBroker(audit_sink=lambda _: None)
            broker.submit(request())
            wait_until(lambda: broker.audit_delivery_stats()['delivered'] == 1)
            assert broker.audit_delivery_stats()['start_attempts'] == 1
            del broker
        else:
            with pytest.raises(failure):
                CapabilityBroker(audit_sink=lambda _: None)
    gc.collect()
    assert len(workers) == 1
    workers[0].join(1)
    assert not workers[0].is_alive()
