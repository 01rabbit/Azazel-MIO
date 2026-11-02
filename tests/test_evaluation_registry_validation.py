"""Negative-path validation for the evaluation-only registry (issue #2 expiry/revocation scope)."""
import copy
import unittest

from azazel_mio.ranking_registry import EvaluationRegistry

DIGEST_A = 'sha256:' + 'a' * 64
DIGEST_B = 'sha256:' + 'b' * 64
CREATED = '2026-10-31T00:00:00Z'
EXPIRES = '2026-12-01T00:00:00Z'

BASE = {
    'schema_version': 'mio.evaluation_registry.v1',
    'records': [],
    'selected': None,
    'history': [],
    'revoked_artifacts': [],
    'revoked_snapshots': [],
}


def digest_at(index):
    return 'sha256:' + format(index, '064x')


def record(digest=DIGEST_A, created=CREATED, expires=EXPIRES, snapshots=()):
    return {'artifact_digest': digest, 'created_at': created, 'expires_at': expires, 'snapshots': list(snapshots)}


def raw(**changes):
    value = copy.deepcopy(BASE)
    value.update(changes)
    return value


class EvaluationRegistryFromDictValidationTests(unittest.TestCase):
    def assertRejects(self, payload, code):
        with self.assertRaises(ValueError) as context:
            EvaluationRegistry.from_dict(payload)
        self.assertEqual(str(context.exception), code)

    def test_empty_registry_is_accepted(self):
        self.assertEqual(EvaluationRegistry.from_dict(copy.deepcopy(BASE)), EvaluationRegistry())

    def test_wrong_schema_version_is_rejected(self):
        self.assertRejects(raw(schema_version='mio.evaluation_registry.v0'), 'invalid_evaluation_registry')

    def test_unexpected_top_level_key_is_rejected(self):
        self.assertRejects({**raw(), 'extra': 1}, 'invalid_evaluation_registry')

    def test_missing_top_level_key_is_rejected(self):
        payload = raw()
        del payload['history']
        self.assertRejects(payload, 'invalid_evaluation_registry')

    def test_non_dict_payload_is_rejected(self):
        self.assertRejects(['mio.evaluation_registry.v1'], 'invalid_evaluation_registry')

    def test_records_must_be_a_list(self):
        self.assertRejects(raw(records={'not': 'a list'}), 'invalid_registry_records')

    def test_record_with_unexpected_field_is_rejected(self):
        self.assertRejects(raw(records=[{**record(), 'extra': True}]), 'invalid_registry_record')

    def test_record_with_non_increasing_interval_is_rejected(self):
        self.assertRejects(raw(records=[record(expires=CREATED)]), 'invalid_registry_interval')

    def test_record_with_reversed_interval_is_rejected(self):
        self.assertRejects(raw(records=[record(created=EXPIRES, expires=CREATED)]), 'invalid_registry_interval')

    def test_registry_timestamps_require_timezone_aware_strings(self):
        for field, value in (
            ('created', '2026-10-31T00:00:00'),
            ('created', 5),
            ('expires', '2026-10-31T00:00:00'),
            ('expires', 5),
        ):
            with self.subTest(field=field, value=value):
                interval = {'created': CREATED, 'expires': EXPIRES}
                interval[field] = value
                self.assertRejects(
                    raw(records=[record(**interval)]), 'invalid_learning_time'
                )

    def test_offset_timestamps_compare_by_instant(self):
        # These different offsets represent the same UTC instant.
        self.assertRejects(
            raw(records=[record(
                created='2026-10-31T00:00:00+09:00',
                expires='2026-10-30T15:00:00+00:00',
            )]),
            'invalid_registry_interval',
        )
        # The local timestamp sorts after the UTC timestamp as text, but is
        # one hour earlier as an instant and therefore forms a valid interval.
        accepted = EvaluationRegistry.from_dict(raw(records=[record(
            created='2026-10-31T00:00:00+09:00',
            expires='2026-10-30T16:00:00+00:00',
        )]))
        self.assertEqual(len(accepted.records), 1)

    def test_record_snapshots_must_be_bounded_codes(self):
        invalid = record()
        # Bypass record(), which normalizes its snapshots argument with list().
        invalid['snapshots'] = 'snapshot1'
        self.assertRejects(
            raw(records=[invalid]), 'invalid_learning_codes'
        )

    def test_duplicate_artifact_digest_is_rejected(self):
        self.assertRejects(raw(records=[record(), record()]), 'duplicate_registry_record')

    def test_selection_outside_records_is_rejected(self):
        self.assertRejects(raw(records=[record()], selected=DIGEST_B), 'unknown_registry_selection')

    def test_selection_must_be_a_string_or_null(self):
        self.assertRejects(raw(records=[record()], selected=5), 'unknown_registry_selection')

    def test_history_outside_records_is_rejected(self):
        self.assertRejects(raw(records=[record()], history=[DIGEST_B]), 'unknown_registry_history')

    def test_malformed_revoked_artifact_digest_is_rejected(self):
        self.assertRejects(raw(revoked_artifacts=['not-a-digest']), 'invalid_registry_digests')

    def test_malformed_record_digest_is_rejected(self):
        self.assertRejects(raw(records=[record(digest='sha256:XYZ')]), 'invalid_registry_digests')

    def test_non_empty_registry_roundtrips(self):
        state = EvaluationRegistry.from_dict(raw(
            records=[record(snapshots=('snapshot-1',))],
            selected=DIGEST_A,
            history=[DIGEST_A],
            revoked_artifacts=[DIGEST_B],
            revoked_snapshots=['snapshot-2'],
        ))
        self.assertEqual(EvaluationRegistry.from_dict(state.to_dict()), state)

    def test_registry_size_caps_are_enforced(self):
        cases = (
            (raw(records=[record()] * 129), 'invalid_registry_records'),
            (raw(history=[DIGEST_A] * 129), 'invalid_registry_digests'),
            (raw(revoked_snapshots=['snapshot-1'] * 2049), 'invalid_learning_codes'),
            (raw(revoked_artifacts=[digest_at(index) for index in range(129)]), 'invalid_registry_digests'),
            (raw(records=[record(snapshots=[f'snapshot-{index:04d}' for index in range(2049)])]), 'invalid_learning_codes'),
        )
        for payload, code in cases:
            with self.subTest(code=code):
                self.assertRejects(payload, code)

    def test_records_at_exact_maximum_are_accepted(self):
        digests = [digest_at(index) for index in range(128)]
        state = EvaluationRegistry.from_dict(raw(records=[record(digest=value) for value in digests]))
        self.assertEqual(len(state.records), 128)
        self.assertEqual([item.artifact_digest for item in state.records], digests)

    def test_history_at_exact_maximum_is_accepted(self):
        digests = [digest_at(index) for index in range(128)]
        state = EvaluationRegistry.from_dict(raw(
            records=[record(digest=value) for value in digests],
            history=digests,
        ))
        self.assertEqual(state.history, tuple(digests))

    def test_revoked_snapshots_at_exact_maximum_are_accepted(self):
        codes = [f'snapshot-{index:04d}' for index in range(2048)]
        state = EvaluationRegistry.from_dict(raw(revoked_snapshots=codes))
        self.assertEqual(state.revoked_snapshots, tuple(codes))

    def test_record_snapshots_at_exact_maximum_are_accepted(self):
        codes = [f'snapshot-{index:04d}' for index in range(2048)]
        state = EvaluationRegistry.from_dict(raw(records=[record(snapshots=codes)]))
        self.assertEqual(state.records[0].snapshots, tuple(codes))

    def test_revoked_artifacts_at_exact_maximum_are_accepted_and_roundtrip(self):
        digests = [digest_at(index) for index in range(128)]
        state = EvaluationRegistry.from_dict(raw(revoked_artifacts=digests))
        self.assertEqual(state.revoked_artifacts, tuple(digests))
        self.assertEqual(EvaluationRegistry.from_dict(state.to_dict()), state)


class EvaluationRegistryRevokeArgumentTests(unittest.TestCase):
    def test_revoke_without_target_is_rejected(self):
        with self.assertRaises(ValueError) as context:
            EvaluationRegistry().revoke()
        self.assertEqual(str(context.exception), 'one_revocation_target_required')

    def test_revoke_with_both_targets_is_rejected(self):
        with self.assertRaises(ValueError) as context:
            EvaluationRegistry().revoke(artifact_digest=DIGEST_A, snapshot='snapshot-1')
        self.assertEqual(str(context.exception), 'one_revocation_target_required')

    def test_revoke_rejects_malformed_artifact_digest(self):
        with self.assertRaises(ValueError) as context:
            EvaluationRegistry().revoke(artifact_digest='sha256:XYZ')
        self.assertEqual(str(context.exception), 'invalid_revocation_digest')

    def test_revoke_rejects_non_string_artifact_digest(self):
        with self.assertRaises(ValueError) as context:
            EvaluationRegistry().revoke(artifact_digest=5)
        self.assertEqual(str(context.exception), 'invalid_revocation_digest')


if __name__ == '__main__':
    unittest.main()
