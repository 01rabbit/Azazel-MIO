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
