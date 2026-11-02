"""Synthetic typed projections test correspondence; real bridge tests live in Knowledge."""
from dataclasses import asdict, replace
import hashlib
import json
import unittest
from unittest.mock import patch

from azazel_mio.learning_data import SnapshotLineage, digest
from azazel_mio.learning_offline import DatasetGateError, evaluate, fit
from azazel_mio.snapshot_input import (ConsumedSnapshotInput, SnapshotInputContext,
    SnapshotRecordBinding, SnapshotSourceBinding, _frame_digest,
    consumed_projection_digest, learning_payload_digest, practice_outcome_digest)
from test_offline_ranking import NOW, EXPIRY, dataset, example

AS_OF = '2026-10-30T00:00:00Z'
CONTENT = 'a' * 64
SNAPSHOT = 'ks-' + CONTENT[:24]


def ref(index): return 'ksr-' + f'{index:032x}'


def consume(rows, *, reviewed=False, rights='training_and_evaluation'):
    """Fixture projection only, not a Knowledge validation/authentication substitute."""
    source = SnapshotSourceBinding('edge:fixture', 'tenant-fixture', 'internal', rights,
        'fixture-rights', ('fixture-origin',), '2026-09-01T00:00:00Z', '2027-01-01T00:00:00Z')
    material = json.dumps([asdict(source)], ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    metadata = hashlib.sha256(material.encode()).hexdigest()
    converted, bindings = [], []
    for index, row in enumerate(rows, 1):
        lineage = SnapshotLineage('azazel-knowledge', SNAPSHOT, 'curated-projection-v1', AS_OF,
            EXPIRY, rights, source.rights_reference, row.snapshot.feature_version, row.snapshot.label_version, source.lineage)
        row = replace(row, example_id=ref(index), incident_group=ref(index + 100), entity_group=ref(index + 200),
            source_kind='curated_observation', snapshot=lineage,
            reviewer=row.reviewer if reviewed else None, outcome=row.outcome if reviewed else None)
        if row.outcome is not None:
            row = replace(row, outcome=replace(row.outcome, example_id=row.example_id,
                frame_digest=digest(row.frame.to_dict()), frame_evidence_refs=row.frame.evidence_refs))
        converted.append(row)
        bindings.append(SnapshotRecordBinding(row.example_id, source.source_ref, row.frame.created_at,
            hashlib.sha256(str(index).encode()).hexdigest(), row.incident_group, row.entity_group,
            _frame_digest(row.frame), ref(300), ref(400), 'ev:ssh:1', learning_payload_digest=learning_payload_digest(row),
            practice_record_ref=row.outcome.practice_record_ref if row.outcome else None,
            practice_payload_digest=practice_outcome_digest(row) if row.outcome else None))
    value = ConsumedSnapshotInput(SNAPSHOT, CONTENT, 'azazel-knowledge', 'curated-projection-v1', 'training',
        'tenant-fixture', 'internal', AS_OF, NOW, EXPIRY, 'rev-v1', (source.source_ref,), len(rows), len(rows),
        len(rows), metadata, material, (source,), tuple(bindings))
    context = SnapshotInputContext('tenant-fixture', 'internal', NOW, 'rev-v1',
        consumption_bindings=((value.snapshot_id, consumed_projection_digest(value)),))
    return converted, value, context


def new_consumption_context(value, context):
    """Synthetic producer fixture mints a new receipt binding, never an annotation bypass."""
    return replace(context, consumption_bindings=((value.snapshot_id, consumed_projection_digest(value)),))


def run(rows, value, context, *, partitions=None, now=NOW):
    return evaluate(rows, partitions if partitions is not None else {row.example_id: 'test' for row in rows},
                    now=now, artifact_expires_at=EXPIRY, snapshot_inputs=(value,), snapshot_context=context)


class SnapshotInputTests(unittest.TestCase):
    def test_cli_accepts_valid_snapshot_bindings_and_rejects_unsafe_shape(self):
        import os
        from pathlib import Path
        import subprocess
        import sys
        import tempfile

        rows, value, context = consume([example(1, 1)])
        root = Path(__file__).resolve().parents[1]
        workspace = root / '.codex-work'
        workspace.mkdir(exist_ok=True)
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(root / 'src')}
        with tempfile.TemporaryDirectory(dir=workspace) as directory:
            path = Path(directory)
            manifest = {'examples': [row.to_dict() for row in rows], 'partitions': {rows[0].example_id: 'test'},
                'now': NOW, 'artifact_expires_at': EXPIRY, 'revoked_snapshots': [],
                'costs': {'wrong_selection': 1.0, 'abstention': .25}, 'snapshot_inputs': [asdict(value)],
                'snapshot_context': asdict(context)}
            (path / 'valid.json').write_text(json.dumps(manifest))
            command = [sys.executable, '-B', '-m', 'azazel_mio.learning_offline', str(path / 'valid.json'),
                '--report', str(path / 'report.json')]
            subprocess.run(command, env=env, capture_output=True, text=True, check=True)
            report = json.loads((path / 'report.json').read_text())
            self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
            self.assertTrue(report['knowledge_curated_snapshot_connected'])
            self.assertEqual(report['knowledge_curated_snapshot_connected'], report['knowledge_curated_snapshot_projection_consistent'])
            self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
            self.assertIn('curated_snapshot_input_connected_not_training_evidence', report['limits'])
            self.assertFalse(report['automatic_promotion'])

            unsafe = dict(manifest)
            unsafe['snapshot_context'] = dict(manifest['snapshot_context'], current_generation=value.generation)
            (path / 'unsafe.json').write_text(json.dumps(unsafe))
            rejected = subprocess.run([sys.executable, '-B', '-m', 'azazel_mio.learning_offline',
                str(path / 'unsafe.json'), '--report', str(path / 'unsafe-report.json')],
                env=env, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('invalid_snapshot_context_shape', rejected.stderr)
            self.assertFalse((path / 'unsafe-report.json').exists())

    def test_valid_input_connection_is_separate_from_reviewed_labels_and_training(self):
        rows, value, context = consume([example(1, 1)])
        report, artifact = run(rows, value, context)
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertTrue(report['knowledge_curated_snapshot_connected'])
        self.assertEqual(report['knowledge_curated_snapshot_connected'], report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        self.assertEqual(report['curated_training_eligible_examples'], 0)
        self.assertFalse(report['curated_independent_outcome_labels_available'])
        self.assertIn('review_missing', report['quarantine'][0]['reasons'])
        self.assertIsNone(artifact)
        self.assertFalse(report['real_world_holdout_verified'])
        self.assertEqual(report['decision'], 'retain_existing_select_playbook')
        provenance = report['snapshot_input_provenance'][0]
        self.assertEqual(provenance['metadata_digest'], value.metadata_digest)
        self.assertNotIn('metadata_canonical_json', provenance)
        self.assertIn('not_authentication_or_truth_proof', provenance['limits'])

    def test_no_boolean_or_context_alone_can_claim_connection_or_labels(self):
        rows, value, context = consume([example(1, 1)])
        report, _ = evaluate(rows, {rows[0].example_id:'test'}, now=NOW, artifact_expires_at=EXPIRY, snapshot_context=context)
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertIn('snapshot_provenance_missing_or_rejected', report['quarantine'][0]['reasons'])
        with self.assertRaises(TypeError): replace(value, independent_labels_available=True)
        with self.assertRaises(TypeError): evaluate([], {}, now=NOW, artifact_expires_at=EXPIRY, knowledge_curated_snapshot_projection_consistent=True)
        report, _ = run(rows, value, None)
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
        receipt_only = replace(value, record_bindings=(), record_count=1, example_count=0, evaluation_input_count=0)
        report, _ = run([], receipt_only, context, partitions={})
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])

    def test_missing_frame_reaches_quarantine_without_a_fabricated_defensive_state(self):
        rows, value, context = consume([example(1, 1)])
        record = replace(value.record_bindings[0], frame_digest=None, boot_ref=None, generation_ref=None,
                         correlation_evidence_ref=None, quarantine_reason='missing_frame_context', learning_payload_digest=None)
        value = replace(value, record_bindings=(record,), example_count=0)
        context = new_consumption_context(value, context)
        raw = {'example_id': record.record_ref, 'source_record': {'observation': 'source data has no defensive state'},
               'bridge_quarantine': 'missing_frame_context'}
        from azazel_mio import MioSituationFrame
        with patch.object(MioSituationFrame, 'build', side_effect=AssertionError('must not invent state')):
            report, artifact = run([raw], value, context, partitions={})
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        self.assertEqual(report['snapshot_input_provenance'][0]['frame_quarantine'][0]['reasons'], ['missing_frame_context'])
        self.assertEqual(report['results']['test']['baseline']['examples'], 0)
        self.assertEqual(report['quarantine'][0]['reasons'], ['malformed_example'])
        self.assertIsNone(artifact)

    def test_current_scope_time_and_revocation_are_rechecked(self):
        rows, value, context = consume([example(1, 1)])
        contexts = [None, replace(context, tenant_ref='another-tenant'), replace(context, privacy_class='public'),
            replace(context, checked_at='2026-10-30T00:00:00Z'), replace(context, revocation_version='rev-v2')]
        contexts += [replace(context, revoked_refs=(target,)) for target in (value.snapshot_id, value.source_refs[0], rows[0].example_id)]
        for bad in contexts:
            with self.subTest(context=bad):
                report, artifact = run(rows, value, bad)
                self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
                self.assertEqual(report['curated_training_eligible_examples'], 0)
                self.assertIsNone(artifact)
        report, _ = run(rows, value, replace(context, checked_at=EXPIRY), now=EXPIRY)
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])

    def test_actual_example_metadata_frame_group_and_evidence_must_match(self):
        rows, value, context = consume([example(1, 1)])
        row = rows[0]
        variants = [replace(row, snapshot=replace(row.snapshot, generation='other-generation')),
            replace(row, snapshot=replace(row.snapshot, rights_reference='other-rights')),
            replace(row, snapshot=replace(row.snapshot, lineage=('other-lineage',))),
            replace(row, snapshot=replace(row.snapshot, as_of='2026-10-29T00:00:00Z')),
            replace(row, snapshot=replace(row.snapshot, expires_at='2026-11-01T00:00:00Z')),
            replace(row, incident_group=ref(900)), replace(row, entity_group=ref(901)),
            replace(row, frame=example(2, 2, 'scan').frame), replace(row, direct_evidence_refs=('ev:ssh:2',)),
            replace(row, features_as_of='2026-10-02T00:00:00Z')]
        for bad in variants:
            with self.subTest(row=bad):
                report, artifact = run([bad], value, context)
                self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
                self.assertIsNone(artifact)
                self.assertTrue(report['snapshot_input_provenance'][0]['rejection_reasons'])
        report, _ = run([], value, context, partitions={})
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
        with self.assertRaises(DatasetGateError): run([row, row], value, context)

    def test_revoked_bound_practice_record_blocks_connection_and_training(self):
        original, original_parts = dataset()
        rows, value, context = consume(original, reviewed=True)
        parts = {row.example_id: original_parts[old.example_id] for row, old in zip(rows, original)}

        report, artifact = run(rows, value, context, partitions=parts)
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        self.assertEqual(report['curated_training_eligible_examples'], 2)
        self.assertIsNotNone(artifact)

        revoked_context = replace(context, revoked_refs=(rows[0].outcome.practice_record_ref,))
        report, artifact = run(rows, value, revoked_context, partitions=parts)
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertEqual(report['curated_training_eligible_examples'], 0)
        self.assertIsNone(artifact)
        self.assertIn('snapshot_currently_revoked', report['snapshot_input_provenance'][0]['rejection_reasons'])
        self.assertIn('snapshot_currently_revoked', report['quarantine'][0]['reasons'])

    def test_changed_review_payload_is_quarantined_with_valid_frame_and_receipt(self):
        rows, value, context = consume([example(1, 1)], reviewed=True)
        report, _ = run(rows, value, context)
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertEqual(report['quarantine'], [])

        changed = replace(rows[0], reviewer=replace(rows[0].reviewer, reviewer='other-reviewer'))
        self.assertEqual(_frame_digest(changed.frame), value.record_bindings[0].frame_digest)
        self.assertNotEqual(learning_payload_digest(changed), value.record_bindings[0].learning_payload_digest)
        report, artifact = run([changed], value, context)
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertEqual(report['snapshot_input_provenance'][0]['rejection_reasons'], [])
        rejection = next(row for row in report['quarantine'] if row.get('example_id') == changed.example_id)
        self.assertEqual(rejection['reasons'], ['snapshot_learning_payload_mismatch'])
        self.assertEqual(report['curated_training_eligible_examples'], 0)
        self.assertEqual(report['results']['test']['baseline']['examples'], 0)
        self.assertIsNone(artifact)

    def test_payload_mismatched_train_row_is_excluded_from_generated_artifact(self):
        original, original_parts = dataset()
        extra = example(7, 3)
        original.insert(2, extra)
        original_parts[extra.example_id] = 'train'
        rows, value, context = consume(original, reviewed=True)
        parts = {row.example_id: original_parts[old.example_id] for row, old in zip(rows, original)}

        report, artifact = run(rows, value, context, partitions=parts)
        self.assertEqual(report['quarantine'], [])
        self.assertEqual(report['curated_training_eligible_examples'], 3)
        self.assertIsNotNone(artifact)
        self.assertIn(digest(rows[2].to_dict()), artifact.training_digests)

        changed = replace(rows[2], reviewer=replace(rows[2].reviewer, reviewer='other-reviewer'))
        self.assertEqual(parts[changed.example_id], 'train')
        self.assertEqual(_frame_digest(changed.frame), value.record_bindings[2].frame_digest)
        self.assertNotEqual(learning_payload_digest(changed), value.record_bindings[2].learning_payload_digest)
        # Keep the original producer binding and consumption receipt after mutation.
        report, artifact = run([*rows[:2], changed, *rows[3:]], value, context, partitions=parts)
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertEqual(report['snapshot_input_provenance'][0]['rejection_reasons'], [])
        self.assertEqual(report['quarantine'], [{'example_id': changed.example_id,
                                               'reasons': ['snapshot_learning_payload_mismatch']}])
        self.assertEqual(report['curated_training_eligible_examples'], 2)
        self.assertEqual(report['partitions']['train'], 2)
        self.assertEqual({row.reviewer.label for row in rows[:2]},
                         {'auth-ambiguity-v1', 'scan-ambiguity-v1'})
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact.training_digests, tuple(sorted(digest(row.to_dict()) for row in rows[:2])))
        self.assertNotIn(digest(changed.to_dict()), artifact.training_digests)
        self.assertNotIn(digest(rows[2].to_dict()), artifact.training_digests)

    def test_example_rights_must_match_source_even_with_rebound_payload(self):
        rows, value, context = consume([example(1, 1)], reviewed=True, rights='evaluation_only')
        changed = replace(rows[0], snapshot=replace(rows[0].snapshot, rights='training_and_evaluation'))
        binding = replace(value.record_bindings[0], learning_payload_digest=learning_payload_digest(changed))
        value = replace(value, record_bindings=(binding,))
        context = new_consumption_context(value, context)
        report, artifact = run([changed], value, context)
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertEqual(report['snapshot_input_provenance'][0]['rejection_reasons'],
                         ['snapshot_example_metadata_mismatch'])
        self.assertIn('snapshot_example_metadata_mismatch', report['quarantine'][0]['reasons'])
        self.assertEqual(report['curated_training_eligible_examples'], 0)
        self.assertEqual(report['results']['test']['baseline']['examples'], 0)
        self.assertIsNone(artifact)

    def test_pinned_snapshot_requires_separate_practice_record_binding_for_outcome(self):
        rows, value, context = consume([example(1, 1)], reviewed=True)
        binding = replace(value.record_bindings[0], practice_record_ref='practice-other')
        changed = replace(value, record_bindings=(binding,))
        context = new_consumption_context(changed, context)
        report, artifact = run(rows, changed, context, partitions={rows[0].example_id: 'test'})
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        self.assertIsNone(artifact)
        rejection = next(row for row in report['quarantine'] if row.get('example_id') == rows[0].example_id)
        self.assertIn('snapshot_practice_outcome_binding_mismatch', rejection['reasons'])

    def test_utf8_frame_digest_is_not_the_ascii_learning_manifest_digest(self):
        rows, value, context = consume([example(1, 1)])
        row = replace(rows[0], frame=replace(rows[0].frame, mission='認証の観測を確認'))
        binding = replace(value.record_bindings[0], frame_digest=_frame_digest(row.frame), learning_payload_digest=learning_payload_digest(row))
        value = replace(value, record_bindings=(binding,))
        context = new_consumption_context(value, context)
        report, _ = run([row], value, context)
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        wrong_digest = digest(row.frame.to_dict()).removeprefix('sha256:')
        self.assertNotEqual(wrong_digest, binding.frame_digest)
        wrong = replace(value, record_bindings=(replace(binding, frame_digest=wrong_digest),))
        report, _ = run([row], wrong, context)
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])

    def test_legacy_revocation_input_cannot_be_overridden_by_a_receipt(self):
        rows, value, context = consume([example(1, 1)])
        report, artifact = evaluate(rows, {rows[0].example_id:'test'}, now=NOW, artifact_expires_at=EXPIRY,
            snapshot_inputs=(value,), snapshot_context=context, revoked_snapshots=(SNAPSHOT,))
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertIsNone(artifact)

    def test_digest_counts_policy_and_reference_shapes_are_closed(self):
        _, value, _ = consume([example(1, 1)])
        for changes in ({'metadata_digest':'f'*64}, {'metadata_canonical_json':'[]'}, {'content_digest':'b'*64},
                        {'purpose':'reference'}, {'record_count':True}, {'example_count':2}, {'feature_version':'other'},
                        {'source_refs':('edge:other',)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError): replace(value, **changes)
        record = value.record_bindings[0]
        with self.assertRaises(ValueError): replace(record, correlation_evidence_ref=record.record_ref)
        with self.assertRaises(ValueError): replace(record, frame_digest=None)
        with self.assertRaises(ValueError): replace(value, source_bindings=(replace(value.source_bindings[0], tenant_ref='other'),))
        with self.assertRaises(ValueError): replace(value, source_bindings=(replace(value.source_bindings[0], valid_until=NOW),))

    def test_receipt_cannot_expand_source_rights_into_training(self):
        original, original_parts = dataset()
        rows, value, context = consume(original, reviewed=True, rights='evaluation_only')
        parts = {row.example_id:original_parts[old.example_id] for row, old in zip(rows, original)}
        with self.assertRaisesRegex(DatasetGateError, 'training_rights_or_review_missing'):
            run(rows, value, context, partitions=parts)

    def test_independent_labels_and_training_are_derived_from_actual_gates(self):
        original, original_parts = dataset()
        rows, value, context = consume(original, reviewed=True)
        parts = {row.example_id:original_parts[old.example_id] for row, old in zip(rows, original)}
        with self.assertRaisesRegex(DatasetGateError, 'curated_training_requires_snapshot_evaluation'):
            fit(rows[:2], created_at=NOW, expires_at=EXPIRY)
        report, artifact = run(rows, value, context, partitions=parts)
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        self.assertTrue(report['curated_independent_outcome_labels_available'])
        self.assertEqual(report['curated_training_eligible_examples'], 2)
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact.use, 'evaluation_only')
        self.assertFalse(report['automatic_promotion'])
        self.assertFalse(report['real_world_holdout_verified'])
        self.assertEqual(report['decision'], 'retain_existing_select_playbook')
        # A valid projection with unknown entity identity is connected but cannot
        # supply an independent group/label or become training evidence.
        unknown = replace(rows[0], entity_group=None)
        binding = replace(value.record_bindings[0], entity_group=None, learning_payload_digest=learning_payload_digest(unknown))
        single = replace(value, record_count=1, example_count=1, evaluation_input_count=1, record_bindings=(binding,))
        context = new_consumption_context(single, context)
        report, artifact = run([unknown], single, context, partitions={unknown.example_id:'train'})
        self.assertTrue(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        self.assertFalse(report['curated_independent_outcome_labels_available'])
        self.assertEqual(report['curated_training_eligible_examples'], 0)
        self.assertIsNone(artifact)


if __name__ == '__main__': unittest.main()
