"""Synthetic fixtures exercise gates; they are not real-world holdout evidence."""
from dataclasses import replace
import json
import unittest

from azazel_mio import MioSituationFrame
from azazel_mio.learning_data import (LearningExample, SnapshotLineage, ReviewerDisposition,
    TeacherCandidate, ObservedOutcome, FEATURE_VERSION, LABEL_VERSION, ORIGINS, digest, parse_json, quarantine_reasons)
from azazel_mio.learning_offline import DatasetGateError, evaluate, prepare
from azazel_mio.playbook_ranker import RankingArtifact, baseline_ranking, rank_playbooks, candidate_prediction
from azazel_mio.ranking_registry import EvaluationRegistry

NOW = '2026-10-31T00:00:00Z'
EXPIRY = '2026-12-01T00:00:00Z'


def example(index, day, family='auth', *, kind='synthetic_fixture'):
    stamp = f'2026-10-{day:02d}T00:00:00Z'
    label = {'auth': 'auth-ambiguity-v1', 'scan': 'scan-ambiguity-v1'}[family]
    frame = MioSituationFrame.build(frame_id=f'frame-{index}', trace_id=f'trace-{index}', created_at=stamp,
        mission=f'Assess {family} observations', current_defensive_state='OBSERVE', threat_level='UNKNOWN',
        known_facts=(f'FIXTURE_CASE_{index}',), evidence_refs=('ev:ssh:1',))
    snapshot = SnapshotLineage('fixture', 'snapshot-1', 'g1', stamp, EXPIRY, 'training_and_evaluation',
        'test-fixture-rights', FEATURE_VERSION, LABEL_VERSION, ('fixture-origin',))
    outcome = ObservedOutcome(f'observation-{index}', f'2026-10-{day:02d}T01:00:00Z', ('OBSERVED_FIXTURE',), ('ev:ssh:1',), label,
        f'example-{index}', digest(frame.to_dict()), f'practice-{index}', ('ev:ssh:1',))
    reviewer = ReviewerDisposition('fixture-reviewer', 'accepted', 'independent_outcome', label,
        f'2026-10-{day:02d}T02:00:00Z', ('ev:ssh:1',))
    return LearningExample(f'example-{index}', frame, stamp, stamp, f'incident-{index}', f'entity-{index}',
        f'2026-10-{day:02d}', kind, snapshot, ('DIRECT_FIXTURE_FACT',), ('ev:ssh:1',), reviewer=reviewer, outcome=outcome)


def dataset():
    rows = [example(1, 1), example(2, 2, 'scan'), example(3, 10), example(4, 11, 'scan'), example(5, 20), example(6, 21, 'scan')]
    partitions = {row.example_id: part for row, part in zip(rows, ('train', 'train', 'validation', 'validation', 'test', 'test'))}
    return rows, partitions


def trained():
    rows, parts = dataset()
    return evaluate(rows, parts, now=NOW, artifact_expires_at=EXPIRY)


class DataGates(unittest.TestCase):
    def test_teacher_candidates_cannot_become_facts_or_labels(self):
        row = example(1, 1)
        teacher = TeacherCandidate('model-v1', 'prompt-v1', 'knowledge-g1', 'scan-ambiguity-v1')
        value = replace(row, teacher=teacher, reviewer=replace(row.reviewer, disposition="corrected"))
        # A reviewed correction backed by an independent outcome stays distinct.
        self.assertEqual(quarantine_reasons(value, now=NOW), ())
        wire = value.to_dict()
        self.assertNotIn(teacher.candidate_label, wire['direct_fact_codes'])
        self.assertNotEqual(wire['teacher']['candidate_label'], wire['reviewer']['label'])
        self.assertIn('teacher_only_label', quarantine_reasons(replace(value, reviewer=replace(row.reviewer, basis='teacher_only')), now=NOW))
        self.assertIn('review_missing', quarantine_reasons(replace(value, reviewer=None, outcome=None), now=NOW))

    def test_poison_conflict_expiry_revocation_and_unknown_rights_quarantine(self):
        row = example(1, 1)
        cases = [replace(row, snapshot=replace(row.snapshot, quality='poisoned')),
                 replace(row, snapshot=replace(row.snapshot, rights='unknown')),
                 replace(row, snapshot=replace(row.snapshot, expires_at=NOW)),
                 replace(row, outcome=replace(row.outcome, expected_playbook='scan-ambiguity-v1'))]
        for bad in cases:
            self.assertTrue(quarantine_reasons(bad, now=NOW))
        self.assertIn('snapshot_revoked', quarantine_reasons(row, now=NOW, revoked_snapshots=('snapshot-1',)))
        self.assertTrue(quarantine_reasons(replace(row, snapshot=replace(row.snapshot, feature_version='future')), now=NOW))

    def test_future_origins_and_label_tokens_are_rejected(self):
        row = example(1, 1)
        self.assertIn('future_feature_leakage', quarantine_reasons(replace(row, features_as_of=NOW), now=NOW))
        self.assertIn('future_prediction_time', quarantine_reasons(replace(row, decision_at='2027-01-01T00:00:00Z'), now=NOW))
        self.assertIn('review_precedes_features', quarantine_reasons(replace(row, reviewer=replace(row.reviewer, reviewed_at='2026-09-01T00:00:00Z')), now=NOW))
        self.assertIn('feature_origin_leakage', quarantine_reasons(replace(row, feature_origins=(*ORIGINS, 'teacher.label')), now=NOW))
        leaked = MioSituationFrame.from_dict({**row.frame.to_dict(), 'soc_summary': row.reviewer.label})
        self.assertIn('label_in_feature_text', quarantine_reasons(replace(row, frame=leaked), now=NOW))
        for field in ('incident_group', 'entity_group', 'time_group'):
            self.assertTrue(quarantine_reasons(replace(row, **{field: None}), now=NOW))

    def test_outcomes_and_reviewer_evidence_are_bound_to_this_frame_and_practice_record(self):
        row = example(1, 1)
        bad_outcomes = (
            replace(row.outcome, example_id='example-other'),
            replace(row.outcome, frame_digest=digest(example(2, 2).frame.to_dict())),
            replace(row.outcome, practice_record_ref=row.example_id),
            replace(row.outcome, frame_evidence_refs=('ev:ssh:2',)),
            replace(row.outcome, evidence_refs=('ev:ssh:2',)),
        )
        for outcome in bad_outcomes:
            with self.subTest(outcome=outcome):
                self.assertTrue(quarantine_reasons(replace(row, outcome=outcome), now=NOW))
        unrelated_review = replace(row.reviewer, evidence_refs=('ev:ssh:2',))
        self.assertIn('review_evidence_unbound', quarantine_reasons(replace(row, reviewer=unrelated_review), now=NOW))

    def test_group_and_temporal_split_overlap_is_a_hard_gate(self):
        for field in ('incident_group', 'entity_group'):
            rows, parts = dataset()
            rows[2] = replace(rows[2], **{field: getattr(rows[0], field)})
            with self.subTest(field=field), self.assertRaises(DatasetGateError): prepare(rows, parts, now=NOW)
        rows, parts = dataset()
        rows[2] = replace(example(3, 1), incident_group='separate-incident', entity_group='separate-entity')
        with self.assertRaises(DatasetGateError): prepare(rows, parts, now=NOW)
        rows, parts = dataset()
        rows[0] = replace(rows[0], reviewer=replace(rows[0].reviewer, reviewed_at='2026-10-15T00:00:00Z'))
        with self.assertRaisesRegex(DatasetGateError, 'temporal'): prepare(rows, parts, now=NOW)

    def test_dedup_and_conflicting_duplicate_labels_are_hard_gates(self):
        rows, parts = dataset()
        # Same exact semantic input, different IDs/time: identity cannot hide copying.
        duplicate = replace(rows[2], frame=replace(rows[0].frame, frame_id='frame-3', trace_id='trace-3', created_at=rows[2].decision_at))
        duplicate = replace(duplicate, outcome=replace(duplicate.outcome,
            frame_digest=digest(duplicate.frame.to_dict()), frame_evidence_refs=duplicate.frame.evidence_refs))
        rows[2] = duplicate
        with self.assertRaisesRegex(DatasetGateError, 'cross_split_duplicate'): prepare(rows, parts, now=NOW)
        rows, parts = dataset()
        conflict = replace(rows[0], example_id='example-8',
            reviewer=replace(rows[0].reviewer, label='scan-ambiguity-v1'),
            outcome=replace(rows[0].outcome, example_id='example-8', expected_playbook='scan-ambiguity-v1'))
        with self.assertRaisesRegex(DatasetGateError, 'duplicate_conflicting_labels'):
            prepare([*rows, conflict], {**parts, 'example-8': 'train'}, now=NOW)
        rows, parts = dataset()
        clone = replace(rows[0], example_id='example-7', incident_group='incident-7', entity_group='entity-7',
                        outcome=replace(rows[0].outcome, example_id='example-7'))
        parts[clone.example_id] = 'train'
        samples, _, duplicates = prepare([*rows, clone], parts, now=NOW)
        self.assertEqual(len(samples['train']), 2)
        self.assertEqual(duplicates, ['example-7'])

    def test_replay_and_evaluation_only_rights_never_enter_training(self):
        rows, parts = dataset()
        rows[0] = replace(rows[0], source_kind='public_replay')
        with self.assertRaisesRegex(DatasetGateError, 'replay'): prepare(rows, parts, now=NOW)
        rows, parts = dataset()
        rows[0] = replace(rows[0], snapshot=replace(rows[0].snapshot, rights='evaluation_only'))
        with self.assertRaisesRegex(DatasetGateError, 'training_rights_or_review_missing'): prepare(rows, parts, now=NOW)
        rows, parts = dataset()
        rows[0] = replace(rows[0], reviewer=replace(rows[0].reviewer, basis='direct_facts'))
        with self.assertRaisesRegex(DatasetGateError, 'training_requires_accepted_independent_practice_outcome'):
            prepare(rows, parts, now=NOW)


class ArtifactsAndRuntime(unittest.TestCase):
    def test_candidates_are_compared_but_baseline_is_always_retained(self):
        report, artifact = trained()
        self.assertIsNotNone(artifact)
        self.assertEqual(report['decision'], 'retain_existing_select_playbook')
        self.assertFalse(report['automatic_promotion'])
        self.assertFalse(report['real_world_holdout_verified'])
        self.assertFalse(report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_curated_snapshot_connected'])
        self.assertEqual(report['knowledge_curated_snapshot_connected'], report['knowledge_curated_snapshot_projection_consistent'])
        self.assertFalse(report['knowledge_snapshot_producer_authenticated'])
        self.assertEqual(set(report['results']['test']), {'baseline', 'centroid', 'pattern_anomaly'})
        self.assertEqual(report['results']['test']['baseline']['top1_accuracy'], 1.0)
        self.assertEqual(report['results']['test']['centroid']['calibration']['status'], 'not_estimated')
        self.assertEqual(artifact.use, 'evaluation_only')
        frame = example(8, 22).frame
        self.assertEqual(rank_playbooks(frame), baseline_ranking(frame))
        state = EvaluationRegistry().register(artifact.to_dict(), now=NOW, evaluation_report=report)
        rejected = rank_playbooks(frame, artifact=artifact.to_dict(), registry=state, now=NOW)
        self.assertTrue(rejected['candidate_rejected'])
        state = state.select_for_evaluation(artifact.to_dict()['artifact_digest'], now=NOW)
        out = rank_playbooks(frame, artifact=artifact.to_dict(), registry=state, now=NOW)
        self.assertEqual(out['selected'], baseline_ranking(frame)['selected'])
        self.assertIn('no_product_admission', out['candidate']['limits'])

    def test_compatibility_tampering_expiry_revocation_and_source_expiry(self):
        report, artifact = trained()
        raw = artifact.to_dict()
        for change in ({'runtime_version': 'incompatible'}, {'feature_definition_digest': digest({'rules':'different'})}, {'use': 'production'}, {'command': 'execute'}):
            broken = {**raw, **change}
            broken['artifact_digest'] = digest({key: value for key, value in broken.items() if key != 'artifact_digest'})
            with self.assertRaises(ValueError): RankingArtifact.from_dict(broken)
        broken = json.loads(json.dumps(raw)); broken['centroids'][0][1][0] = float('nan')
        with self.assertRaises(ValueError): RankingArtifact.from_dict(broken)
        with self.assertRaisesRegex(ValueError, 'evaluation_evidence_mismatch'):
            EvaluationRegistry().register(raw, now=NOW, evaluation_report={**report, 'automatic_promotion': True})
        state = EvaluationRegistry().register(raw, now=NOW, evaluation_report=report).select_for_evaluation(raw['artifact_digest'], now=NOW)
        frame = example(8, 22).frame
        for revoked in (state.revoke(artifact_digest=raw['artifact_digest']), state.revoke(snapshot='snapshot-1')):
            self.assertTrue(rank_playbooks(frame, artifact=raw, registry=revoked, now=NOW)['candidate_rejected'])
        self.assertTrue(rank_playbooks(frame, artifact=raw, registry=state, now=EXPIRY)['candidate_rejected'])
        rows, parts = dataset()
        rows[0] = replace(rows[0], snapshot=replace(rows[0].snapshot, expires_at='2026-11-01T00:00:00Z'))
        _, bounded = evaluate(rows, parts, now=NOW, artifact_expires_at=EXPIRY)
        self.assertEqual(bounded.expires_at, '2026-11-01T00:00:00+00:00')

    def test_explicit_rollback_never_revives_revoked_candidate(self):
        report, first = trained()
        second_report = {**report, "evaluation_run": "second"}
        second = replace(first, evaluation_digest=digest(second_report))
        a, b = first.to_dict(), second.to_dict()
        state = EvaluationRegistry().register(a, now=NOW, evaluation_report=report).register(b, now=NOW, evaluation_report=second_report)
        state = state.select_for_evaluation(a['artifact_digest'], now=NOW).select_for_evaluation(b['artifact_digest'], now=NOW)
        self.assertEqual(state.rollback(now=NOW).selected, a['artifact_digest'])
        self.assertIsNone(state.revoke(artifact_digest=a['artifact_digest']).rollback(now=NOW).selected)
        self.assertIsNone(state.revoke(snapshot='snapshot-1').rollback(now=NOW).selected)

    def test_anomaly_and_drift_are_unfamiliarity_not_maliciousness(self):
        report, artifact = trained()
        row = example(8, 22)
        frame = MioSituationFrame.from_dict({**row.frame.to_dict(), 'mission': 'Assess exploit observations'})
        out = candidate_prediction(frame, artifact, kind='pattern_anomaly')
        self.assertIsNone(out['selected'])
        self.assertIn('feature_drift', out['abstain_reasons'])
        self.assertIn('novelty_not_maliciousness', out['limits'])
        self.assertEqual(out['novelty'], 2/6)

    def test_no_data_never_invents_a_candidate_or_performance(self):
        report, artifact = evaluate([], {}, now=NOW, artifact_expires_at=EXPIRY)
        self.assertIsNone(artifact)
        self.assertEqual(report['decision'], 'retain_existing_select_playbook')
        self.assertIsNone(report['results']['test']['baseline']['top1_accuracy'])
        self.assertIsNone(report['results']['test']['baseline']['resource_rss'])

class CommandAndImportBoundaries(unittest.TestCase):
    def test_offline_runtime_and_registry_commands_are_separate_and_exclusive(self):
        import os
        from pathlib import Path
        import subprocess
        import sys
        import tempfile
        root = Path(__file__).resolve().parents[1]
        workspace = root / '.codex-work'
        workspace.mkdir(exist_ok=True)
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(root / 'src')}
        with tempfile.TemporaryDirectory(dir=workspace) as directory:
            path = Path(directory)
            rows, parts = dataset()
            manifest = {'examples': [row.to_dict() for row in rows], 'partitions': parts, 'now': NOW,
                'artifact_expires_at': EXPIRY, 'revoked_snapshots': [], 'costs': {'wrong_selection': 1.0, 'abstention': .25}}
            (path / 'manifest.json').write_text(json.dumps(manifest))
            (path / 'frame.json').write_text(json.dumps(rows[-1].frame.to_dict()))
            def run(module, *args, check=True):
                return subprocess.run([sys.executable, '-B', '-m', module, *map(str, args)], env=env, capture_output=True, text=True, check=check)
            train_args = (path/'manifest.json', '--report', path/'report.json', '--artifact', path/'artifact.json')
            run('azazel_mio.learning_offline', *train_args)
            self.assertNotEqual(run('azazel_mio.learning_offline', *train_args, check=False).returncode, 0)
            artifact = json.loads((path/'artifact.json').read_text())
            self.assertEqual(artifact['use'], 'evaluation_only')
            self.assertNotIn('pickle', (path/'artifact.json').read_text())
            run('azazel_mio.ranking_registry', 'register', '--artifact', path/'artifact.json', '--evaluation-report', path/'report.json', '--now', NOW, '--out', path/'registry0.json')
            self.assertIsNone(json.loads((path/'registry0.json').read_text())['selected'])
            run('azazel_mio.ranking_registry', 'select-evaluation', '--state', path/'registry0.json', '--target', artifact['artifact_digest'], '--now', NOW, '--out', path/'registry1.json')
            output = json.loads(run('azazel_mio.playbook_ranker', path/'frame.json', '--artifact', path/'artifact.json', '--registry', path/'registry1.json', '--now', NOW).stdout)
            self.assertEqual(output['selected'], baseline_ranking(rows[-1].frame)['selected'])
            self.assertEqual(output['method'], 'baseline_with_evaluation_candidate')
            run('azazel_mio.ranking_registry', 'revoke-snapshot', '--state', path/'registry1.json', '--target', 'snapshot-1', '--now', NOW, '--out', path/'revoked.json')
            output = json.loads(run('azazel_mio.playbook_ranker', path/'frame.json', '--artifact', path/'artifact.json', '--registry', path/'revoked.json', '--now', NOW).stdout)
            self.assertTrue(output['candidate_rejected'])

    def test_local_json_rejects_duplicate_keys_and_nonfinite_numbers(self):
        for text in ('{"label":"auth","label":"scan"}', '{"score":NaN}', '{"nested":{"x":1,"x":2}}'):
            with self.subTest(text=text), self.assertRaises(ValueError): parse_json(text)

    def test_import_and_baseline_do_not_train_open_files_spawn_or_contact_network(self):
        import os
        from pathlib import Path
        import subprocess
        import sys
        root = Path(__file__).resolve().parents[1]
        code = '''
import socket, subprocess, secrets

def forbidden(*a, **k): raise AssertionError('import/runtime side effect')
socket.socket = forbidden
subprocess.Popen = forbidden
secrets.token_bytes = forbidden
import azazel_mio.learning_data
import azazel_mio.learning_offline as offline
import azazel_mio.playbook_ranker as runtime
import azazel_mio.ranking_registry
import builtins
builtins.open = forbidden
offline.fit = forbidden
from azazel_mio import MioSituationFrame
frame=MioSituationFrame.build(frame_id='frame-1',trace_id='trace-1',created_at='2026-10-01T00:00:00Z',mission='Assess auth observations',current_defensive_state='OBSERVE',threat_level='UNKNOWN')
assert runtime.rank_playbooks(frame)['selected'] == 'auth-ambiguity-v1'
'''
        subprocess.run([sys.executable, '-B', '-c', code], env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1', 'PYTHONPATH':str(root/'src')}, check=True)


if __name__ == '__main__': unittest.main()
