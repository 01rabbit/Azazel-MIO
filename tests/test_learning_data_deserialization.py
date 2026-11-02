"""LearningExample.from_dict shape, time, code, and ref validation; no quarantine semantics here."""
import copy
import unittest

from azazel_mio import MioSituationFrame
from azazel_mio.learning_data import (LearningExample, SnapshotLineage, ReviewerDisposition,
    TeacherCandidate, ObservedOutcome, FEATURE_VERSION, LABEL_VERSION, ORIGINS, digest, quarantine_reasons)

EXPIRY = '2026-12-01T00:00:00Z'


def valid_example():
    stamp = '2026-10-01T00:00:00+00:00'
    frame = MioSituationFrame.build(frame_id='frame-1', trace_id='trace-1', created_at=stamp,
        mission='Assess auth observations', current_defensive_state='OBSERVE', threat_level='UNKNOWN',
        known_facts=('FIXTURE_CASE_1',), evidence_refs=('ev:ssh:1',))
    snapshot = SnapshotLineage('fixture', 'snapshot-1', 'g1', stamp, EXPIRY, 'training_and_evaluation',
        'test-fixture-rights', FEATURE_VERSION, LABEL_VERSION, ('fixture-origin',))
    teacher = TeacherCandidate('model-v1', 'prompt-v1', 'knowledge-g1', 'auth-ambiguity-v1')
    outcome = ObservedOutcome('observation-1', '2026-10-01T01:00:00+00:00', ('OBSERVED_FIXTURE',),
        ('ev:ssh:1',), 'auth-ambiguity-v1', 'example-1', digest(frame.to_dict()), 'practice-1', ('ev:ssh:1',))
    reviewer = ReviewerDisposition('fixture-reviewer', 'accepted', 'independent_outcome', 'auth-ambiguity-v1',
        '2026-10-01T02:00:00+00:00', ('ev:ssh:1',))
    return LearningExample('example-1', frame, stamp, stamp, 'incident-1', 'entity-1', '2026-10-01',
        'synthetic_fixture', snapshot, ('DIRECT_FIXTURE_FACT',), ('ev:ssh:1',),
        teacher=teacher, reviewer=reviewer, outcome=outcome)


def with_direct(field, values):
    wire = valid_example().to_dict()
    wire[field] = values
    return wire


class FromDictDeserialization(unittest.TestCase):
    def test_roundtrip_preserves_aware_timestamps_and_nested_metadata(self):
        original = valid_example()
        wire = original.to_dict()
        restored = LearningExample.from_dict(copy.deepcopy(wire))
        self.assertEqual(restored.to_dict(), wire)
        self.assertEqual(restored.decision_at, '2026-10-01T00:00:00+00:00')
        self.assertEqual(restored.reviewer.reviewed_at, '2026-10-01T02:00:00+00:00')
        self.assertEqual(restored.outcome.observed_at, '2026-10-01T01:00:00+00:00')
        self.assertEqual(restored.snapshot.lineage, ('fixture-origin',))
        self.assertEqual(restored.teacher.candidate_label, 'auth-ambiguity-v1')
        self.assertEqual(restored.feature_origins, ORIGINS)
        self.assertEqual(restored.direct_fact_codes, ('DIRECT_FIXTURE_FACT',))

    def test_naive_timestamps_are_rejected(self):
        naive = '2026-10-01T00:00:00'
        cases = {
            'decision_at': lambda w: w.__setitem__('decision_at', naive),
            'features_as_of': lambda w: w.__setitem__('features_as_of', naive),
            'frame.created_at': lambda w: w['frame'].__setitem__('created_at', naive),
            'snapshot.as_of': lambda w: w['snapshot'].__setitem__('as_of', naive),
            'snapshot.expires_at': lambda w: w['snapshot'].__setitem__('expires_at', naive),
            'reviewer.reviewed_at': lambda w: w['reviewer'].__setitem__('reviewed_at', naive),
            'outcome.observed_at': lambda w: w['outcome'].__setitem__('observed_at', naive),
        }
        for name, mutate in cases.items():
            with self.subTest(field=name):
                wire = valid_example().to_dict()
                mutate(wire)
                with self.assertRaisesRegex(ValueError, r'^invalid_learning_time$'):
                    LearningExample.from_dict(wire)

    def test_non_string_timestamps_are_rejected(self):
        cases = {
            'decision_at': lambda w: w.__setitem__('decision_at', 1759276800),
            'features_as_of': lambda w: w.__setitem__('features_as_of', None),
            'frame.created_at': lambda w: w['frame'].__setitem__('created_at', 1759276800),
            'snapshot.as_of': lambda w: w['snapshot'].__setitem__('as_of', ['2026-10-01T00:00:00Z']),
            'snapshot.expires_at': lambda w: w['snapshot'].__setitem__('expires_at', None),
            'reviewer.reviewed_at': lambda w: w['reviewer'].__setitem__('reviewed_at', 1759284000),
            'outcome.observed_at': lambda w: w['outcome'].__setitem__('observed_at', {'t': '2026-10-01T01:00:00Z'}),
        }
        for name, mutate in cases.items():
            with self.subTest(field=name):
                wire = valid_example().to_dict()
                mutate(wire)
                # frame.created_at is rejected earlier by MioSituationFrame.from_dict.
                expected = ('^invalid_situation_frame_payload$' if name == 'frame.created_at'
                            else r'^invalid_learning_time$')
                with self.assertRaisesRegex(ValueError, expected):
                    LearningExample.from_dict(wire)

    def test_malformed_timestamp_text_raises_invalid_learning_time(self):
        cases = {
            'not a date': 'not-a-timestamp',
            'impossible month': '2026-13-01T00:00:00Z',
            'empty string': '',
            'over 64 characters': '2026-10-01T00:00:00.' + '0' * 60 + '+00:00',
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                wire = valid_example().to_dict()
                wire['decision_at'] = text
                with self.assertRaisesRegex(ValueError, r'^invalid_learning_time$'):
                    LearningExample.from_dict(wire)

    def test_malformed_lineage_and_code_lists_are_rejected(self):
        codes_msg = r'^invalid_learning_codes$'
        refs_msg = r'^invalid_learning_refs$'
        cases = {
            'snapshot.lineage is a string': (lambda w: w['snapshot'].__setitem__('lineage', 'fixture-origin'), codes_msg),
            'snapshot.lineage bad code': (lambda w: w['snapshot'].__setitem__('lineage', ['bad code!']), codes_msg),
            'snapshot.lineage non-string item': (lambda w: w['snapshot'].__setitem__('lineage', [7]), codes_msg),
            'direct_fact_codes is a string': (lambda w: w.__setitem__('direct_fact_codes', 'DIRECT_FIXTURE_FACT'), codes_msg),
            'direct_fact_codes non-string item': (lambda w: w.__setitem__('direct_fact_codes', [7]), codes_msg),
            'direct_fact_codes invalid code': (lambda w: w.__setitem__('direct_fact_codes', ['-leading-dash']), codes_msg),
            'outcome.fact_codes is a string': (lambda w: w['outcome'].__setitem__('fact_codes', 'OBSERVED_FIXTURE'), codes_msg),
            'outcome.fact_codes non-string item': (lambda w: w['outcome'].__setitem__('fact_codes', [None]), codes_msg),
            'outcome.fact_codes invalid code': (lambda w: w['outcome'].__setitem__('fact_codes', ['bad code!']), codes_msg),
            'direct_evidence_refs is a dict': (lambda w: w.__setitem__('direct_evidence_refs', {'ev': 1}), refs_msg),
            'direct_evidence_refs invalid ref': (lambda w: w.__setitem__('direct_evidence_refs', ['not a ref']), refs_msg),
            'direct_evidence_refs non-string item': (lambda w: w.__setitem__('direct_evidence_refs', [3]), refs_msg),
            'reviewer.evidence_refs is a string': (lambda w: w['reviewer'].__setitem__('evidence_refs', 'ev:ssh:1'), refs_msg),
            'reviewer.evidence_refs invalid ref': (lambda w: w['reviewer'].__setitem__('evidence_refs', ['not a ref']), refs_msg),
            'outcome.evidence_refs is a dict': (lambda w: w['outcome'].__setitem__('evidence_refs', {'ev': 1}), refs_msg),
            'outcome.evidence_refs non-string item': (lambda w: w['outcome'].__setitem__('evidence_refs', [None]), refs_msg),
            'outcome.frame_evidence_refs is a string': (lambda w: w['outcome'].__setitem__('frame_evidence_refs', 'ev:ssh:1'), refs_msg),
            'outcome.frame_evidence_refs invalid ref': (lambda w: w['outcome'].__setitem__('frame_evidence_refs', ['not a ref']), refs_msg),
        }
        for name, (mutate, message) in cases.items():
            with self.subTest(case=name):
                wire = valid_example().to_dict()
                mutate(wire)
                with self.assertRaisesRegex(ValueError, message):
                    LearningExample.from_dict(wire)

    def test_invalid_codes_raise_invalid_learning_codes(self):
        cases = {
            'string instead of list': 'DIRECT_FIXTURE_FACT',
            'non-string item': [7],
            'invalid code': ['-leading-dash'],
            'over 96 characters': ['A' * 97],
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(ValueError, r'^invalid_learning_codes$'):
                    LearningExample.from_dict(with_direct('direct_fact_codes', value))

    def test_invalid_refs_raise_invalid_learning_refs(self):
        cases = {
            'dict instead of list': {'ev': 1},
            'invalid ref': ['not a ref'],
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(ValueError, r'^invalid_learning_refs$'):
                    LearningExample.from_dict(with_direct('direct_evidence_refs', value))

    def test_feature_origins_non_list_values_are_rejected(self):
        cases = {
            'string': 'frame.mission',
            'dict': {'frame.mission': 1},
            'null': None,
            'integer': 7,
            'bool': True,
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                wire = valid_example().to_dict()
                wire['feature_origins'] = value
                with self.assertRaisesRegex(ValueError, r'^invalid_learning_feature_origins$'):
                    LearningExample.from_dict(wire)

    def test_feature_origins_non_string_items_are_rejected(self):
        cases = {
            'integer item': list(ORIGINS[:3]) + [7],
            'null item': [None] + list(ORIGINS[1:]),
            'nested list item': [list(ORIGINS[:1])] + list(ORIGINS[1:]),
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                wire = valid_example().to_dict()
                wire['feature_origins'] = value
                with self.assertRaisesRegex(ValueError, r'^invalid_learning_feature_origins$'):
                    LearningExample.from_dict(wire)

    def test_feature_origins_valid_list_roundtrips_and_unexpected_strings_are_kept(self):
        wire = valid_example().to_dict()
        self.assertEqual(wire['feature_origins'], list(ORIGINS))
        restored = LearningExample.from_dict(copy.deepcopy(wire))
        self.assertEqual(restored.feature_origins, ORIGINS)
        # Valid-but-unexpected origin strings parse; quarantine rejects them later.
        wire['feature_origins'] = ['frame.mission', 'frame.unexpected_origin']
        restored = LearningExample.from_dict(copy.deepcopy(wire))
        self.assertEqual(restored.feature_origins, ('frame.mission', 'frame.unexpected_origin'))

    def test_feature_origins_count_boundary_16_accepted_17_rejected(self):
        origins16 = [f'frame.origin_{i}' for i in range(16)]
        restored = LearningExample.from_dict(with_direct('feature_origins', origins16))
        self.assertEqual(restored.feature_origins, tuple(origins16))
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_feature_origins$'):
            LearningExample.from_dict(with_direct('feature_origins', origins16 + ['frame.origin_16']))

    def test_feature_origins_length_boundary_96_accepted_97_rejected(self):
        at_cap = 'frame.' + 'x' * 90
        self.assertEqual(len(at_cap), 96)
        restored = LearningExample.from_dict(with_direct('feature_origins', [at_cap]))
        self.assertEqual(restored.feature_origins, (at_cap,))
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_feature_origins$'):
            LearningExample.from_dict(with_direct('feature_origins', ['frame.' + 'x' * 91]))

    def test_feature_origins_tuple_parses_and_roundtrips(self):
        wire = valid_example().to_dict()
        wire['feature_origins'] = tuple(ORIGINS)
        restored = LearningExample.from_dict(wire)
        self.assertEqual(restored.feature_origins, ORIGINS)
        rewired = restored.to_dict()
        self.assertEqual(rewired['feature_origins'], list(ORIGINS))
        self.assertEqual(LearningExample.from_dict(copy.deepcopy(rewired)).feature_origins, ORIGINS)

    def test_feature_origins_str_subclass_items_are_rejected(self):
        class OriginStr(str):
            pass
        cases = {
            'subclass item in list': [OriginStr('frame.mission')] + list(ORIGINS[1:]),
            'subclass item in tuple': (OriginStr('frame.mission'),) + tuple(ORIGINS[1:]),
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                wire = valid_example().to_dict()
                wire['feature_origins'] = value
                with self.assertRaisesRegex(ValueError, r'^invalid_learning_feature_origins$'):
                    LearningExample.from_dict(wire)

    def test_feature_origin_leakage_reason_for_empty_and_unexpected_origins(self):
        now = '2026-10-02T00:00:00Z'
        valid_reasons = quarantine_reasons(valid_example(), now=now)
        self.assertNotIn('feature_origin_leakage', valid_reasons)
        cases = {
            'empty list': [],
            'unexpected origin': ['frame.unexpected_origin'],
            'expected plus unexpected': list(ORIGINS) + ['frame.unexpected_origin'],
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                wire = valid_example().to_dict()
                wire['feature_origins'] = value
                example = LearningExample.from_dict(wire)
                self.assertIn('feature_origin_leakage', quarantine_reasons(example, now=now))

    def test_direct_fact_codes_boundary_16_accepted_17_rejected(self):
        codes16 = [f'DIRECT_FACT_{i}' for i in range(16)]
        restored = LearningExample.from_dict(with_direct('direct_fact_codes', codes16))
        self.assertEqual(len(restored.direct_fact_codes), 16)
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_codes$'):
            LearningExample.from_dict(with_direct('direct_fact_codes', codes16 + ['DIRECT_FACT_16']))

    def test_direct_evidence_refs_boundary_32_accepted_33_rejected(self):
        refs32 = [f'ev:ssh:{i}' for i in range(32)]
        restored = LearningExample.from_dict(with_direct('direct_evidence_refs', refs32))
        self.assertEqual(len(restored.direct_evidence_refs), 32)
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_refs$'):
            LearningExample.from_dict(with_direct('direct_evidence_refs', refs32 + ['ev:ssh:32']))

    def test_snapshot_lineage_boundary_16_accepted_17_rejected(self):
        lineage16 = [f'lineage-{i}' for i in range(16)]
        wire = valid_example().to_dict()
        wire['snapshot']['lineage'] = lineage16
        restored = LearningExample.from_dict(wire)
        self.assertEqual(len(restored.snapshot.lineage), 16)
        wire = valid_example().to_dict()
        wire['snapshot']['lineage'] = lineage16 + ['lineage-16']
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_codes$'):
            LearningExample.from_dict(wire)

    def test_outcome_fact_codes_boundary_16_accepted_17_rejected(self):
        codes16 = [f'OUTCOME_FACT_{i}' for i in range(16)]
        wire = valid_example().to_dict()
        wire['outcome']['fact_codes'] = codes16
        restored = LearningExample.from_dict(wire)
        self.assertEqual(len(restored.outcome.fact_codes), 16)
        wire = valid_example().to_dict()
        wire['outcome']['fact_codes'] = codes16 + ['OUTCOME_FACT_16']
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_codes$'):
            LearningExample.from_dict(wire)

    def test_reviewer_evidence_refs_boundary_32_accepted_33_rejected(self):
        refs32 = [f'ev:ssh:{i}' for i in range(32)]
        wire = valid_example().to_dict()
        wire['reviewer']['evidence_refs'] = refs32
        restored = LearningExample.from_dict(wire)
        self.assertEqual(len(restored.reviewer.evidence_refs), 32)
        wire = valid_example().to_dict()
        wire['reviewer']['evidence_refs'] = refs32 + ['ev:ssh:32']
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_refs$'):
            LearningExample.from_dict(wire)

    def test_outcome_evidence_refs_boundary_32_accepted_33_rejected(self):
        refs32 = [f'ev:ssh:{i}' for i in range(32)]
        wire = valid_example().to_dict()
        wire['outcome']['evidence_refs'] = refs32
        restored = LearningExample.from_dict(wire)
        self.assertEqual(len(restored.outcome.evidence_refs), 32)
        wire = valid_example().to_dict()
        wire['outcome']['evidence_refs'] = refs32 + ['ev:ssh:32']
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_refs$'):
            LearningExample.from_dict(wire)

    def test_outcome_frame_evidence_refs_boundary_32_accepted_33_rejected(self):
        refs32 = [f'ev:ssh:{i}' for i in range(32)]
        wire = valid_example().to_dict()
        wire['outcome']['frame_evidence_refs'] = refs32
        restored = LearningExample.from_dict(wire)
        self.assertEqual(len(restored.outcome.frame_evidence_refs), 32)
        wire = valid_example().to_dict()
        wire['outcome']['frame_evidence_refs'] = refs32 + ['ev:ssh:32']
        with self.assertRaisesRegex(ValueError, r'^invalid_learning_refs$'):
            LearningExample.from_dict(wire)


if __name__ == '__main__':
    unittest.main()
