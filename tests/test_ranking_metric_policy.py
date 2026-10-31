"""FL-02: evaluate playbook choices using one policy, independent of method."""
from dataclasses import replace
import unittest

from azazel_mio.learning_offline import _metrics, evaluate
from azazel_mio.playbook_ranker import baseline_ranking
from test_offline_ranking import dataset, example, NOW, EXPIRY
from azazel_mio.learning_data import digest

GENERIC = 'generic-evidence-first-v1'
AUTH = 'auth-ambiguity-v1'


class RankingMetricPolicy(unittest.TestCase):
    def test_independent_six_example_reproduction_has_no_false_superiority(self):
        rows, parts = dataset()
        for index in (1, 3, 5):
            row = rows[index]
            frame = replace(row.frame, mission='Assess auth and scan observations')
            rows[index] = replace(row, frame=frame,
                reviewer=replace(row.reviewer, label=GENERIC),
                outcome=replace(row.outcome, expected_playbook=GENERIC, frame_digest=digest(frame.to_dict()),
                                frame_evidence_refs=frame.evidence_refs))
        report, artifact = evaluate(rows, parts, now=NOW, artifact_expires_at=EXPIRY)
        self.assertIsNotNone(artifact)
        for partition in ('validation', 'test'):
            metrics = report['results'][partition]
            for method in ('baseline', 'centroid', 'pattern_anomaly'):
                self.assertEqual(metrics[method]['selection_counts'], {AUTH: 1, GENERIC: 1})
                self.assertEqual(metrics[method]['top1_accuracy'], 1.0)
                self.assertEqual(metrics[method]['mean_reciprocal_rank'], 1.0)
                self.assertEqual(metrics[method]['abstention_rate'], 0.0)
                self.assertEqual(metrics[method]['weighted_cost'], 0.0)
                self.assertEqual(metrics[method]['coverage'], 1.0)
                self.assertEqual(metrics[method]['calibration']['status'], 'not_estimated')
        self.assertFalse(any(report['candidate_beats_baseline_in_this_evaluation'].values()))
        self.assertEqual(report['decision'], 'retain_existing_select_playbook')
        self.assertFalse(report['automatic_promotion'])
        self.assertFalse(report['real_world_holdout_verified'])
        self.assertEqual(report['metric_policy']['generic'], 'valid_playbook_choice_for_every_method')

    def test_correct_generic_preserves_uncertainty_context_without_a_baseline_penalty(self):
        row = example(1, 1)
        frame = replace(row.frame, mission='Assess auth and scan observations')
        baseline = baseline_ranking(frame)
        self.assertEqual(baseline['selected'], GENERIC)
        self.assertTrue(baseline['fallback_reasons'])
        self.assertEqual(baseline['abstain_reasons'], [])
        self.assertIn('not_probability', baseline['limits'])

    def test_all_methods_share_correct_generic_wrong_specific_generic_error_and_abstention_costs(self):
        row = example(1, 1)
        cases = (
            # expected, selected, true-abstention, accuracy, cost, false-specific, missed-specific, coverage
            (GENERIC, GENERIC, False, 1.0, 0.0, 0, 0, 1.0),
            (GENERIC, AUTH, False, 0.0, 1.0, 1, 0, 1.0),
            (AUTH, GENERIC, False, 0.0, 1.0, 0, 1, 1.0),
            (AUTH, None, True, 0.0, 0.25, 0, 1, 0.0),
            (GENERIC, None, True, 0.0, 0.25, 0, 0, 0.0),
        )
        for expected, selected, abstain, accuracy, cost, fp, fn, coverage in cases:
            target = replace(row, reviewer=replace(row.reviewer, label=expected),
                             outcome=replace(row.outcome, expected_playbook=expected))
            comparable = []
            for method in ('existing_select_playbook', 'centroid', 'pattern_anomaly'):
                output = {'method': method, 'selected': selected, 'ranking': [] if selected is None else [selected],
                          'abstain_reasons': ['feature_drift'] if abstain else [],
                          'fallback_reasons': ['multiple_family_match'] if method == 'existing_select_playbook' and selected == GENERIC else []}
                metrics = _metrics([target], [output], [100], wrong_cost=1.0, abstain_cost=.25)
                self.assertEqual(metrics['top1_accuracy'], accuracy)
                self.assertEqual(metrics['weighted_cost'], cost)
                self.assertEqual(metrics['false_specific_selection'], fp)
                self.assertEqual(metrics['missed_expected_specific_playbook'], fn)
                self.assertEqual(metrics['coverage'], coverage)
                self.assertEqual(metrics['calibration']['status'], 'not_estimated')
                comparable.append({key: metrics[key] for key in (
                    'top1_accuracy', 'mean_reciprocal_rank', 'abstention_rate', 'weighted_cost', 'coverage',
                    'false_specific_selection', 'missed_expected_specific_playbook', 'calibration')})
            self.assertEqual(comparable[0], comparable[1])
            self.assertEqual(comparable[0], comparable[2])

    def test_unlabelled_data_has_no_accuracy_or_cost_claim_even_when_generic_is_selected(self):
        row = replace(example(1, 1), reviewer=None, outcome=None)
        output = baseline_ranking(replace(row.frame, mission='Assess auth and scan observations'))
        metrics = _metrics([row], [output], [100], wrong_cost=1.0, abstain_cost=.25)
        self.assertEqual(metrics['examples'], 1)
        self.assertEqual(metrics['labelled'], 0)
        self.assertEqual(metrics['generic_selection_count'], 1)
        self.assertEqual(metrics['generic_fallback_context_count'], 1)
        self.assertIsNone(metrics['top1_accuracy'])
        self.assertIsNone(metrics['weighted_cost'])
        self.assertEqual(metrics['calibration']['status'], 'not_estimated')


if __name__ == '__main__': unittest.main()
