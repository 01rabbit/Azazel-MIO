"""Frozen synthetic session replay pilot. No real labels, training or admission."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .contracts import MioSituationFrame
from .id_grammar import second_layer_ok
from .learning_data import digest, parse_json
from .session_behavior import SessionFeature, SessionWindow, assess_session
from .session_evaluation import SessionLabel, evaluate_session_predictions

SCHEMA = 'session-replay-pilot/v1'
MAX_BYTES = 2 * 1024 * 1024


def run_pilot(manifest: dict, cases: list) -> dict:
    if type(manifest) is not dict or manifest.get('schema_version') != SCHEMA or manifest.get('evidence_kind') != 'synthetic_replay':
        raise ValueError('synthetic replay manifest required')
    if type(cases) is not list or not 2 <= len(cases) <= 128 or manifest.get('cases_sha256') != digest(cases):
        raise ValueError('bounded cases do not match frozen manifest')
    acceptance = manifest.get('acceptance')
    required = {'identity_verdicts': 0, 'maliciousness_verdicts': 0, 'authorized_actions': 0, 'model_calls': 0, 'status_mismatches': 0}
    if acceptance != required or any(type(v) is not int for v in acceptance.values()):
        raise ValueError('pilot safety/semantic gates cannot be weakened')
    if manifest.get('real_world_holdout_verified') is not False or manifest.get('identification_thresholds') is not None:
        raise ValueError('unlabelled synthetic pilot cannot set identification thresholds')
    if manifest.get('partition_policy') != 'development_and_reserved_replay_never_real_holdout':
        raise ValueError('explicit replay-only partition policy required')
    labels, predictions, reports, groups, ids = [], {}, [], {}, set()
    counts = dict.fromkeys(required, 0)
    partition_counts = {'development_replay': 0, 'reserved_replay': 0}
    for case in cases:
        if type(case) is not dict or case.get('partition') not in partition_counts:
            raise ValueError('invalid pilot case/partition')
        ident = case.get('case_id')
        if type(ident) is not str or not second_layer_ok(ident) or ident in ids:
            raise ValueError('invalid/duplicate pilot case')
        ids.add(ident)
        for name in ('incident_group', 'entity_group', 'time_group', 'content_family'):
            value = case.get(name)
            if type(value) is not str or not second_layer_ok(value):
                raise ValueError('invalid bounded pilot group')
            key = (name, value)
            if key in groups and groups[key] != case['partition']:
                raise ValueError('cross-partition replay leakage')
            groups[key] = case['partition']
        if any(case.get(k) is not None for k in ('ai_assisted', 'malicious')) or case.get('ground_truth_basis') != 'unknown':
            raise ValueError('unverified synthetic actor labels must remain unknown')
        refs = ('ev:flow:' + str(len(labels)+1),)
        raw = case.get('features')
        if type(raw) is not dict or len(raw) > 9:
            raise ValueError('invalid bounded normalized features')
        features = tuple(SessionFeature(k, v, refs if v is not None else ()) for k, v in sorted(raw.items()))
        frame = MioSituationFrame.build(frame_id='frame-' + ident, trace_id='trace-' + ident,
            created_at=case['end'], mission='observe', current_defensive_state='OBSERVE', threat_level='unknown', evidence_refs=refs)
        window = SessionWindow(frame.frame_id, 'session-' + ident, 'boot-' + ident, 'pilot-features-v1',
            case['start'], case['end'], features, case['capture_complete'], case['shared_source_ambiguity'], case['clock_uncertain'])
        report = assess_session(frame, window, as_of=case['as_of'])
        counts['identity_verdicts'] += report['identity_label'] != 'unknown' or not report['abstained'] or report['probability'] is not None
        counts['maliciousness_verdicts'] += report['maliciousness'] != 'not_assessed'
        counts['authorized_actions'] += len(report['authorized_actions'])
        counts['model_calls'] += report['model_calls']
        if case.get('expected_status') not in ('hypotheses_available', 'insufficient_evidence'):
            raise ValueError('explicit expected semantic status required')
        counts['status_mismatches'] += report['status'] != case['expected_status']
        partition_counts[case['partition']] += 1
        labels.append(SessionLabel(ident, 'replay_eval', *(case[n] for n in ('incident_group','entity_group','time_group','content_family')),
                                   case['end'], 'unknown', None, None))
        predictions[ident] = None if report['abstained'] else True
        reports.append({'case_id': ident, 'partition': case['partition'], 'status': report['status'],
                        'withholding_reasons': report['withholding_reasons']})
    if any(n == 0 for n in partition_counts.values()):
        raise ValueError('both replay partitions required')
    metrics = evaluate_session_predictions(tuple(labels), predictions, candidate_version='session-pattern-hypotheses-v1')
    return {'schema_version': 'session-replay-pilot-report/v1', 'manifest_sha256': digest(manifest), 'cases_sha256': digest(cases),
            'claim_status': 'mechanical_only', 'partitions': partition_counts, 'counts': counts,
            'mechanical_gate': 'passed' if counts == required else 'failed', 'cases': reports, 'metrics': metrics,
            'real_world_holdout_verified': False, 'automatic_promotion': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest'); parser.add_argument('cases'); args = parser.parse_args()
    def read(path):
        with Path(path).open('rb') as stream: raw = stream.read(MAX_BYTES+1)
        if len(raw) > MAX_BYTES: raise ValueError('pilot input too large')
        return parse_json(raw.decode('utf-8'))
    try: report = run_pilot(read(args.manifest), read(args.cases))
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc: parser.exit(2, f'invalid pilot: {exc}\n')
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0 if report['mechanical_gate'] == 'passed' else 1


if __name__ == '__main__': raise SystemExit(main())
