"""Offline-only training/evaluation. No training or file access on import."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
import math
from time import perf_counter_ns
from statistics import median

from .learning_data import (FEATURE_VERSION, LABEL_VERSION, LearningExample, canonical,
                            content_digest, digest, instant, parse_json, quarantine_reasons)
from .playbook_ranker import (RankingArtifact, baseline_ranking, candidate_prediction,
                              features, DIMENSIONS)
from .playbook import selection_rules_digest
from .snapshot_input import snapshot_input_audit


class DatasetGateError(ValueError):
    pass


def _prepare(examples, partitions: dict, *, now: str, revoked_snapshots=(), snapshot_inputs=(), snapshot_context=None):
    if type(examples) not in (tuple, list) or len(examples) > 2048 or type(partitions) is not dict:
        raise DatasetGateError("dataset_size_or_partitions")
    audit = snapshot_input_audit(examples, snapshot_inputs, context=snapshot_context, now=now,
                                 additional_revoked_refs=tuple(revoked_snapshots))
    accepted, quarantine = [], []
    ids = set()
    for ordinal, raw in enumerate(examples):
        try:
            example = LearningExample.from_dict(raw.to_dict()) if type(raw) is LearningExample else LearningExample.from_dict(raw)
            if example.example_id in ids: raise DatasetGateError("duplicate_example_id")
            ids.add(example.example_id)
            reasons = quarantine_reasons(example, now=now, revoked_snapshots=revoked_snapshots)
            reasons += audit["rejected_examples"].get(example.example_id, ())
        except DatasetGateError:
            raise
        except (ValueError, TypeError, KeyError):
            quarantine.append({"record": ordinal, "reasons": ["malformed_example"]})
            continue
        if reasons:
            quarantine.append({"example_id": example.example_id, "reasons": list(reasons)})
        else:
            accepted.append(example)
    if any(key not in ids or part not in {"train", "validation", "test", "replay_eval"} for key, part in partitions.items()):
        raise DatasetGateError("unknown_partition_assignment")
    groups = {name: defaultdict(set) for name in ("incident_group", "entity_group", "time_group")}
    samples, duplicates, seen = defaultdict(list), [], {}
    for example in accepted:
        part = partitions.get(example.example_id)
        if part is None: raise DatasetGateError("missing_partition_assignment")
        if example.source_kind == "public_replay" and part != "replay_eval": raise DatasetGateError("replay_is_evaluation_only")
        if part == "train" and (example.snapshot.rights != "training_and_evaluation" or example.reviewer is None):
            raise DatasetGateError("training_rights_or_review_missing")
        if part == "train" and (example.reviewer.disposition not in {"accepted", "corrected"}
                or example.reviewer.basis != "independent_outcome" or example.outcome is None):
            raise DatasetGateError("training_requires_accepted_independent_practice_outcome")
        if part in {"train", "validation", "test"} and example.reviewer is None:
            raise DatasetGateError("supervised_label_missing")
        # Replay is one separate eval-only cohort, never an independent holdout.
        if part != "replay_eval":
            for name, assignments in groups.items():
                group = getattr(example, name)
                assignments[group].add(part)
                if len(assignments[group]) > 1: raise DatasetGateError(f"cross_split_{name}")
        key = content_digest(example)
        label = example.reviewer.label if example.reviewer else None
        if key in seen:
            old_part, old_label = seen[key]
            if old_label != label: raise DatasetGateError("duplicate_conflicting_labels")
            if old_part != part: raise DatasetGateError("cross_split_duplicate")
            duplicates.append(example.example_id)
            continue
        seen[key] = part, label
        samples[part].append(example)
    for earlier, later in (("train", "validation"), ("validation", "test"), ("train", "test")):
        if samples[earlier] and samples[later]:
            # Training review/outcome labels must already exist before any later
            # prediction; frame features alone do not justify future labels.
            available = [max(instant(row.decision_at), instant(row.reviewer.reviewed_at),
                             instant(row.outcome.observed_at) if row.outcome else instant(row.decision_at)) for row in samples[earlier]]
            if max(available) >= min(instant(row.decision_at) for row in samples[later]):
                raise DatasetGateError("temporal_or_label_availability_leakage")
    return dict(samples), quarantine, duplicates, audit


def prepare(examples, partitions: dict, *, now: str, revoked_snapshots=(), snapshot_inputs=(), snapshot_context=None):
    """Public preparation API preserves its existing three-result contract."""
    samples, quarantine, duplicates, _ = _prepare(examples, partitions, now=now,
        revoked_snapshots=revoked_snapshots, snapshot_inputs=snapshot_inputs, snapshot_context=snapshot_context)
    return samples, quarantine, duplicates


def _fit_eligible(train: list[LearningExample], *, created_at: str, expires_at: str) -> RankingArtifact:
    if type(train) not in (list, tuple) or len(train) > 2048 or any(
            type(row) is not LearningExample or quarantine_reasons(row, now=created_at)
            or row.source_kind == "public_replay" or row.snapshot.rights != "training_and_evaluation"
            or row.reviewer is None or row.reviewer.disposition not in {"accepted", "corrected"}
            or row.reviewer.basis != "independent_outcome" or row.outcome is None
            or quarantine_reasons(row, now=created_at) for row in train):
        raise DatasetGateError("training_input_not_eligible")
    if len(train) < 2 or len({row.reviewer.label for row in train}) < 2:
        raise DatasetGateError("insufficient_reviewed_training_classes")
    by_label = defaultdict(list)
    for row in train: by_label[row.reviewer.label].append(features(row.frame))
    centroids = tuple((label, tuple(sum(vector[i] for vector in vectors) / len(vectors) for i in range(DIMENSIONS)))
                      for label, vectors in sorted(by_label.items()))
    sources = sorted({(row.snapshot.snapshot, row.snapshot.generation, row.snapshot.rights, row.snapshot.lineage) for row in train})
    expiry = min([instant(expires_at), *(instant(row.snapshot.expires_at) for row in train)]).isoformat()
    return RankingArtifact(created_at, expiry, centroids, tuple(sorted({features(row.frame) for row in train})),
                           tuple(sorted(digest(row.to_dict()) for row in train)),
                           tuple(row[0] for row in sources), tuple(row[1] for row in sources),
                           tuple(row[2] for row in sources), tuple(row[3] for row in sources),
                           tuple(sorted({row.source_kind for row in train})), digest({"evaluation": "pending"}),
                           digest({"selection_rules": selection_rules_digest(), "deception_feature": "available.v1"}))


def fit(train: list[LearningExample], *, created_at: str, expires_at: str) -> RankingArtifact:
    """Fixture-only fitting helper; curated inputs must pass evaluate's bindings."""
    if any(type(row) is LearningExample and row.source_kind == "curated_observation" for row in train):
        raise DatasetGateError("curated_training_requires_snapshot_evaluation")
    return _fit_eligible(train, created_at=created_at, expires_at=expires_at)


def _metrics(rows, predictions, durations, *, wrong_cost, abstain_cost):
    labelled = [(row, output) for row, output in zip(rows, predictions) if row.reviewer is not None]
    decisions = [(row, None if output["abstain_reasons"] else output["selected"]) for row, output in labelled]
    correct = sum(selected == row.reviewer.label for row, selected in decisions)
    abstained = sum(selected is None for _, selected in decisions)
    errors = sum(selected is not None and selected != row.reviewer.label for row, selected in decisions)
    fp = sum(selected is not None and selected != row.reviewer.label and selected != "generic-evidence-first-v1" for row, selected in decisions)
    fn = sum(selected != row.reviewer.label and row.reviewer.label != "generic-evidence-first-v1" for row, selected in decisions)
    rank_positions = [output["ranking"].index(row.reviewer.label) + 1 for row, output in labelled if row.reviewer.label in output["ranking"]]
    ordered = sorted(durations)
    return {"examples": len(rows), "labelled": len(labelled), "unlabelled": len(rows) - len(labelled),
            "coverage": sum(output["selected"] is not None and not output["abstain_reasons"] for output in predictions) / len(rows) if rows else None,
            "selection_counts": {label: sum(output["selected"] == label for output in predictions) for label in sorted({output["selected"] for output in predictions if output["selected"] is not None})},
            "generic_selection_count": sum(output["selected"] == "generic-evidence-first-v1" for output in predictions),
            "generic_fallback_context_count": sum(bool(output.get("fallback_reasons")) for output in predictions),
            "correct_top1": correct,
            "top1_accuracy": correct / len(labelled) if labelled else None,
            "mean_reciprocal_rank": sum(1 / rank for rank in rank_positions) / len(labelled) if labelled else None,
            "abstained": abstained, "abstention_rate": abstained / len(labelled) if labelled else None,
            "false_specific_selection": fp, "missed_expected_specific_playbook": fn,
            "weighted_cost": errors * wrong_cost + abstained * abstain_cost if labelled else None,
            "calibration": {"status": "not_estimated", "reason": "distances_and_rule_scores_are_not_probabilities"},
            "drift_abstentions": sum("feature_drift" in output["abstain_reasons"] for output in predictions),
            "latency_ns": {"measured_calls": len(ordered), "median": median(ordered) if ordered else None,
                           "p95": ordered[max(0, math.ceil(.95*len(ordered))-1)] if ordered else None},
            "resource_rss": None, "resource_limit": "target_process_memory_not_measured"}


def evaluate(examples, partitions, *, now: str, artifact_expires_at: str,
             revoked_snapshots=(), wrong_cost=1.0, abstain_cost=0.25, snapshot_inputs=(), snapshot_context=None):
    for cost in (wrong_cost, abstain_cost):
        if type(cost) not in (int, float) or not math.isfinite(cost) or cost < 0: raise ValueError("invalid_evaluation_cost")
    samples, quarantine, duplicates, snapshot_audit = _prepare(examples, partitions, now=now,
        revoked_snapshots=revoked_snapshots, snapshot_inputs=snapshot_inputs, snapshot_context=snapshot_context)
    bound = snapshot_audit["bound_example_ids"]
    connected_rows = [row for rows in samples.values() for row in rows if row.example_id in bound]
    training_rows = [row for row in samples.get("train", ()) if row.example_id in bound and row.snapshot.rights == "training_and_evaluation"]
    independent_rows = [row for row in connected_rows if row.reviewer is not None and row.reviewer.basis == "independent_outcome" and row.outcome is not None]
    report = {"schema_version": "mio.offline_ranking_evaluation.v1", "task": "playbook_ranking",
              "feature_version": FEATURE_VERSION, "label_version": LABEL_VERSION,
              "baseline_selection_rules_digest": selection_rules_digest(),
              "metric_policy": {"version": "playbook-method-comparison.v2",
                                "generic": "valid_playbook_choice_for_every_method",
                                "abstention": "explicit_unavailable_or_unsupported_prediction",
                                "label_domain": "playbook_method_not_threat_truth"},
              "dataset_digest": digest([row.to_dict() if type(row) is LearningExample else row for row in examples]),
              "quarantine": quarantine, "deduplicated": duplicates, "partitions": {key: len(samples.get(key, ())) for key in ("train", "validation", "test", "replay_eval")},
              "costs": {"wrong_selection": wrong_cost, "abstention": abstain_cost}, "results": {},
              "decision": "retain_existing_select_playbook", "automatic_promotion": False,
              "real_world_holdout_verified": False,
              "knowledge_curated_snapshot_projection_consistent": snapshot_audit["connected"],
              # Deprecated v1 compatibility alias: this reflects local projection
              # consistency only, not a live or authenticated Knowledge connection.
              "knowledge_curated_snapshot_connected": snapshot_audit["connected"],
              "knowledge_snapshot_producer_authenticated": False,
              "snapshot_input_provenance": snapshot_audit["snapshots"],
              "curated_training_eligible_examples": len(training_rows),
              "curated_independent_outcome_labels_available": bool(independent_rows),
              "curated_reviewed_label_count": sum(row.reviewer is not None for row in connected_rows),
              "limits": ["evaluation_only", "no_product_admission", "no_real_world_generalization",
                         *( ["curated_snapshot_projection_consistent_not_training_evidence",
                             "curated_snapshot_input_connected_not_training_evidence"] if snapshot_audit["connected"]
                            else ["curated_snapshot_input_missing_or_rejected"] )]}
    artifact = None
    if samples.get("train") and samples.get("validation") and samples.get("test"):
        try:
            artifact = _fit_eligible(samples["train"], created_at=now, expires_at=artifact_expires_at)
            # Validate before any inference, including direct programmatic calls.
            artifact = RankingArtifact.from_dict(artifact.to_dict())
        except (DatasetGateError, ValueError):
            report["limits"].append("insufficient_or_invalid_training")
    else:
        report["limits"].append("complete_group_separated_supervised_split_unavailable")
    for partition in ("validation", "test", "replay_eval"):
        rows = samples.get(partition, [])
        result = {}
        methods = ("baseline", "centroid", "pattern_anomaly") if artifact else ("baseline",)
        for method in methods:
            outputs, durations = [], []
            for row in rows:
                started = perf_counter_ns()
                output = baseline_ranking(row.frame) if method == "baseline" else candidate_prediction(row.frame, artifact, kind=method)
                durations.append(perf_counter_ns() - started)
                outputs.append(output)
            result[method] = _metrics(rows, outputs, durations, wrong_cost=wrong_cost, abstain_cost=abstain_cost)
        report["results"][partition] = result
    if artifact:
        report["candidate_beats_baseline_in_this_evaluation"] = {
            method: all(report["results"][part][method]["weighted_cost"] < report["results"][part]["baseline"]["weighted_cost"] for part in ("validation", "test"))
            for method in ("centroid", "pattern_anomaly")}
        artifact = replace(artifact, evaluation_digest=digest(report))
    return report, artifact


def main():
    import argparse
    import json
    from pathlib import Path
    from dataclasses import fields
    from .snapshot_input import (ConsumedSnapshotInput, SnapshotInputContext,
        SnapshotRecordBinding, SnapshotSourceBinding)

    def strict_object(value, cls):
        if type(value) is not dict or set(value) != {field.name for field in fields(cls)}:
            raise ValueError("invalid_snapshot_input_shape")
        value = dict(value)
        if cls is SnapshotSourceBinding:
            if type(value["lineage"]) is not list: raise ValueError("invalid_snapshot_input_shape")
            value["lineage"] = tuple(value["lineage"])
        return cls(**value)

    def load_snapshot_input(value):
        if type(value) is not dict or set(value) != {field.name for field in fields(ConsumedSnapshotInput)}:
            raise ValueError("invalid_snapshot_input_shape")
        data = dict(value)
        for name in ("source_refs",):
            if type(data[name]) is not list: raise ValueError("invalid_snapshot_input_shape")
            data[name] = tuple(data[name])
        if type(data["source_bindings"]) is not list or type(data["record_bindings"]) is not list:
            raise ValueError("invalid_snapshot_input_shape")
        data["source_bindings"] = tuple(strict_object(row, SnapshotSourceBinding) for row in data["source_bindings"])
        data["record_bindings"] = tuple(strict_object(row, SnapshotRecordBinding) for row in data["record_bindings"])
        return ConsumedSnapshotInput(**data)

    def load_snapshot_context(value):
        if type(value) is not dict or set(value) != {field.name for field in fields(SnapshotInputContext)}:
            raise ValueError("invalid_snapshot_context_shape")
        data = dict(value)
        for name in ("revoked_refs", "consumption_bindings"):
            if type(data[name]) is not list: raise ValueError("invalid_snapshot_context_shape")
            data[name] = tuple(tuple(row) if name == "consumption_bindings" and type(row) is list else row for row in data[name])
        return SnapshotInputContext(**data)

    parser = argparse.ArgumentParser(description="Offline evaluation only; never activates a model")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--artifact", type=Path)
    args = parser.parse_args()
    if args.manifest.stat().st_size > 8 * 1024 * 1024: raise ValueError("manifest_budget")
    manifest = parse_json(args.manifest.read_text())
    required = {"examples", "partitions", "now", "artifact_expires_at", "revoked_snapshots", "costs"}
    optional = {"snapshot_inputs", "snapshot_context"}
    if type(manifest) is not dict or not required <= set(manifest) or set(manifest) - required - optional:
        raise ValueError("invalid_local_evaluation_manifest")
    snapshot_inputs = manifest.get("snapshot_inputs", [])
    if type(snapshot_inputs) is not list: raise ValueError("invalid_snapshot_input_shape")
    snapshot_inputs = tuple(load_snapshot_input(value) for value in snapshot_inputs)
    snapshot_context = manifest.get("snapshot_context")
    if snapshot_context is not None: snapshot_context = load_snapshot_context(snapshot_context)
    report, artifact = evaluate(manifest["examples"], manifest["partitions"], now=manifest["now"],
        artifact_expires_at=manifest["artifact_expires_at"], revoked_snapshots=manifest["revoked_snapshots"],
        wrong_cost=manifest["costs"]["wrong_selection"], abstain_cost=manifest["costs"]["abstention"],
        snapshot_inputs=snapshot_inputs, snapshot_context=snapshot_context)
    # Exclusive creation makes artifacts immutable by this command. Registry
    # selection/revocation is a separate explicit operation and never happens here.
    # Preflight only: reject report/artifact aliasing and any existing output (including dangling
    # symlinks) before the first write. This is not atomic: concurrent creators or write failures
    # after the first open can still leave partial output.
    writes_artifact = artifact is not None and args.artifact is not None
    if writes_artifact and args.report.resolve() == args.artifact.resolve(): raise FileExistsError(f"output_alias: {args.report}")
    # Without this, a missing report directory would fail only after the artifact was already created.
    if writes_artifact and not args.report.parent.is_dir(): raise FileNotFoundError(f"report_parent_missing: {args.report.parent}")
    for target in ((args.report, args.artifact) if writes_artifact else (args.report,)):
        if target.exists() or target.is_symlink(): raise FileExistsError(f"output_exists: {target}")
    if writes_artifact:
        with args.artifact.open("x") as handle: handle.write(canonical(artifact.to_dict()) + "\n")
    with args.report.open("x") as handle: handle.write(canonical(report) + "\n")


if __name__ == "__main__": main()
