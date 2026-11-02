"""Pure runtime ranking. Existing select_playbook remains the default policy."""
from __future__ import annotations

from dataclasses import dataclass
import math

from .contracts import MioSituationFrame
from .learning_data import FEATURE_VERSION, LABEL_VERSION, LABELS, canonical, digest, instant, parse_json
from .playbook import SELECTION_RULES, _frame_tokens, select_playbook, selection_rules_digest

RUNTIME_VERSION = "mio-offline-ranking.v2"
DIMENSIONS = len(SELECTION_RULES) + 1


def features(frame: MioSituationFrame) -> tuple[int, ...]:
    frame = MioSituationFrame.from_dict(frame.to_dict())
    tokens = _frame_tokens(frame)  # existing selection semantics; excludes known_facts
    return tuple(int(bool(words & tokens)) for _, words in SELECTION_RULES) + (int(frame.deception_status == "available"),)


def baseline_ranking(frame: MioSituationFrame) -> dict:
    selection = select_playbook(frame)
    selected = selection.playbook.playbook_id
    return {"method": "existing_select_playbook", "selected": selected,
            "ranking": [selected],  # existing selector provides no ordering for other playbooks
            "selection_reason": selection.reason, "selection_rules_digest": selection_rules_digest(),
            # Generic is an existing legitimate playbook, not an implicit
            # abstention reserved to this baseline. Preserve fallback context
            # separately from genuine unavailable/unsupported predictions.
            "fallback_reasons": [selection.reason] if selection.is_generic_fallback else [],
            "abstain_reasons": [],
            "limits": ["advisory_playbook_method_only", "not_probability", "baseline_default"]}


@dataclass(frozen=True)
class RankingArtifact:
    created_at: str
    expires_at: str
    centroids: tuple[tuple[str, tuple[float, ...]], ...]
    patterns: tuple[tuple[int, ...], ...]
    training_digests: tuple[str, ...]
    source_snapshots: tuple[str, ...]
    source_generations: tuple[str, ...]
    source_rights: tuple[str, ...]
    source_lineage: tuple[tuple[str, ...], ...]
    data_kinds: tuple[str, ...]
    evaluation_digest: str
    feature_definition_digest: str
    feature_version: str = FEATURE_VERSION
    label_version: str = LABEL_VERSION
    runtime_version: str = RUNTIME_VERSION
    use: str = "evaluation_only"

    def to_dict(self) -> dict:
        raw = {"schema_version": "mio.ranking_artifact.v1", "task": "playbook_ranking",
               **{key: getattr(self, key) for key in self.__dataclass_fields__}}
        import json
        raw = json.loads(canonical(raw))
        raw["artifact_digest"] = digest(raw)
        return raw

    @classmethod
    def from_dict(cls, raw: dict) -> "RankingArtifact":
        from .learning_data import codes
        if type(raw) is not dict or set(raw) != set(cls.__dataclass_fields__) | {"schema_version", "task", "artifact_digest"}:
            raise ValueError("invalid_ranking_artifact_fields")
        payload = {key: value for key, value in raw.items() if key != "artifact_digest"}
        if raw["schema_version"] != "mio.ranking_artifact.v1" or raw["task"] != "playbook_ranking" or digest(payload) != raw["artifact_digest"]:
            raise ValueError("ranking_artifact_digest_or_schema")
        if raw["feature_definition_digest"] != digest({"selection_rules": selection_rules_digest(), "deception_feature": "available.v1"}):
            raise ValueError("ranking_artifact_feature_definition")
        if raw["use"] != "evaluation_only": raise ValueError("ranking_artifact_use")
        if (raw["feature_version"], raw["label_version"], raw["runtime_version"]) != (FEATURE_VERSION, LABEL_VERSION, RUNTIME_VERSION):
            raise ValueError("ranking_artifact_compatibility")
        if not instant(raw["created_at"]) < instant(raw["expires_at"]): raise ValueError("ranking_artifact_interval")
        centroids = raw["centroids"]
        patterns = raw["patterns"]
        if type(centroids) is not list or not 1 <= len(centroids) <= len(LABELS) or type(patterns) is not list or not 1 <= len(patterns) <= 2048:
            raise ValueError("ranking_artifact_model_size")
        for row in centroids:
            if type(row) is not list or len(row) != 2 or row[0] not in LABELS or type(row[1]) is not list or len(row[1]) != DIMENSIONS:
                raise ValueError("ranking_artifact_centroid")
            if any(type(x) not in (int, float) or not math.isfinite(x) or not 0 <= x <= 1 for x in row[1]): raise ValueError("ranking_artifact_number")
        if len({row[0] for row in centroids}) != len(centroids): raise ValueError("ranking_artifact_duplicate_label")
        if any(type(row) is not list or len(row) != DIMENSIONS or any(type(x) is not int or x not in (0, 1) for x in row) for row in patterns):
            raise ValueError("ranking_artifact_pattern")
        from re import fullmatch
        for field in ("training_digests",):
            if type(raw[field]) is not list or not 2 <= len(raw[field]) <= 2048 or any(type(x) is not str or not fullmatch(r"sha256:[0-9a-f]{64}", x) for x in raw[field]):
                raise ValueError("ranking_artifact_training_lineage")
        if not isinstance(raw["evaluation_digest"], str) or not fullmatch(r"sha256:[0-9a-f]{64}", raw["evaluation_digest"]): raise ValueError("ranking_artifact_evaluation")
        for field in ("source_snapshots", "source_generations", "source_rights", "data_kinds"):
            codes(raw[field], 2048)
        if not raw["source_snapshots"] or len(raw["source_snapshots"]) != len(raw["source_generations"]) or len(raw["source_snapshots"]) != len(raw["source_rights"]) or len(raw["source_snapshots"]) != len(raw["source_lineage"]):
            raise ValueError("ranking_artifact_sources")
        if any(right != "training_and_evaluation" for right in raw["source_rights"]): raise ValueError("ranking_artifact_rights")
        if not raw["data_kinds"] or any(kind not in {"curated_observation", "synthetic_fixture"} for kind in raw["data_kinds"]): raise ValueError("ranking_artifact_data_kind")
        if type(raw["source_lineage"]) is not list or any(not codes(row) for row in raw["source_lineage"]): raise ValueError("ranking_artifact_source_lineage")
        values = {key: raw[key] for key in cls.__dataclass_fields__}
        values.update(centroids=tuple((label, tuple(vector)) for label, vector in centroids), patterns=tuple(tuple(row) for row in patterns),
                      source_lineage=tuple(tuple(row) for row in raw["source_lineage"]))
        for field in ("training_digests", "source_snapshots", "source_generations", "source_rights", "data_kinds"):
            values[field] = tuple(raw[field])
        return cls(**values)


def candidate_prediction(frame: MioSituationFrame, artifact: RankingArtifact, *, kind: str) -> dict:
    """Evaluation inference only. Distances/novelty are not probabilities."""
    if kind not in {"centroid", "pattern_anomaly"}: raise ValueError("unknown_ranking_candidate")
    vector = features(frame)
    ranked = sorted((sum((value - center) ** 2 for value, center in zip(vector, centroid)) / DIMENSIONS, label)
                    for label, centroid in artifact.centroids)
    novelty = min(sum(a != b for a, b in zip(vector, pattern)) / DIMENSIONS for pattern in artifact.patterns)
    reasons = []
    if not any(vector): reasons.append("features_absent")
    if any(value and not any(pattern[i] for pattern in artifact.patterns) for i, value in enumerate(vector)): reasons.append("feature_drift")
    if kind == "centroid" and len(ranked) > 1 and ranked[0][0] == ranked[1][0]: reasons.append("ranking_tie")
    if kind == "pattern_anomaly" and novelty > 0: reasons.append("unfamiliar_pattern")
    baseline = baseline_ranking(frame)
    if kind == "pattern_anomaly":
        reasons.extend(baseline["abstain_reasons"])
    return {"method": kind, "selected": None if reasons else (ranked[0][1] if kind == "centroid" else baseline["selected"]),
            "ranking": [label for _, label in ranked] if kind == "centroid" else baseline["ranking"],
            "distance_scores": [{"label": label, "distance": distance} for distance, label in ranked],
            "novelty": novelty, "abstain_reasons": reasons,
            "fallback_reasons": baseline["fallback_reasons"] if kind == "pattern_anomaly" else [],
            "limits": ["evaluation_only", "not_probability", "novelty_not_maliciousness", "no_product_admission"]}


def rank_playbooks(frame: MioSituationFrame, *, artifact: dict | None = None, registry=None, now: str | None = None, kind="centroid") -> dict:
    """Baseline by default; explicit registered candidates are still evaluation-only."""
    baseline = baseline_ranking(frame)
    if artifact is None:
        return baseline
    try:
        candidate = RankingArtifact.from_dict(artifact)
        if now is None or not instant(candidate.created_at) <= instant(now) < instant(candidate.expires_at): raise ValueError("artifact_not_current")
        from .ranking_registry import EvaluationRegistry
        if type(registry) is not EvaluationRegistry: raise ValueError("artifact_not_registered_for_evaluation")
        registry = EvaluationRegistry.from_dict(registry.to_dict())
        if not registry.usable(artifact["artifact_digest"], now=now): raise ValueError("artifact_not_registered_for_evaluation")
        prediction = candidate_prediction(frame, candidate, kind=kind)
        return {**baseline, "candidate": prediction, "method": "baseline_with_evaluation_candidate"}
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return {**baseline, "candidate_rejected": True, "limits": baseline["limits"] + ["candidate_unavailable_or_incompatible"]}


def main():
    import argparse
    import json
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Baseline playbook ranking; candidate activation is never implicit")
    parser.add_argument("frame", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--now")
    parser.add_argument("--kind", choices=("centroid", "pattern_anomaly"), default="centroid")
    args = parser.parse_args()
    def load(path, cap):
        if path.stat().st_size > cap: raise ValueError("runtime_file_budget")
        return parse_json(path.read_text())
    frame = MioSituationFrame.from_dict(load(args.frame, 65536))
    if any((args.artifact, args.registry, args.now)) and not all((args.artifact, args.registry, args.now)):
        parser.error("artifact, registry and now must be supplied together")
    registry, artifact = None, None
    if args.artifact:
        from .ranking_registry import EvaluationRegistry
        artifact = load(args.artifact, 512 * 1024)
        registry = EvaluationRegistry.from_dict(load(args.registry, 128 * 1024))
    print(canonical(rank_playbooks(frame, artifact=artifact, registry=registry, now=args.now, kind=args.kind)))



if __name__ == "__main__": main()
