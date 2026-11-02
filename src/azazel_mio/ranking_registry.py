"""Explicit evaluation registry, separate from artifact bytes and product admission."""
from dataclasses import asdict, dataclass, replace
import json
import re

from .learning_data import canonical, codes, digest, instant, parse_json


@dataclass(frozen=True)
class EvaluationRegistration:
    artifact_digest: str
    created_at: str
    expires_at: str
    snapshots: tuple[str, ...]


@dataclass(frozen=True)
class EvaluationRegistry:
    records: tuple[EvaluationRegistration, ...] = ()
    selected: str | None = None
    history: tuple[str, ...] = ()
    revoked_artifacts: tuple[str, ...] = ()
    revoked_snapshots: tuple[str, ...] = ()

    def to_dict(self):
        return json.loads(canonical({"schema_version": "mio.evaluation_registry.v1", **asdict(self)}))

    @classmethod
    def from_dict(cls, raw):
        if type(raw) is not dict or set(raw) != set(cls.__dataclass_fields__) | {"schema_version"} or raw["schema_version"] != "mio.evaluation_registry.v1":
            raise ValueError("invalid_evaluation_registry")
        def hashes(values, cap):
            if type(values) is not list or len(values) > cap or any(type(x) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in values):
                raise ValueError("invalid_registry_digests")
            return tuple(values)
        if type(raw["records"]) is not list or len(raw["records"]) > 128: raise ValueError("invalid_registry_records")
        records = []
        for record in raw["records"]:
            if type(record) is not dict or set(record) != set(EvaluationRegistration.__dataclass_fields__): raise ValueError("invalid_registry_record")
            hashes([record["artifact_digest"]], 1)
            if not instant(record["created_at"]) < instant(record["expires_at"]): raise ValueError("invalid_registry_interval")
            records.append(EvaluationRegistration(record["artifact_digest"], record["created_at"], record["expires_at"], codes(record["snapshots"], 2048)))
        identifiers = {record.artifact_digest for record in records}
        if len(identifiers) != len(records): raise ValueError("duplicate_registry_record")
        selected = raw["selected"]
        if selected is not None and (type(selected) is not str or selected not in identifiers): raise ValueError("unknown_registry_selection")
        history = hashes(raw["history"], 128)
        if not set(history) <= identifiers: raise ValueError("unknown_registry_history")
        return cls(tuple(records), selected, history, hashes(raw["revoked_artifacts"], 128), codes(raw["revoked_snapshots"], 2048))

    def register(self, artifact: dict, *, now: str, evaluation_report: dict):
        from .playbook_ranker import RankingArtifact
        value = RankingArtifact.from_dict(artifact)
        if (type(evaluation_report) is not dict or evaluation_report.get("schema_version") != "mio.offline_ranking_evaluation.v1"
                or evaluation_report.get("task") != "playbook_ranking" or evaluation_report.get("automatic_promotion") is not False
                or digest(evaluation_report) != value.evaluation_digest):
            raise ValueError("evaluation_evidence_mismatch")
        if not instant(value.created_at) <= instant(now) < instant(value.expires_at): raise ValueError("artifact_not_current")
        identifier = artifact["artifact_digest"]
        if identifier in self.revoked_artifacts or set(value.source_snapshots) & set(self.revoked_snapshots): raise ValueError("artifact_or_source_revoked")
        if any(record.artifact_digest == identifier for record in self.records): return self
        if len(self.records) >= 128: raise ValueError("evaluation_registry_full")
        record = EvaluationRegistration(identifier, value.created_at, value.expires_at, value.source_snapshots)
        return replace(self, records=(*self.records, record))  # registration never selects

    def usable(self, identifier: str, *, now: str) -> bool:
        if self.selected != identifier or identifier in self.revoked_artifacts: return False
        for record in self.records:
            if record.artifact_digest == identifier:
                return (instant(record.created_at) <= instant(now) < instant(record.expires_at)
                        and not set(record.snapshots) & set(self.revoked_snapshots))
        return False

    def select_for_evaluation(self, identifier: str, *, now: str):
        candidate = replace(self, selected=identifier)
        if not candidate.usable(identifier, now=now): raise ValueError("evaluation_selection_rejected")
        if identifier == self.selected: return self
        history = (*self.history, self.selected) if self.selected is not None else self.history
        return replace(candidate, history=history[-128:])

    def revoke(self, *, artifact_digest=None, snapshot=None):
        if (artifact_digest is None) == (snapshot is None): raise ValueError("one_revocation_target_required")
        if artifact_digest is not None and (type(artifact_digest) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest)):
            raise ValueError("invalid_revocation_digest")
        if snapshot is not None: codes((snapshot,), 1)
        artifacts = self.revoked_artifacts + ((artifact_digest,) if artifact_digest not in self.revoked_artifacts and artifact_digest is not None else ())
        snapshots = self.revoked_snapshots + ((snapshot,) if snapshot not in self.revoked_snapshots and snapshot is not None else ())
        if len(artifacts) > 128 or len(snapshots) > 2048: raise ValueError("revocation_registry_full")
        result = replace(self, revoked_artifacts=artifacts, revoked_snapshots=snapshots)
        selected_record = next((item for item in self.records if item.artifact_digest == result.selected), None)
        if result.selected in artifacts or (selected_record and set(selected_record.snapshots) & set(snapshots)):
            result = replace(result, selected=None)
        return result

    def rollback(self, *, now: str):
        for index in range(len(self.history) - 1, -1, -1):
            candidate = replace(self, selected=self.history[index], history=self.history[:index])
            if candidate.usable(candidate.selected, now=now): return candidate
        return replace(self, selected=None, history=())


def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Evaluation-only registry; no product activation")
    parser.add_argument("action", choices=("register", "select-evaluation", "revoke-artifact", "revoke-snapshot", "rollback"))
    parser.add_argument("--state", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--evaluation-report", type=Path)
    parser.add_argument("--now", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def load(path, cap):
        if path.stat().st_size > cap: raise ValueError("registry_file_budget")
        return parse_json(path.read_text())
    state = EvaluationRegistry.from_dict(load(args.state, 128 * 1024)) if args.state else EvaluationRegistry()
    if args.action == "register":
        if args.artifact is None or args.evaluation_report is None: parser.error("register requires artifact and evaluation report")
        state = state.register(load(args.artifact, 512 * 1024), now=args.now, evaluation_report=load(args.evaluation_report, 1024 * 1024))
    elif args.action == "select-evaluation": state = state.select_for_evaluation(args.target, now=args.now)
    elif args.action == "revoke-artifact": state = state.revoke(artifact_digest=args.target)
    elif args.action == "revoke-snapshot": state = state.revoke(snapshot=args.target)
    else: state = state.rollback(now=args.now)
    with args.out.open("x") as handle: handle.write(canonical(state.to_dict()) + "\n")


if __name__ == "__main__": main()
