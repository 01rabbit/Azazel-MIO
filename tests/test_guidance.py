import json
import unittest
from unittest import mock

from azazel_mio import guidance as G
from azazel_mio.contracts import MioSituationFrame

REF = "sha256:" + "ab" * 32
WITHHELD = ("198.51.100.18", "198.51.100.19")

NOC_REPORT = ("Synthetic 5m report: DNS timeouts 18/60 vs prior 0/60; existing TCP checks 60/60. "
              "One probe, one resolver; other sites unknown. Clock trust and affected population are unknown. "
              "Read-only checks; preserve essential communication.")
SOC_REPORT = ("Synthetic 5m auth report: 24 failed logins vs prior 1; success logs absent; "
              "approved automation and credential changes unknown. Clock trust and affected population are unknown. "
              "Read-only checks; preserve essential communication.")


def frame(report, ref=REF, signature="DNS resolver timeouts"):
    return MioSituationFrame.build(
        frame_id="mio-x-1:frame", trace_id="mio-x-1", created_at="2026-11-08T00:00:00Z",
        mission="Assess the supplied security situation; no operational authority",
        current_defensive_state="OBSERVE", threat_level="UNKNOWN",
        noc_summary="Edge signature (unverified report): " + signature, soc_summary=report,
        unknowns=["Situation question and context are untrusted reports"], evidence_refs=[ref])


def noc(report=NOC_REPORT, **kw):
    return G.build_guidance(frame(report), report_texts=[report], withheld_values=WITHHELD, request_id="inc-x:1", incident_id="inc-x", privacy_class="P3-restricted", **kw)


def soc(report=SOC_REPORT, **kw):
    return G.build_guidance(frame(report, signature="auth report failed logins"), report_texts=[report], withheld_values=WITHHELD, request_id="inc-y:1", incident_id="inc-y", privacy_class="P3-restricted", **kw)


def req(g):
    return [c["id"] for c in g.next_checks if c["tier"] == "required"]


class GuidanceTests(unittest.TestCase):
    def test_summary_elements_noc(self):
        g = noc()
        d = g.to_dict()
        self.assertEqual(d["content_kind"], "deterministic_guidance")
        self.assertEqual(d["guidance_schema_version"], "1.0.0")
        self.assertEqual((d["model_calls"], d["generation_method"]), (0, "deterministic_guidance"))
        self.assertEqual(g.playbook_id, "dns-resolution-degradation-v1")
        obs = [f for f in g.facts if f["kind"] == "supplied_report"]
        self.assertTrue(any("18/60" in f["text"] and "0/60" in f["text"] for f in obs))
        self.assertTrue(all(f["trust"] == "untrusted_report" for f in obs))
        self.assertEqual(len(req(g)), 2)
        self.assertTrue(any("other sites unknown" in u for u in g.unknowns))
        self.assertIn("report", next(x for x in g.unknown_groups if "other sites" in x["text"])["sources"])
        self.assertEqual(g.recommendation, {"recommended_action": "OBSERVE", "executable": False, "current_action": None, "source": "deterministic_fixed"})
        self.assertEqual(g.evidence_gaps["items"], [])
        self.assertTrue(g.evidence_gaps["reason"])
        self.assertTrue(g.playbook_digest.startswith("sha256:"))
        for e in g.competing_explanations:
            self.assertEqual(e["support"], "unverified_candidate")
            self.assertEqual(e["evidence_refs"], [REF])
        json.dumps(d)

    def test_summary_elements_soc(self):
        g = soc()
        self.assertEqual(g.playbook_id, "auth-ambiguity-v1")
        self.assertTrue(any("24 failed logins" in f["text"] for f in g.facts))
        self.assertEqual(len(req(g)), 2)
        self.assertTrue(any("success" in u.lower() for u in g.unknowns))
        self.assertTrue(any("frame_analysis" in x["sources"] or "report" in x["sources"] for x in g.unknown_groups))
        self.assertEqual(g.recommendation["recommended_action"], "OBSERVE")
        self.assertEqual(g.weight_notes, ())

    def test_new_information_updates_unknowns(self):
        base = soc()
        new = soc(SOC_REPORT.replace("success logs absent", "one successful login after the failures is reported"))
        self.assertFalse(any("success logs absent" in u for u in new.unknowns))
        self.assertTrue(any(u.startswith("Reported, not verified") for u in new.unknowns))
        self.assertTrue(any(w["explanation"] == "credential_attack" and w["direction"] == "verification_priority_up" for w in new.weight_notes))
        self.assertNotEqual(new.to_dict(), base.to_dict())
        self.assertTrue(any("successful login" in c["text"] for c in new.next_checks if c["tier"] == "required"))
        # no compromise or actor is asserted from a reported success
        text = json.dumps(new.to_dict()).lower()
        for banned in ("compromised", "attacker is", "breach confirmed"):
            self.assertNotIn(banned, text)
        noc_new = noc(NOC_REPORT.replace("other sites unknown", "two other sites report no timeouts against the same resolver"))
        self.assertFalse(any("other sites unknown" in u for u in noc_new.unknowns))
        self.assertTrue(any(w["explanation"] == "probe_specific_or_partial_link" for w in noc_new.weight_notes))

    def test_negation_does_not_raise(self):
        g = soc(SOC_REPORT.replace("success logs absent", "no successful login is reported after the failures"))
        self.assertFalse(any(w["explanation"] == "credential_attack" and w["direction"] == "verification_priority_up" for w in g.weight_notes))
        self.assertTrue(any(t["id"] == "auth_success" and t["negative"] for t in g.topics_addressed))
        n = noc(NOC_REPORT.replace("other sites unknown", "no other sites were reported"))
        self.assertFalse(any(t["id"] == "dns_other_sites" for t in n.topics_addressed))
        self.assertEqual(n.weight_notes, ())

    def test_withheld_not_exposed(self):
        report = NOC_REPORT + " Source 198.51.100.18 and target 198.51.100.19 observed. Another observation: 3 hosts."
        g = noc(report, knowledge_facts=[{"claim_class": "observed", "value": "peer 198.51.100.18"}], knowledge_unknowns=["owner of 198.51.100.19 unknown"])
        blob = json.dumps(g.to_dict())
        for v in WITHHELD:
            self.assertNotIn(v, blob)
        self.assertIn(G.WITHHELD_MARK, blob)

    def test_family_swap(self):
        a = noc()
        b = G.build_guidance(frame(SOC_REPORT, signature="auth report failed logins"), report_texts=[NOC_REPORT])
        self.assertNotEqual(a.playbook_id, b.playbook_id)
        self.assertNotEqual(a.playbook_digest, b.playbook_digest)

    def test_values_follow_input(self):
        g = noc(NOC_REPORT.replace("18/60", "7/60").replace("prior 0/60", "prior 2/60"))
        blob = json.dumps(g.to_dict())
        self.assertIn("7/60", blob)
        self.assertNotIn("18/60", blob)
        ref2 = "sha256:" + "cd" * 32
        g2 = G.build_guidance(frame(NOC_REPORT, ref=ref2), report_texts=[NOC_REPORT])
        self.assertIn(ref2, json.dumps(g2.to_dict()))
        self.assertNotIn(REF, json.dumps(g2.to_dict()))
        self.assertEqual(g2.handoff["evidence_refs"], [ref2])

    def test_no_case_name_and_handoff_binding(self):
        for g in (noc(), soc()):
            blob = json.dumps(g.to_dict())
            for name in ("NOC1", "SOC1"):
                self.assertNotIn(name, blob)
            h = g.handoff
            self.assertEqual((h["trace_id"], h["frame_id"]), ("mio-x-1", "mio-x-1:frame"))
            self.assertEqual(h["privacy_class"], "P3-restricted")
            self.assertEqual(h["sections"]["execution"], "none (current_action null)")

    def test_unknown_comparison_not_generated(self):
        # time window / probe / resolver correspondence is not supplied: no sentence compares or attributes
        text = json.dumps(noc().to_dict()).lower()
        for banned in ("caused by", "root cause", "is the cause", "confirmed outage"):
            self.assertNotIn(banned, text)

    def test_capabilities_gap_only_with_capability(self):
        g = soc(effective_read_capabilities=("query_recent_alerts", "lookup_behavior_pattern"))
        self.assertTrue(g.evidence_gaps["items"])
        self.assertTrue(all(i["capability"] in ("query_recent_alerts", "lookup_behavior_pattern") for i in g.evidence_gaps["items"]))

    def test_topics_validated_and_digest_follows_topics(self):
        self.assertEqual(G.validate_topics(), ())
        base = G.guidance_digest()
        mutated = {k: tuple(dict(t) for t in v) for k, v in G.TOPICS.items()}
        mutated["auth-ambiguity-v1"][0]["note"] = "changed"
        with mock.patch.object(G, "TOPICS", mutated):
            self.assertNotEqual(G.guidance_digest(), base)
        bad = {"auth-ambiguity-v1": ({**G.TOPICS["auth-ambiguity-v1"][0], "note": "run `x` && isolate it"},)}
        errs = G.validate_topics(bad)
        self.assertTrue(any("shell_syntax" in e for e in errs))
        self.assertTrue(any("directive_language" in e for e in errs))
        with mock.patch.object(G, "TOPICS", bad):
            with self.assertRaises(ValueError):
                noc()
        long_ = {"auth-ambiguity-v1": ({**G.TOPICS["auth-ambiguity-v1"][0], "note": "x" * 400},)}
        self.assertTrue(G.validate_topics(long_))




class ReportEpistemicsTests(unittest.TestCase):
    N2 = ("One probe timed out on 31 of 60 DNS lookups in 5 minutes, spread across three different resolvers. "
          "A colleague mentioned that other probes looked fine, but no record was attached. TCP checks from the probe were not run.")
    S3 = ("Login failures for account backup-sync occur every 15 minutes, 8 per burst, since 02:00. An engineer thinks this may be "
          "the nightly backup job retrying after a credential change, but no automation record has been read yet.")
    S4 = ("One analyst reports 60 failed logins for account ops-test with no successful login. A second note says a login succeeded at 11:42 "
          "but gives a different time zone and no count. The two reports cover windows that may not overlap.")

    def test_hearsay_is_note_and_moves_nothing(self):
        g = noc(self.N2)
        self.assertEqual(g.weight_notes, ())
        self.assertFalse(any(t["id"] == "dns_other_sites" for t in g.topics_addressed))
        self.assertTrue(any(f["kind"] == "supplied_report_note" and "colleague mentioned" in f["text"] for f in g.facts))
        self.assertTrue(any(u.startswith("Reported, not verified: A colleague mentioned") for u in g.unknowns))

    def test_negated_confirmation_phrases_are_gaps(self):
        g = noc(self.N2)
        gaps = [f["text"] for f in g.facts if f["kind"] == "supplied_report_gap"]
        self.assertTrue(any("no record was attached" in x for x in gaps))
        self.assertTrue(any("were not run" in x for x in gaps))
        self.assertTrue(any("no record was attached" in u["text"] and "report" in u["sources"] for u in g.unknown_groups))
        for text in ("The 14:05 window has not been aggregated yet", "Whether the link is shared is not documented in the report",
                     "There is no confirmation of the stop", "The reporter did not say which source"):
            kinds = [f["kind"] for f in noc(text).facts if f["text"].startswith(text[:12])]
            self.assertEqual(kinds, ["supplied_report_gap"], text)

    def test_hedged_inference_is_not_a_reported_automation(self):
        g = soc(self.S3)
        self.assertFalse(any(t["id"] == "auth_baseline" for t in g.topics_addressed))
        self.assertEqual([w for w in g.weight_notes if w["topic"] == "auth_baseline"], [])
        self.assertTrue(any("no automation record has been read yet" in f["text"] and f["kind"] == "supplied_report_gap" for f in g.facts))

    def test_incomparable_reports_do_not_change_priority(self):
        g = soc(self.S4)
        self.assertEqual(g.weight_notes, ())
        self.assertTrue(any(u["text"] == G.COMPARE_UNKNOWN and "report" in u["sources"] for u in g.unknown_groups))
        self.assertEqual(g.recommendation["recommended_action"], "OBSERVE")

    def test_negative_cases_unchanged(self):
        base = "Probe A queries resolver R1 and 22 of 60 lookups timed out in the last 5 minutes, against 0 of 60 before. "
        up = noc(base + "Two other probes also timed out against R1.")
        self.assertTrue(any(w["explanation"] == "resolver_or_path_degradation" for w in up.weight_notes))
        down = noc(base + "Two other probes report no timeouts against R1.")
        self.assertTrue(any(w["explanation"] == "probe_specific_or_partial_link" for w in down.weight_notes))
        plain = soc("A user reports that a successful login happened after about 40 failed web logins on account jdoe-test.")
        self.assertTrue(any(w["explanation"] == "credential_attack" and w["direction"] == "verification_priority_up" for w in plain.weight_notes))
        self.assertTrue(any(f["kind"] == "supplied_report" for f in plain.facts))

    def test_invariants(self):
        for g in (noc(self.N2), soc(self.S3), soc(self.S4)):
            d = g.to_dict()
            self.assertEqual((d["guidance_schema_version"], d["model_calls"]), ("1.0.0", 0))
            self.assertEqual(g.recommendation["executable"], False)
            self.assertEqual(len(req(g)), 2)


if __name__ == "__main__":
    unittest.main()
