import copy
import dataclasses
import unittest

from azazel_mio.assessment import READ_ONLY_CHECKS, Observation, assess
from azazel_mio.assessment_routing import (
    PATH_HUMAN_REVIEW,
    PATH_READ_ONLY_CHECKS,
    REASON_INSUFFICIENT_EVIDENCE,
    REASON_INVALID_CHECKS,
    REASON_INVALID_COUNT,
    REASON_INVALID_EVIDENCE,
    REASON_INVALID_SHAPE,
    REASON_INVALID_STATUS,
    REASON_REVIEW_WITH_CHECKS,
    REASON_UNSUPPORTED_PRESENT,
    FastReviewRecommendation,
    recommend_fast_review,
)

KNOWN_REASONS = {
    REASON_INSUFFICIENT_EVIDENCE, REASON_UNSUPPORTED_PRESENT,
    REASON_INVALID_SHAPE, REASON_INVALID_STATUS, REASON_INVALID_COUNT,
    REASON_INVALID_CHECKS, REASON_INVALID_EVIDENCE,
    "review_recommended_read_only_checks",
}
MARKER = "INJECTED-FREE-TEXT-MARKER"


def _valid(*observations):
    return assess("case-1", list(observations))


def _obs(signal, evidence="ev-1"):
    return Observation("case-1", evidence, signal)


class RoutingNormalTests(unittest.TestCase):
    def test_review_with_checks_routes_read_only(self):
        rec = recommend_fast_review(
            _valid(_obs("suspicious_process"), _obs("unusual_outbound", "ev-2")))
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)
        self.assertFalse(rec.deeper_review_recommended)
        self.assertEqual(rec.read_only_checks, (
            READ_ONLY_CHECKS["suspicious_process"],
            READ_ONLY_CHECKS["unusual_outbound"],
        ))
        self.assertEqual(rec.reason_codes, ("review_recommended_read_only_checks",))

    def test_unsupported_with_supported_checks_sets_advisory_flag(self):
        rec = recommend_fast_review(
            _valid(_obs("authentication_failures"), _obs("made_up_signal", "ev-2")))
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)
        self.assertTrue(rec.deeper_review_recommended)
        self.assertIn(REASON_UNSUPPORTED_PRESENT, rec.reason_codes)
        self.assertEqual(rec.read_only_checks,
                         (READ_ONLY_CHECKS["authentication_failures"],))

    def test_unsupported_only_routes_human_review_with_flag(self):
        rec = recommend_fast_review(_valid(_obs("made_up_signal")))
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertTrue(rec.deeper_review_recommended)
        self.assertEqual(rec.reason_codes,
                         (REASON_INSUFFICIENT_EVIDENCE, REASON_UNSUPPORTED_PRESENT))
        self.assertEqual(rec.read_only_checks, ())

    def test_empty_insufficient_evidence_routes_human_review(self):
        rec = recommend_fast_review(_valid())
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertFalse(rec.deeper_review_recommended)
        self.assertEqual(rec.reason_codes, (REASON_INSUFFICIENT_EVIDENCE,))


class RoutingFailClosedTests(unittest.TestCase):
    def assertFailsClosed(self, result, reason=None):
        rec = recommend_fast_review(result)
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertFalse(rec.deeper_review_recommended)
        self.assertEqual(rec.read_only_checks, ())
        self.assertEqual(len(rec.reason_codes), 1)
        self.assertIn(rec.reason_codes[0], KNOWN_REASONS)
        if reason is not None:
            self.assertEqual(rec.reason_codes, (reason,))
        return rec

    def base(self):
        return copy.deepcopy(_valid(_obs("suspicious_process")))

    def test_non_mapping_and_missing_keys(self):
        for bad in (None, [], "review", 3):
            with self.subTest(bad=bad):
                self.assertFailsClosed(bad, REASON_INVALID_SHAPE)
        missing = self.base()
        del missing["limitations"]
        self.assertFailsClosed(missing, REASON_INVALID_SHAPE)
        extra = self.base()
        extra["extra"] = 1
        self.assertFailsClosed(extra, REASON_INVALID_SHAPE)

    def test_unsupported_status(self):
        for status in ("approved", "", None, ["review_recommended"]):
            with self.subTest(status=status):
                r = self.base()
                r["status"] = status
                self.assertFailsClosed(r, REASON_INVALID_STATUS)

    def test_authority_and_probability_fields_tampered(self):
        r = self.base()
        r["authorized_actions"] = ["isolate"]
        self.assertFailsClosed(r, REASON_INVALID_SHAPE)
        r = self.base()
        r["priority_index_is_probability"] = True
        self.assertFailsClosed(r, REASON_INVALID_SHAPE)
        r = self.base()
        r["rule_version"] = "other"
        self.assertFailsClosed(r, REASON_INVALID_SHAPE)

    def test_counts_are_typed_and_bounded(self):
        for value in (True, -1, 10001, 1.0, "3"):
            with self.subTest(value=value):
                r = self.base()
                r["unsupported_observations"] = value
                self.assertFailsClosed(r, REASON_INVALID_COUNT)
        r = self.base()
        r["priority_index"] = 101
        self.assertFailsClosed(r, REASON_INVALID_COUNT)

    def test_checks_tampered_or_missing_fail_closed(self):
        r = self.base()
        r["next_read_only_checks"] = []
        self.assertFailsClosed(r, REASON_INVALID_CHECKS)
        r = self.base()
        r["next_read_only_checks"] = [MARKER]
        rec = self.assertFailsClosed(r, REASON_INVALID_CHECKS)
        self.assertNotIn(MARKER, repr(rec))
        r = self.base()
        r["next_read_only_checks"] = list(READ_ONLY_CHECKS.values()) * 2
        self.assertFailsClosed(r, REASON_INVALID_COUNT)

    def test_insufficient_with_hits_or_checks_is_inconsistent(self):
        r = copy.deepcopy(_valid())
        r["rule_hits"] = self.base()["rule_hits"]
        self.assertFailsClosed(r, REASON_INVALID_SHAPE)

    def test_review_without_hits_is_inconsistent(self):
        r = self.base()
        r["rule_hits"] = []
        self.assertFailsClosed(r, REASON_INVALID_SHAPE)

    def test_hit_validation(self):
        r = self.base()
        r["rule_hits"][0]["signal"] = MARKER
        self.assertFailsClosed(r, REASON_INVALID_SHAPE)
        r = self.base()
        r["rule_hits"][0]["weight"] = 999
        self.assertFailsClosed(r, REASON_INVALID_SHAPE)
        r = self.base()
        r["rule_hits"][0]["evidence_ids"] = [" padded "]
        self.assertFailsClosed(r, REASON_INVALID_EVIDENCE)
        r = self.base()
        r["rule_hits"][0]["evidence_ids"] = []
        self.assertFailsClosed(r, REASON_INVALID_COUNT)
        r = self.base()
        r["rule_hits"] = r["rule_hits"] * 5
        self.assertFailsClosed(r, REASON_INVALID_COUNT)

    def test_no_free_text_echo_on_rejection(self):
        r = self.base()
        r["status"] = MARKER
        rec = recommend_fast_review(r)
        self.assertNotIn(MARKER, repr(rec))
        self.assertEqual(rec.reason_codes, (REASON_INVALID_STATUS,))

    def test_input_is_not_mutated(self):
        r = self.base()
        before = copy.deepcopy(r)
        recommend_fast_review(r)
        self.assertEqual(r, before)


class RoutingNoActionTests(unittest.TestCase):
    def test_no_dispatch_or_actions_in_any_path(self):
        results = [
            _valid(_obs("suspicious_process"), _obs("made_up", "ev-2")),
            _valid(_obs("made_up")),
            _valid(),
            None,
        ]
        for result in results:
            with self.subTest(result=result):
                rec = recommend_fast_review(result)
                self.assertIs(rec.automatic_dispatch, False)
                self.assertEqual(rec.authorized_actions, ())

    def test_recommendation_is_immutable(self):
        rec = recommend_fast_review(_valid(_obs("suspicious_process")))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            rec.path = PATH_HUMAN_REVIEW

    def test_constructor_refuses_dispatch_or_actions(self):
        reasons = (REASON_INSUFFICIENT_EVIDENCE,)
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, False, reasons, (),
                                     automatic_dispatch=True)
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, False, reasons, (),
                                     authorized_actions=("isolate",))
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, False, reasons, (),
                                     automatic_dispatch=0)


class PriorityCrossCheckTests(unittest.TestCase):
    """Regression: priority_index must equal min(100, sum of hit weights)."""

    def test_priority_must_match_hit_weights(self):
        r = _valid(_obs("suspicious_process"))  # weight 30
        for value in (0, 20, 31, 100):
            with self.subTest(value=value):
                tampered = copy.deepcopy(r)
                tampered["priority_index"] = value
                rec = recommend_fast_review(tampered)
                self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
                self.assertEqual(rec.reason_codes, (REASON_INVALID_COUNT,))

    def test_priority_capped_sum_accepted_and_tampered_rejected(self):
        # All four signals sum to 105 and must be capped at 100.
        r = _valid(_obs("suspicious_process"), _obs("unusual_outbound", "ev-2"),
                   _obs("authentication_failures", "ev-3"),
                   _obs("confirmed_malware_indicator", "ev-4"))
        self.assertEqual(r["priority_index"], 100)
        rec = recommend_fast_review(r)
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)
        for value in (0, 99, 101):
            with self.subTest(value=value):
                tampered = copy.deepcopy(r)
                tampered["priority_index"] = value
                self.assertEqual(recommend_fast_review(tampered).reason_codes,
                                 (REASON_INVALID_COUNT,))

    def test_priority_nonzero_without_hits_rejected(self):
        r = copy.deepcopy(_valid())
        r["priority_index"] = 10
        rec = recommend_fast_review(r)
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertEqual(rec.reason_codes, (REASON_INVALID_SHAPE,))


class EvidenceBoundTests(unittest.TestCase):
    """Regression: evidence IDs are bounded across all hits, not per hit."""

    def _two_hits(self, first, second):
        r = copy.deepcopy(_valid(_obs("suspicious_process")))
        r["rule_hits"] = [
            {"signal": "suspicious_process", "weight": 30,
             "evidence_ids": [f"a-{i}" for i in range(first)]},
            {"signal": "unusual_outbound", "weight": 20,
             "evidence_ids": [f"b-{i}" for i in range(second)]},
        ]
        r["priority_index"] = 50
        r["next_read_only_checks"] = [
            READ_ONLY_CHECKS["suspicious_process"],
            READ_ONLY_CHECKS["unusual_outbound"],
        ]
        return r

    def test_total_over_bound_rejected_though_each_hit_is_within_bound(self):
        r = self._two_hits(5001, 5000)  # 10001 total; each hit <= 10000
        rec = recommend_fast_review(r)
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertEqual(rec.reason_codes, (REASON_INVALID_COUNT,))

    def test_total_at_bound_accepted(self):
        r = self._two_hits(5000, 5000)  # exactly 10000 total
        rec = recommend_fast_review(r)
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)


class CaseIdTests(unittest.TestCase):
    """Regression: case_id must be canonical text, as assess() requires."""

    def test_non_canonical_case_id_rejected(self):
        bad_values = ("", " case-1", "case-1 ", "case\n1", "x" * 257, 7, None,
                      ["case-1"])
        for bad in bad_values:
            with self.subTest(bad=bad):
                r = copy.deepcopy(_valid(_obs("suspicious_process")))
                r["case_id"] = bad
                rec = recommend_fast_review(r)
                self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
                self.assertEqual(rec.reason_codes, (REASON_INVALID_SHAPE,))

    def test_case_id_free_text_not_echoed(self):
        r = copy.deepcopy(_valid(_obs("suspicious_process")))
        r["case_id"] = MARKER + "\n"
        rec = recommend_fast_review(r)
        self.assertNotIn(MARKER, repr(rec))

    def test_case_id_at_length_bound_accepted(self):
        r = copy.deepcopy(_valid(_obs("suspicious_process")))
        r["case_id"] = "c" * 256
        rec = recommend_fast_review(r)
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)


class RecommendationConstructorTests(unittest.TestCase):
    """Regression: FastReviewRecommendation enforces strict, canonical fields."""

    CHECK_A = READ_ONLY_CHECKS["authentication_failures"]
    CHECK_B = READ_ONLY_CHECKS["suspicious_process"]

    def test_valid_construction_still_works(self):
        FastReviewRecommendation(PATH_HUMAN_REVIEW, False,
                                 (REASON_INSUFFICIENT_EVIDENCE,))
        FastReviewRecommendation(PATH_READ_ONLY_CHECKS, True,
                                 (REASON_REVIEW_WITH_CHECKS,),
                                 (self.CHECK_A, self.CHECK_B))

    def test_reason_codes_must_be_known_unique_tuple(self):
        bad = (
            ("free text reason",),
            [REASON_INSUFFICIENT_EVIDENCE],
            (),
            (REASON_INSUFFICIENT_EVIDENCE, REASON_INSUFFICIENT_EVIDENCE),
            (MARKER,),
        )
        for reasons in bad:
            with self.subTest(reasons=reasons):
                with self.assertRaises(ValueError):
                    FastReviewRecommendation(PATH_HUMAN_REVIEW, False, reasons)

    def test_fields_have_strict_types(self):
        reasons = (REASON_INSUFFICIENT_EVIDENCE,)
        with self.assertRaises(ValueError):
            FastReviewRecommendation(None, False, reasons)
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, "no", reasons)
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, 0, reasons)
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, False, reasons,
                                     read_only_checks=[])
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, False, reasons,
                                     automatic_dispatch=1)

    def test_checks_must_be_known_unique_and_canonically_ordered(self):
        path, reasons = PATH_READ_ONLY_CHECKS, (REASON_REVIEW_WITH_CHECKS,)
        bad = (
            (MARKER,),
            (self.CHECK_A, self.CHECK_A),
            (self.CHECK_B, self.CHECK_A),  # reversed canonical order
            (self.CHECK_A + " ",),
        )
        for checks in bad:
            with self.subTest(checks=checks):
                with self.assertRaises(ValueError):
                    FastReviewRecommendation(path, False, reasons, checks)

    def test_human_review_cannot_carry_checks(self):
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_HUMAN_REVIEW, False,
                                     (REASON_INSUFFICIENT_EVIDENCE,),
                                     (self.CHECK_A,))

    def test_read_only_path_requires_checks(self):
        with self.assertRaises(ValueError):
            FastReviewRecommendation(PATH_READ_ONLY_CHECKS, False,
                                     (REASON_REVIEW_WITH_CHECKS,), ())


if __name__ == "__main__":
    unittest.main()
