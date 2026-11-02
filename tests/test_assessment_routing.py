import copy
import dataclasses
import unittest
from collections.abc import Mapping

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
             "evidence_ids": [f"a-{i:05d}" for i in range(first)]},
            {"signal": "unusual_outbound", "weight": 20,
             "evidence_ids": [f"b-{i:05d}" for i in range(second)]},
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
                                 (REASON_REVIEW_WITH_CHECKS,
                                  REASON_UNSUPPORTED_PRESENT),
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


class _RaisingMapping(Mapping):
    """Custom Mapping whose behavior is hostile: it raises on access."""

    def __init__(self, backing, fail_on=None, fail_keys=False):
        self._backing = backing
        self._fail_on = fail_on
        self._fail_keys = fail_keys

    def __getitem__(self, key):
        if key == self._fail_on:
            raise RuntimeError("hostile __getitem__")
        return self._backing[key]

    def __iter__(self):
        return iter(self._backing)

    def __len__(self):
        return len(self._backing)

    def keys(self):
        if self._fail_keys:
            raise RuntimeError("hostile keys()")
        return self._backing.keys()


class FailClosedCustomMappingTests(unittest.TestCase):
    """Regression: exceptions from custom Mapping objects fail closed."""

    def setUp(self):
        self.good = copy.deepcopy(_valid(_obs("suspicious_process")))

    def _assert_human_review_invalid_shape(self, rec):
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertFalse(rec.deeper_review_recommended)
        self.assertEqual(rec.read_only_checks, ())
        self.assertEqual(rec.reason_codes, (REASON_INVALID_SHAPE,))

    def test_top_level_mapping_raising_on_keys_fails_closed(self):
        rec = recommend_fast_review(
            _RaisingMapping(self.good, fail_keys=True))
        self._assert_human_review_invalid_shape(rec)

    def test_top_level_mapping_raising_on_getitem_fails_closed(self):
        for key in _EXPECTED_KEYS_FOR_TEST:
            with self.subTest(key=key):
                rec = recommend_fast_review(
                    _RaisingMapping(self.good, fail_on=key))
                self._assert_human_review_invalid_shape(rec)

    def test_hit_mapping_raising_fails_closed(self):
        for key in ("signal", "weight", "evidence_ids"):
            with self.subTest(key=key):
                r = copy.deepcopy(self.good)
                r["rule_hits"][0] = _RaisingMapping(
                    r["rule_hits"][0], fail_on=key)
                self._assert_human_review_invalid_shape(
                    recommend_fast_review(r))
        r = copy.deepcopy(self.good)
        r["rule_hits"][0] = _RaisingMapping(r["rule_hits"][0], fail_keys=True)
        self._assert_human_review_invalid_shape(recommend_fast_review(r))

    def test_non_exception_hostile_values_do_not_escape(self):
        # Inner exceptions surface only as the fixed shape code, never raw.
        r = copy.deepcopy(self.good)
        r["rule_hits"][0] = _RaisingMapping(r["rule_hits"][0], fail_keys=True)
        rec = recommend_fast_review(r)
        self.assertNotIn("hostile", repr(rec))

    def test_custom_mapping_with_valid_content_still_routes(self):
        rec = recommend_fast_review(_RaisingMapping(self.good))
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)
        self.assertEqual(rec.reason_codes, (REASON_REVIEW_WITH_CHECKS,))


_EXPECTED_KEYS_FOR_TEST = (
    "case_id", "rule_version", "status", "priority_index",
    "priority_index_is_probability", "rule_hits", "unsupported_observations",
    "limitations", "next_read_only_checks", "authorized_actions",
)


class EvidenceOrderingTests(unittest.TestCase):
    """Regression: evidence_ids per hit are sorted and unique, as assess() emits."""

    def _with_refs(self, refs):
        r = copy.deepcopy(_valid(_obs("suspicious_process")))
        r["rule_hits"][0]["evidence_ids"] = refs
        return r

    def test_unsorted_evidence_rejected(self):
        rec = recommend_fast_review(self._with_refs(["ev-2", "ev-1"]))
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertEqual(rec.reason_codes, (REASON_INVALID_EVIDENCE,))

    def test_duplicate_evidence_rejected(self):
        rec = recommend_fast_review(self._with_refs(["ev-1", "ev-1"]))
        self.assertEqual(rec.reason_codes, (REASON_INVALID_EVIDENCE,))

    def test_sorted_unique_evidence_accepted(self):
        rec = recommend_fast_review(self._with_refs(["ev-1", "ev-2", "ev-3"]))
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)

    def test_assess_output_is_always_sorted_unique(self):
        r = _valid(_obs("suspicious_process", "ev-9"),
                   _obs("suspicious_process", "ev-1"),
                   _obs("suspicious_process", "ev-9"))
        refs = r["rule_hits"][0]["evidence_ids"]
        self.assertEqual(refs, ["ev-1", "ev-9"])
        self.assertEqual(recommend_fast_review(r).path, PATH_READ_ONLY_CHECKS)


class CombinedEvidenceCapTests(unittest.TestCase):
    """Regression: supported evidence IDs plus unsupported observations <= 10000."""

    def _tampered(self, evidence_count, unsupported):
        r = copy.deepcopy(_valid(_obs("suspicious_process")))
        r["rule_hits"][0]["evidence_ids"] = [
            f"ev-{i:05d}" for i in range(evidence_count)]
        r["unsupported_observations"] = unsupported
        return r

    def test_evidence_plus_unsupported_over_bound_rejected(self):
        rec = recommend_fast_review(self._tampered(9999, 2))  # 10001 total
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertEqual(rec.reason_codes, (REASON_INVALID_COUNT,))

    def test_evidence_plus_unsupported_at_bound_accepted(self):
        rec = recommend_fast_review(self._tampered(9999, 1))  # exactly 10000
        self.assertEqual(rec.path, PATH_READ_ONLY_CHECKS)
        self.assertTrue(rec.deeper_review_recommended)
        self.assertEqual(rec.reason_codes,
                         (REASON_REVIEW_WITH_CHECKS, REASON_UNSUPPORTED_PRESENT))

    def test_unsupported_only_at_bound_still_accepted(self):
        r = copy.deepcopy(_valid())
        r["unsupported_observations"] = 10000
        rec = recommend_fast_review(r)
        self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
        self.assertEqual(rec.reason_codes,
                         (REASON_INSUFFICIENT_EVIDENCE, REASON_UNSUPPORTED_PRESENT))


class LimitationsContractTests(unittest.TestCase):
    """limitations is validated strictly against the upstream constant and never echoed."""

    def base(self):
        return copy.deepcopy(_valid(_obs("suspicious_process")))

    def test_routing_constant_matches_live_assess_output(self):
        from azazel_mio import assessment_routing as routing
        self.assertEqual(list(routing._UPSTREAM_LIMITATIONS),
                         _valid()["limitations"])

    def test_tampered_limitations_fail_closed(self):
        bad_values = (
            [],
            ["Advisory priority only; not a verdict of maliciousness."],
            list(_valid()["limitations"]) + ["extra"],
            list(reversed(_valid()["limitations"])),
            tuple(_valid()["limitations"]),
            MARKER,
            None,
            [MARKER, MARKER, MARKER],
        )
        for bad in bad_values:
            with self.subTest(bad=repr(bad)[:40]):
                r = self.base()
                r["limitations"] = bad
                rec = recommend_fast_review(r)
                self.assertEqual(rec.path, PATH_HUMAN_REVIEW)
                self.assertEqual(rec.reason_codes, (REASON_INVALID_SHAPE,))
                self.assertNotIn(MARKER, repr(rec))

    def test_limitations_text_never_echoed_into_recommendation(self):
        rec = recommend_fast_review(self.base())
        for text in _valid()["limitations"]:
            self.assertNotIn(text, repr(rec))


class RouteCombinationConstructorTests(unittest.TestCase):
    """Regression: reason codes, path and deeper-review flag must match a valid route."""

    CHECK = READ_ONLY_CHECKS["suspicious_process"]

    def assertRejected(self, path, deeper, reasons, checks=()):
        with self.subTest(path=path, deeper=deeper, reasons=reasons):
            with self.assertRaises(ValueError):
                FastReviewRecommendation(path, deeper, reasons, checks)

    def test_deeper_flag_must_match_unsupported_reason(self):
        self.assertRejected(PATH_HUMAN_REVIEW, True, (REASON_INSUFFICIENT_EVIDENCE,))
        self.assertRejected(PATH_HUMAN_REVIEW, False,
                            (REASON_INSUFFICIENT_EVIDENCE, REASON_UNSUPPORTED_PRESENT))
        self.assertRejected(PATH_READ_ONLY_CHECKS, True,
                            (REASON_REVIEW_WITH_CHECKS,), (self.CHECK,))
        self.assertRejected(PATH_READ_ONLY_CHECKS, False,
                            (REASON_REVIEW_WITH_CHECKS, REASON_UNSUPPORTED_PRESENT),
                            (self.CHECK,))

    def test_primary_reason_must_match_path(self):
        self.assertRejected(PATH_HUMAN_REVIEW, False, (REASON_REVIEW_WITH_CHECKS,))
        self.assertRejected(PATH_READ_ONLY_CHECKS, False,
                            (REASON_INSUFFICIENT_EVIDENCE,), (self.CHECK,))

    def test_reason_order_is_fixed(self):
        self.assertRejected(PATH_HUMAN_REVIEW, True,
                            (REASON_UNSUPPORTED_PRESENT, REASON_INSUFFICIENT_EVIDENCE))
        self.assertRejected(PATH_READ_ONLY_CHECKS, True,
                            (REASON_UNSUPPORTED_PRESENT, REASON_REVIEW_WITH_CHECKS),
                            (self.CHECK,))

    def test_fail_closed_codes_only_on_single_reason_human_review(self):
        self.assertRejected(PATH_READ_ONLY_CHECKS, False, (REASON_INVALID_SHAPE,),
                            (self.CHECK,))
        self.assertRejected(PATH_HUMAN_REVIEW, True, (REASON_INVALID_COUNT,))
        self.assertRejected(PATH_HUMAN_REVIEW, False,
                            (REASON_INVALID_CHECKS, REASON_INVALID_EVIDENCE))
        self.assertRejected(PATH_HUMAN_REVIEW, False,
                            (REASON_INSUFFICIENT_EVIDENCE, REASON_INVALID_SHAPE))

    def test_valid_routes_still_construct(self):
        FastReviewRecommendation(PATH_HUMAN_REVIEW, True,
                                 (REASON_INSUFFICIENT_EVIDENCE, REASON_UNSUPPORTED_PRESENT))
        FastReviewRecommendation(PATH_HUMAN_REVIEW, False, (REASON_INVALID_EVIDENCE,))
        FastReviewRecommendation(PATH_READ_ONLY_CHECKS, False,
                                 (REASON_REVIEW_WITH_CHECKS,), (self.CHECK,))


if __name__ == "__main__":
    unittest.main()
