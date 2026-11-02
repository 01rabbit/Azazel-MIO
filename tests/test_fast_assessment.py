"""Independent golden fixtures for the portable fast-assessment contract."""

import pytest

from azazel_mio.fast_assessment import FastAssessmentInput, PortSignal, assess_fast


@pytest.mark.parametrize(
    ("inputs", "expected_score", "expected_factors"),
    [
        # Expected outputs were run through Edge TacticalScorer.score() from
        # scorer.py at 47c880b2503d7f771bbdacba9b6205dafe03c4c7.
        (
            FastAssessmentInput(severity=9, classes=(), action="unknown"),
            16,
            ("severity=9",),
        ),
        (
            FastAssessmentInput(
                severity=1,
                classes=("c2",),
                token_only=True,
                ports=(PortSignal("admin", 22),),
                action="rejected",
            ),
            39,
            (
                "severity=1",
                "sid_present",
                "threat_class=c2(48)",
                "admin_port=22",
                "action=rejected(contained)",
                "token_only_ceiling",
            ),
        ),
        (
            FastAssessmentInput(
                severity=2,
                classes=("c2", "exfil"),
                ports=(PortSignal("web", 443),),
                action="drop",
            ),
            93,
            (
                "severity=2",
                "sid_present",
                "threat_class=c2(48)",
                "threat_class=exfil(46)",
                "web_port=443",
                "action=drop(contained)",
            ),
        ),
        (
            FastAssessmentInput(severity=2, benign_classless=True),
            25,
            ("severity=2", "benign_dampener"),
        ),
        (
            FastAssessmentInput(
                severity=2,
                classes=("recon",),
                ports=(PortSignal("decoy", 18080),),
                deception_sid=True,
            ),
            75,
            (
                "severity=2",
                "sid_present",
                "threat_class=recon(30)",
                "decoy_port=18080",
            ),
        ),
        # Low-severity, low-weight real deception SID: this is the case that
        # reaches the deception floor from the Edge-equivalent input shape.
        # Hand-derived from TacticalScorer at 47c880b: base 18 (sev 4) + 5 (SID)
        # + 30 (recon) = 53 < 60, so the floor applies. Edge-side feature
        # mapping is from 47c880b; PR #528 head df61bd adds shadow-comparison
        # bookkeeping, not a change to score/factor logic.
        (
            FastAssessmentInput(
                severity=4,
                classes=("recon",),
                deception_sid=True,
            ),
            60,
            (
                "severity=4",
                "sid_present",
                "threat_class=recon(30)",
                "deception_floor",
            ),
        ),
    ],
    ids=(
        "unknown-severity-and-class",
        "token-ceiling-at-39",
        "ordered-multiple-classes-port-action",
        "classless-benign-dampener",
        "deception-above-floor",
        "deception-floor-low-weight-class",
    ),
)
def test_edge_scorer_source_goldens(inputs, expected_score, expected_factors):
    result = assess_fast(inputs)
    assert result.score == expected_score
    assert result.factors == expected_factors


def test_unrecognized_severity_and_class_fall_back_to_low_base():
    result = assess_fast(
        FastAssessmentInput(severity=9, classes=("future-class",), action="unknown")
    )
    assert result.score == 16
    assert result.factors == ("severity=9",)


def test_severity_one_classless_blocked_alert_is_capped_after_action():
    result = assess_fast(FastAssessmentInput(severity=1, action="blocked"))
    assert result.score == 35
    assert result.factors == (
        "severity=1",
        "action=blocked(contained)",
        "sev1_no_threat_cap",
    )


def test_max_class_weight_ports_and_contained_action_keep_factor_order():
    result = assess_fast(
        FastAssessmentInput(
            severity=2,
            classes=("exfil", "c2", "future-class"),
            ports=(PortSignal("web", 443),),
            action="drop",
        )
    )
    assert result.score == 93  # 30 + 5 + max(48, 46) + 8 + 2
    assert result.factors == (
        "severity=2",
        "sid_present",
        "threat_class=c2(48)",
        "threat_class=exfil(46)",
        "web_port=443",
        "action=drop(contained)",
    )


def test_token_only_ceiling_applies_after_port_and_action_bonuses():
    result = assess_fast(
        FastAssessmentInput(
            severity=1,
            classes=("c2",),
            token_only=True,
            ports=(PortSignal("admin", 22),),
            action="rejected",
        )
    )
    assert result.score == 39
    assert result.factors == (
        "severity=1",
        "sid_present",
        "threat_class=c2(48)",
        "admin_port=22",
        "action=rejected(contained)",
        "token_only_ceiling",
    )


def test_deception_floor_wins_over_benign_and_severity_one_cap():
    # The below-floor deception result is raised to exactly 60.
    result = assess_fast(
        FastAssessmentInput(
            severity=1,
            ports=(PortSignal("decoy", 12222),),
            action="blocked",
            deception_sid=True,
            benign_classless=True,
        )
    )
    assert result.score == 60
    assert result.factors == (
        "severity=1",
        "sid_present",
        "decoy_port=12222",
        "action=blocked(contained)",
        "sev1_no_threat_cap",
        "deception_floor",
    )


def test_benign_classless_dampener_is_fixed_at_twenty_five():
    result = assess_fast(
        FastAssessmentInput(severity=2, benign_classless=True)
    )
    assert result.score == 25
    assert result.factors == ("severity=2", "benign_dampener")


def test_classless_unknown_port_and_action_do_not_create_threat():
    result = assess_fast(
        FastAssessmentInput(
            severity=4,
            classes=("unknown",),
            ports=(PortSignal("future-port-kind", 4444),),
            action="allow",
        )
    )
    assert result.score == 18
    assert result.factors == ("severity=4",)


def test_authoritative_class_avoids_token_only_ceiling():
    result = assess_fast(
        FastAssessmentInput(severity=1, classes=("c2",), token_only=False)
    )
    assert result.score == 91  # 38 + 5 + 48
    assert "token_only_ceiling" not in result.factors


def test_token_only_marker_without_a_recognized_class_has_no_effect():
    result = assess_fast(FastAssessmentInput(severity=2, token_only=True))
    assert result.score == 30
    assert result.factors == ("severity=2",)


def test_deception_score_above_floor_does_not_emit_floor_factor():
    # This recognized recon alert scores 75, so the floor must not change it.
    result = assess_fast(
        FastAssessmentInput(
            severity=2,
            classes=("recon",),
            ports=(PortSignal("decoy", 18080),),
            deception_sid=True,
        )
    )
    assert result.score == 75
    assert result.factors == (
        "severity=2",
        "sid_present",
        "threat_class=recon(30)",
        "decoy_port=18080",
    )


def test_known_class_weights_use_max_not_sum():
    result = assess_fast(
        FastAssessmentInput(severity=3, classes=("recon", "scan", "phishing"))
    )
    assert result.score == 71  # 24 + 5 + max(42, 36, 30)


def test_port_priority_is_stable_and_final_score_clamps_to_one_hundred():
    result = assess_fast(
        FastAssessmentInput(
            severity=1,
            classes=("rce",),
            ports=(
                PortSignal("dns", 53),
                PortSignal("web", 443),
                PortSignal("admin", 22),
                PortSignal("decoy", 12222),
            ),
        )
    )
    assert result.score == 100
    assert result.factors == (
        "severity=1",
        "sid_present",
        "threat_class=rce(50)",
        "admin_port=22",
        "decoy_port=12222",
    )


def test_each_canonical_class_weight_has_an_independent_golden():
    expected = {
        "rce": (50, 79),
        "c2": (48, 77),
        "exfil": (46, 75),
        "cred": (44, 73),
        "phishing": (42, 71),
        "mitm": (40, 69),
        "scan": (36, 65),
        "recon": (30, 59),
    }
    for name, (weight, score) in expected.items():
        result = assess_fast(FastAssessmentInput(severity=3, classes=(name,)))
        assert result.score == score, f"unexpected score for {name}"
        assert result.factors == (
            "severity=3",
            "sid_present",
            f"threat_class={name}({weight})",
        ), f"unexpected factors for {name}"


def test_duplicate_class_signals_are_counted_once():
    result = assess_fast(FastAssessmentInput(severity=2, classes=("c2", "c2", "c2")))
    assert result.score == 83
    assert result.factors == (
        "severity=2",
        "sid_present",
        "threat_class=c2(48)",
    )


def test_dns_port_has_its_own_factor_and_bonus():
    result = assess_fast(
        FastAssessmentInput(
            severity=2,
            classes=("c2",),
            ports=(PortSignal("dns", 53),),
        )
    )
    assert result.score == 91
    assert result.factors == (
        "severity=2",
        "sid_present",
        "threat_class=c2(48)",
        "dns_port=53",
    )


def test_known_port_does_not_create_a_classless_threat():
    result = assess_fast(
        FastAssessmentInput(severity=2, ports=(PortSignal("admin", 22),))
    )
    assert result.score == 30
    assert result.factors == ("severity=2",)
