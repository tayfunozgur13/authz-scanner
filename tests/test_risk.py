from scanner.core.finding import Severity, VulnerabilityClass
from scanner.core.risk import (
    infer_default_severity,
    resolve_risk,
    score_for_severity,
    severity_from_score,
)


def test_score_for_severity_maps_to_stable_numeric_risk() -> None:
    assert score_for_severity(Severity.LOW) == 20
    assert score_for_severity(Severity.MEDIUM) == 50
    assert score_for_severity(Severity.HIGH) == 80
    assert score_for_severity(Severity.CRITICAL) == 95


def test_severity_from_score_uses_report_thresholds() -> None:
    assert severity_from_score(95) == Severity.CRITICAL
    assert severity_from_score(80) == Severity.HIGH
    assert severity_from_score(50) == Severity.MEDIUM
    assert severity_from_score(20) == Severity.LOW


def test_resolve_risk_uses_explicit_severity_override() -> None:
    severity, risk_score = resolve_risk(
        vulnerability_class=VulnerabilityClass.BOLA,
        method="GET",
        endpoint="/orders/{id}",
        severity_override=Severity.MEDIUM,
    )

    assert severity == Severity.MEDIUM
    assert risk_score == 50


def test_resolve_risk_uses_explicit_score_override() -> None:
    severity, risk_score = resolve_risk(
        vulnerability_class=VulnerabilityClass.BFLA,
        method="POST",
        endpoint="/admin/users",
        risk_score_override=1000,
    )

    assert severity == Severity.CRITICAL
    assert risk_score == 100


def test_privilege_escalation_defaults_to_critical() -> None:
    assert (
        infer_default_severity(
            VulnerabilityClass.PRIVILEGE_ESCALATION,
            "PUT",
            "/users/{subject_id}",
        )
        == Severity.CRITICAL
    )


def test_read_only_customer_bola_defaults_to_high() -> None:
    assert (
        infer_default_severity(
            VulnerabilityClass.BOLA,
            "GET",
            "/support/tickets/{id}",
        )
        == Severity.HIGH
    )


def test_mutating_bola_defaults_to_critical() -> None:
    assert (
        infer_default_severity(
            VulnerabilityClass.BOLA,
            "DELETE",
            "/orders/{id}",
        )
        == Severity.CRITICAL
    )
