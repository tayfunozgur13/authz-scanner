from scanner.core.evidence import HttpEvidence
from scanner.core.finding import Finding, Severity, VulnerabilityClass
from scanner.core.result import HttpRequestResult


def build_result(status_code: int = 200) -> HttpRequestResult:
    return HttpRequestResult(
        identity_name="attacker",
        method="GET",
        path="/resources/resource-1",
        status_code=status_code,
        response_json={"id": "resource-1"},
    )


def test_http_evidence_detects_status_mismatch() -> None:
    evidence = HttpEvidence(
        observed=build_result(status_code=200),
        expected_status_code=403,
        description="Attacker accessed another user's resource.",
    )

    assert evidence.status_mismatch is True


def test_http_evidence_allows_matching_status() -> None:
    evidence = HttpEvidence(
        observed=build_result(status_code=403),
        expected_status_code=403,
        description="Access was blocked as expected.",
    )

    assert evidence.status_mismatch is False


def test_finding_groups_vulnerability_metadata_and_evidence() -> None:
    evidence = HttpEvidence(
        observed=build_result(status_code=200),
        expected_status_code=403,
        description="Cross-user object access returned success.",
    )

    finding = Finding(
        title="Cross-user object access allowed",
        vulnerability_class=VulnerabilityClass.BOLA,
        severity=Severity.HIGH,
        endpoint="/resources/{id}",
        method="GET",
        identity_name="attacker",
        description="A regular user can read a resource owned by another user.",
        business_impact="Another user's business data may be exposed.",
        recommendation="Verify resource ownership before returning the object.",
        evidence=[evidence],
    )

    assert finding.vulnerability_class == VulnerabilityClass.BOLA
    assert finding.severity == Severity.HIGH
    assert finding.business_impact == "Another user's business data may be exposed."
    assert finding.evidence_count == 1
    assert finding.evidence[0].observed.path == "/resources/resource-1"
