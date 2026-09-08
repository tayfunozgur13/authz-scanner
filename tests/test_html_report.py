from datetime import UTC, datetime

from scanner.core.evidence import HttpEvidence
from scanner.core.finding import Finding, Severity, VulnerabilityClass
from scanner.core.identity import AuthenticatedIdentity
from scanner.core.result import HttpRequestResult
from scanner.main import ScannerRunResult
from scanner.reporting.html_report import build_html_report, escape_html, write_html_report


def build_result(findings: list[Finding] | None = None) -> ScannerRunResult:
    return ScannerRunResult(
        target_name="External API",
        base_url="http://testserver",
        identities={
            "regular": AuthenticatedIdentity(
                name="regular",
                email="regular@example.test",
                role="user",
                access_token="secret-token",
            )
        },
        health_status_code=200,
        openapi_status_code=200,
        openapi_title="External API",
        findings=findings or [],
    )


def build_finding() -> Finding:
    return Finding(
        title="BOLA: same_role_users_cannot_read_each_others_resources",
        vulnerability_class=VulnerabilityClass.BOLA,
        severity=Severity.HIGH,
        endpoint="/resources/{id}",
        method="GET",
        identity_name="regular",
        description="A regular user accessed another user's resource.",
        business_impact="Another customer's data may be exposed.",
        recommendation="Check resource ownership before returning the resource.",
        evidence=[
            HttpEvidence(
                observed=HttpRequestResult(
                    identity_name="regular",
                    method="GET",
                    path="/resources/1",
                    status_code=200,
                    request_json={"password": "secret-password"},
                    response_json={
                        "id": "1",
                        "owner_id": "other-subject",
                        "password_hash": "secret-hash",
                    },
                ),
                expected_status_code=403,
                description="Cross-user resource read succeeded.",
            )
        ],
    )


def test_escape_html_escapes_markup_and_quotes() -> None:
    assert escape_html('<script type="text/javascript">') == (
        "&lt;script type=&quot;text/javascript&quot;&gt;"
    )


def test_build_html_report_includes_summary_findings_and_redacted_evidence() -> None:
    report = build_html_report(
        build_result([build_finding()]),
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert "<!doctype html>" in report
    assert "<title>AuthZ Scanner Report - External API</title>" in report
    assert "<strong>External API</strong>" in report
    assert "<strong>1</strong>" in report
    assert "<dt>Risk Score</dt><dd>80</dd>" in report
    assert "BOLA: same_role_users_cannot_read_each_others_resources" in report
    assert "API1: Broken Object Level Authorization" in report
    assert "Business Impact" in report
    assert "Another customer&#x27;s data may be exposed." in report
    assert "GET /resources/1" in report
    assert "Appendix 1.1" in report
    assert "&quot;password&quot;: &quot;[REDACTED]&quot;" in report
    assert "&quot;password_hash&quot;: &quot;[REDACTED]&quot;" in report
    assert "secret-password" not in report
    assert "secret-hash" not in report
    assert "secret-token" not in report


def test_build_html_report_handles_zero_findings() -> None:
    report = build_html_report(
        build_result(),
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert "<strong>0</strong>" in report
    assert "No findings were identified." in report


def test_write_html_report_creates_report_file(tmp_path) -> None:
    report_path = write_html_report(
        build_result([build_finding()]),
        output_dir=tmp_path,
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert report_path.name == "authz-scan-external-api-20260902T120000Z.html"
    assert report_path.read_text().startswith("<!doctype html>")
