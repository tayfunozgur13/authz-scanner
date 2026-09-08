from datetime import UTC, datetime

from scanner.core.evidence import HttpEvidence
from scanner.core.destructive import SkippedTest
from scanner.core.finding import Finding, Severity, VulnerabilityClass
from scanner.core.identity import AuthenticatedIdentity
from scanner.core.result import HttpRequestResult
from scanner.main import ScannerRunResult
from scanner.reporting.markdown_report import (
    build_markdown_report,
    build_reproduction_steps,
    count_findings_by_class,
    escape_table_cell,
    get_impact_statement,
    get_owasp_api_category,
    write_markdown_report,
)


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
        skipped_tests=[
            SkippedTest(
                module="bfla",
                name="refund_order",
                reason="destructive test skipped by default",
                destructive=True,
                reset_recommended=True,
            )
        ],
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


def build_bfla_finding() -> Finding:
    return Finding(
        title="BFLA: regular_users_cannot_open_admin_panel",
        vulnerability_class=VulnerabilityClass.BFLA,
        severity=Severity.HIGH,
        endpoint="/admin/users",
        method="GET",
        identity_name="regular",
        description="A regular user accessed an admin function.",
        business_impact="Administrative user data may be exposed.",
        recommendation="Require admin role before executing privileged functions.",
        evidence=[
            HttpEvidence(
                observed=HttpRequestResult(
                    identity_name="regular",
                    method="GET",
                    path="/admin/users",
                    status_code=200,
                    response_json=[],
                ),
                expected_status_code=403,
                description="Admin user listing succeeded.",
            )
        ],
    )


def test_escape_table_cell_keeps_markdown_tables_valid() -> None:
    assert escape_table_cell("a|b\nc") == "a\\|b c"


def test_count_findings_by_class_groups_findings_for_summary() -> None:
    result = build_result([build_finding(), build_bfla_finding()])

    assert count_findings_by_class(result) == {
        "BOLA": 1,
        "BFLA": 1,
    }


def test_get_owasp_api_category_maps_known_authorization_classes() -> None:
    assert get_owasp_api_category("BOLA") == "API1: Broken Object Level Authorization"
    assert get_owasp_api_category("BFLA") == "API5: Broken Function Level Authorization"
    assert get_owasp_api_category("Mass Assignment") == (
        "API3: Broken Object Property Level Authorization"
    )
    assert get_owasp_api_category("Unknown") == "Unmapped"


def test_get_impact_statement_returns_pentest_style_impact() -> None:
    assert "another user" in get_impact_statement("BOLA")
    assert "server-controlled properties" in get_impact_statement("Mass Assignment")


def test_build_reproduction_steps_summarizes_observed_request() -> None:
    steps = build_reproduction_steps(build_finding())

    assert steps == [
        "Authenticate as `regular`.",
        "Send `GET /resources/1`.",
        "Compare the observed status `200` with the expected status `403`.",
        "Review the linked appendix entry for the sanitized request and response bodies.",
    ]


def test_build_markdown_report_includes_summary_findings_and_evidence() -> None:
    report = build_markdown_report(
        build_result([build_finding()]),
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert "# AuthZ Scanner Report" in report
    assert "- Target: `External API`" in report
    assert "- Total Findings: `1`" in report
    assert "- Skipped Tests: `1`" in report
    assert "## Skipped Tests" in report
    assert "| bfla | refund_order | destructive test skipped by default | yes |" in report
    assert "### Findings by Class" in report
    assert "| BOLA | 1 |" in report
    assert "### Findings Table" in report
    assert "| 1 | high | 80 | BOLA | GET | `/resources/{id}` | regular |" in report
    assert "### 1. BOLA: same_role_users_cannot_read_each_others_resources" in report
    assert "- OWASP API Category: `API1: Broken Object Level Authorization`" in report
    assert "- Destructive Test: `no`" in report
    assert "#### Overview" in report
    assert "#### Impact" in report
    assert "An attacker may access or modify resources owned by another user" in report
    assert "#### Business Impact" in report
    assert "Another customer's data may be exposed." in report
    assert "#### Affected Endpoint" in report
    assert "#### Steps to Reproduce" in report
    assert "1. Authenticate as `regular`." in report
    assert "2. Send `GET /resources/1`." in report
    assert "- Expected Status: `403`" in report
    assert "- Observed Status: `200`" in report
    assert "- Full Evidence: `Appendix 1.1`" in report
    assert "#### Remediation" in report
    assert "## Evidence Appendix" in report
    assert "### Appendix 1.1" in report
    assert '"owner_id": "other-subject"' in report
    assert '"password": "[REDACTED]"' in report
    assert '"password_hash": "[REDACTED]"' in report
    assert "secret-password" not in report
    assert "secret-hash" not in report
    assert "Check resource ownership before returning the resource." in report
    assert "secret-token" not in report


def test_build_markdown_report_handles_zero_findings() -> None:
    report = build_markdown_report(
        build_result(),
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert "- Total Findings: `0`" in report
    assert "No findings were identified." in report


def test_write_markdown_report_creates_report_file(tmp_path) -> None:
    report_path = write_markdown_report(
        build_result([build_finding()]),
        output_dir=tmp_path,
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert report_path.name == "authz-scan-external-api-20260902T120000Z.md"
    assert report_path.read_text().startswith("# AuthZ Scanner Report")
