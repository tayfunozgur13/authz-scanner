import json
from datetime import UTC, datetime

from scanner.core.evidence import HttpEvidence
from scanner.core.finding import Finding, Severity, VulnerabilityClass
from scanner.core.identity import AuthenticatedIdentity
from scanner.core.result import HttpRequestResult
from scanner.main import ScannerRunResult
from scanner.reporting.json_report import (
    build_json_report,
    redact_sensitive_values,
    sanitize_filename_part,
    write_json_report,
)


def build_result() -> ScannerRunResult:
    observed = HttpRequestResult(
        identity_name="regular",
        method="GET",
        path="/resources/1",
        status_code=200,
        request_json={"password": "secret-password"},
        response_json={"id": "1", "owner_id": "other-subject", "password_hash": "secret-hash"},
    )
    finding = Finding(
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
                observed=observed,
                expected_status_code=403,
                description="Cross-user resource read succeeded.",
            )
        ],
    )

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
        findings=[finding],
    )


def test_sanitize_filename_part_keeps_report_filenames_simple() -> None:
    assert sanitize_filename_part("External API!") == "external-api"
    assert sanitize_filename_part("   ") == "target"


def test_redact_sensitive_values_redacts_nested_report_data() -> None:
    redacted = redact_sensitive_values(
        {
            "password": "secret-password",
            "profile": {
                "api_key": "secret-api-key",
                "sessions": [{"refresh_token": "secret-refresh-token"}],
            },
            "email": "regular@example.test",
        }
    )

    assert redacted == {
        "password": "[REDACTED]",
        "profile": {
            "api_key": "[REDACTED]",
            "sessions": [{"refresh_token": "[REDACTED]"}],
        },
        "email": "regular@example.test",
    }


def test_build_json_report_serializes_scan_result_without_tokens() -> None:
    report = build_json_report(
        build_result(),
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert report["schema_version"] == "1.0"
    assert report["generated_at"] == "2026-09-02T12:00:00+00:00"
    assert report["target"] == {
        "name": "External API",
        "base_url": "http://testserver",
    }
    assert report["checks"]["health"] == {
        "ok": True,
        "status_code": 200,
    }
    assert report["identities"] == [
        {
            "name": "regular",
            "email": "regular@example.test",
            "role": "user",
        }
    ]
    assert "access_token" not in json.dumps(report)
    assert report["summary"]["finding_count"] == 1
    assert report["summary"]["max_risk_score"] == 80
    assert report["findings"][0]["class"] == "BOLA"
    assert report["findings"][0]["risk_score"] == 80
    assert report["findings"][0]["business_impact"] == "Another customer's data may be exposed."
    assert report["findings"][0]["evidence"][0]["expected_status_code"] == 403
    assert report["findings"][0]["evidence"][0]["observed"]["request_json"] == {
        "password": "[REDACTED]"
    }
    assert report["findings"][0]["evidence"][0]["observed"]["status_code"] == 200
    assert report["findings"][0]["evidence"][0]["observed"]["response_json"]["password_hash"] == (
        "[REDACTED]"
    )


def test_write_json_report_creates_report_file(tmp_path) -> None:
    report_path = write_json_report(
        build_result(),
        output_dir=tmp_path,
        generated_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
    )

    assert report_path.name == "authz-scan-external-api-20260902T120000Z.json"
    written_report = json.loads(report_path.read_text())
    assert written_report["summary"]["finding_count"] == 1
