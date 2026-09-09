import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.reporting.curl import build_curl_command


SENSITIVE_REPORT_FIELDS = {
    "access_token",
    "api_key",
    "card_number",
    "credit_card",
    "cvv",
    "hashed_password",
    "mfa_secret",
    "national_id",
    "otp_secret",
    "password",
    "password_hash",
    "private_key",
    "refresh_token",
    "reset_token",
    "secret",
    "ssn",
    "token",
}


def sanitize_filename_part(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower())
    return normalized.strip("-") or "target"


def redact_sensitive_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key in SENSITIVE_REPORT_FIELDS else redact_sensitive_values(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_values(item) for item in value]
    return value


def build_json_report(result: Any, generated_at: datetime | None = None) -> dict[str, Any]:
    timestamp = generated_at or datetime.now(UTC)
    return {
        "schema_version": "1.0",
        "generated_at": timestamp.isoformat(),
        "target": {
            "name": result.target_name,
            "base_url": result.base_url,
        },
        "checks": {
            "health": {
                "ok": result.health_ok,
                "status_code": result.health_status_code,
            },
            "openapi": {
                "ok": result.openapi_ok,
                "status_code": result.openapi_status_code,
                "title": result.openapi_title,
            },
        },
        "identities": [
            {
                "name": identity.name,
                "email": identity.email,
                "role": identity.role,
            }
            for identity in result.identities.values()
        ],
        "summary": {
            "finding_count": result.finding_count,
            "skipped_test_count": len(result.skipped_tests),
            "max_risk_score": max((finding.risk_score for finding in result.findings), default=0),
        },
        "skipped_tests": [
            {
                "module": skipped_test.module,
                "name": skipped_test.name,
                "reason": skipped_test.reason,
                "destructive": skipped_test.destructive,
                "reset_recommended": skipped_test.reset_recommended,
            }
            for skipped_test in result.skipped_tests
        ],
        "findings": [
            {
                "title": finding.title,
                "class": finding.vulnerability_class.value,
                "severity": finding.severity.value,
                "risk_score": finding.risk_score,
                "destructive": finding.destructive,
                "reset_recommended": finding.reset_recommended,
                "endpoint": finding.endpoint,
                "method": finding.method,
                "identity_name": finding.identity_name,
                "description": finding.description,
                "business_impact": finding.business_impact,
                "recommendation": finding.recommendation,
                "evidence": [
                    {
                        "description": evidence.description,
                        "expected_status_code": evidence.expected_status_code,
                        "curl": build_curl_command(result, evidence),
                        "observed": {
                            "identity_name": evidence.observed.identity_name,
                            "method": evidence.observed.method,
                            "path": evidence.observed.path,
                            "status_code": evidence.observed.status_code,
                            "request_json": redact_sensitive_values(evidence.observed.request_json),
                            "response_json": redact_sensitive_values(evidence.observed.response_json),
                            "response_text": evidence.observed.response_text,
                        },
                    }
                    for evidence in finding.evidence
                ],
            }
            for finding in result.findings
        ],
    }


def write_json_report(
    result: Any,
    output_dir: str | Path = "reports",
    generated_at: datetime | None = None,
) -> Path:
    timestamp = generated_at or datetime.now(UTC)
    report = build_json_report(result, generated_at=timestamp)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    filename_target = sanitize_filename_part(result.target_name)
    filename_timestamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
    report_path = output_path / f"authz-scan-{filename_target}-{filename_timestamp}.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report_path
