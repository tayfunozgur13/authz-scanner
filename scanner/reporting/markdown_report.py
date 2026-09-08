import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.reporting.json_report import redact_sensitive_values, sanitize_filename_part


def escape_table_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def format_check(ok: bool) -> str:
    return "OK" if ok else "FAILED"


def format_json_block(value: Any) -> str:
    if value is None:
        return "`null`"
    return "```json\n" + json.dumps(value, indent=2) + "\n```"


def count_findings_by_class(result: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in result.findings:
        class_name = finding.vulnerability_class.value
        counts[class_name] = counts.get(class_name, 0) + 1
    return counts


def count_findings_by_severity(result: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in result.findings:
        severity = finding.severity.value
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def get_owasp_api_category(vulnerability_class: str) -> str:
    categories = {
        "BOLA": "API1: Broken Object Level Authorization",
        "BFLA": "API5: Broken Function Level Authorization",
        "Excessive Data Exposure": "API3: Broken Object Property Level Authorization",
        "Mass Assignment": "API3: Broken Object Property Level Authorization",
        "Privilege Escalation": "API5: Broken Function Level Authorization",
    }
    return categories.get(vulnerability_class, "Unmapped")


def get_impact_statement(vulnerability_class: str) -> str:
    impacts = {
        "BOLA": (
            "An attacker may access or modify resources owned by another user by changing "
            "object identifiers in the request."
        ),
        "BFLA": (
            "A low-privilege user may execute functionality that should be restricted to "
            "a privileged role."
        ),
        "Excessive Data Exposure": (
            "The API may disclose sensitive object properties that clients do not need and "
            "should not receive."
        ),
        "Mass Assignment": (
            "A client may set server-controlled properties by adding unexpected fields to "
            "the request body."
        ),
        "Privilege Escalation": (
            "A low-privilege user may alter privilege-related properties and gain elevated "
            "access."
        ),
    }
    return impacts.get(vulnerability_class, "The behavior may weaken authorization guarantees.")


def build_reproduction_steps(finding: Any) -> list[str]:
    if not finding.evidence:
        return ["Review the affected endpoint and reproduce the scanner request manually."]

    evidence = finding.evidence[0]
    observed = evidence.observed
    return [
        f"Authenticate as `{finding.identity_name}`.",
        f"Send `{observed.method} {observed.path}`.",
        f"Compare the observed status `{observed.status_code}` with the expected status `{evidence.expected_status_code}`.",
        "Review the linked appendix entry for the sanitized request and response bodies.",
    ]


def build_markdown_report(result: Any, generated_at: datetime | None = None) -> str:
    timestamp = generated_at or datetime.now(UTC)
    lines: list[str] = [
        "# AuthZ Scanner Report",
        "",
        "## Executive Summary",
        "",
        f"- Target: `{result.target_name}`",
        f"- Base URL: `{result.base_url}`",
        f"- Generated At: `{timestamp.isoformat()}`",
        f"- Total Findings: `{result.finding_count}`",
        f"- Highest Risk Score: `{max((finding.risk_score for finding in result.findings), default=0)}`",
        "",
        "## Scan Metadata",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
        f"| Health | {format_check(result.health_ok)} | `{result.health_status_code}` |",
        (
            f"| OpenAPI | {format_check(result.openapi_ok)} | "
            f"`{escape_table_cell(result.openapi_title or result.openapi_status_code)}` |"
        ),
        "",
        "## Tested Identities",
        "",
        "| Name | Email | Role |",
        "|---|---|---|",
    ]

    for identity in result.identities.values():
        lines.append(
            "| "
            f"{escape_table_cell(identity.name)} | "
            f"{escape_table_cell(identity.email)} | "
            f"{escape_table_cell(identity.role)} |"
        )

    lines.extend(
        [
            "",
            "## Findings Summary",
            "",
        ]
    )

    if not result.findings:
        lines.extend(["No findings were identified.", ""])
        return "\n".join(lines).rstrip() + "\n"

    lines.extend(
        [
            "### Findings by Class",
            "",
            "| Class | Count |",
            "|---|---|",
        ]
    )
    for class_name, count in count_findings_by_class(result).items():
        lines.append(f"| {escape_table_cell(class_name)} | {count} |")

    lines.extend(
        [
            "",
            "### Findings by Severity",
            "",
            "| Severity | Count |",
            "|---|---|",
        ]
    )
    for severity, count in count_findings_by_severity(result).items():
        lines.append(f"| {escape_table_cell(severity)} | {count} |")

    lines.extend(["", "### Findings Table", ""])
    lines.extend(
        [
            "| # | Severity | Risk Score | Class | Method | Endpoint | Identity |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for index, finding in enumerate(result.findings, start=1):
        lines.append(
            "| "
            f"{index} | "
            f"{escape_table_cell(finding.severity.value)} | "
            f"{finding.risk_score} | "
            f"{escape_table_cell(finding.vulnerability_class.value)} | "
            f"{escape_table_cell(finding.method)} | "
            f"`{escape_table_cell(finding.endpoint)}` | "
            f"{escape_table_cell(finding.identity_name)} |"
        )

    lines.extend(["", "## Detailed Findings", ""])

    for index, finding in enumerate(result.findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- Severity: `{finding.severity.value}`",
                f"- Risk Score: `{finding.risk_score}`",
                f"- Class: `{finding.vulnerability_class.value}`",
                f"- OWASP API Category: `{get_owasp_api_category(finding.vulnerability_class.value)}`",
                f"- Endpoint: `{finding.method} {finding.endpoint}`",
                f"- Identity: `{finding.identity_name}`",
                "",
                "#### Overview",
                "",
                finding.description,
                "",
                "#### Impact",
                "",
                get_impact_statement(finding.vulnerability_class.value),
                "",
                "#### Business Impact",
                "",
                finding.business_impact,
                "",
                "#### Affected Endpoint",
                "",
                f"`{finding.method} {finding.endpoint}`",
                "",
                "#### Steps to Reproduce",
                "",
            ]
        )

        for step_index, step in enumerate(build_reproduction_steps(finding), start=1):
            lines.append(f"{step_index}. {step}")

        lines.extend(
            [
                "",
                "#### Evidence",
                "",
            ]
        )

        for evidence_index, evidence in enumerate(finding.evidence, start=1):
            observed = evidence.observed
            lines.extend(
                [
                    f"Evidence {evidence_index}: {evidence.description}",
                    "",
                    f"- Expected Status: `{evidence.expected_status_code}`",
                    f"- Observed Status: `{observed.status_code}`",
                    f"- Observed Request: `{observed.method} {observed.path}`",
                    f"- Full Evidence: `Appendix {index}.{evidence_index}`",
                    "",
                ]
            )

        lines.extend(
            [
                "#### Remediation",
                "",
                finding.recommendation,
                "",
            ]
        )

    lines.extend(["## Evidence Appendix", ""])

    for finding_index, finding in enumerate(result.findings, start=1):
        for evidence_index, evidence in enumerate(finding.evidence, start=1):
            observed = evidence.observed
            lines.extend(
                [
                    f"### Appendix {finding_index}.{evidence_index}",
                    "",
                    f"- Finding: `{finding.title}`",
                    f"- Observed Request: `{observed.method} {observed.path}`",
                    f"- Expected Status: `{evidence.expected_status_code}`",
                    f"- Observed Status: `{observed.status_code}`",
                    "",
                    "Request Body:",
                    "",
                    format_json_block(redact_sensitive_values(observed.request_json)),
                    "",
                    "Response Body:",
                    "",
                    format_json_block(redact_sensitive_values(observed.response_json) or observed.response_text),
                    "",
                ]
            )

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(
    result: Any,
    output_dir: str | Path = "reports",
    generated_at: datetime | None = None,
) -> Path:
    timestamp = generated_at or datetime.now(UTC)
    report = build_markdown_report(result, generated_at=timestamp)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    filename_target = sanitize_filename_part(result.target_name)
    filename_timestamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
    report_path = output_path / f"authz-scan-{filename_target}-{filename_timestamp}.md"
    report_path.write_text(report)
    return report_path
