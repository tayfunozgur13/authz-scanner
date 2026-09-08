import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.reporting.json_report import redact_sensitive_values, sanitize_filename_part
from scanner.reporting.markdown_report import (
    build_reproduction_steps,
    count_findings_by_class,
    count_findings_by_severity,
    get_impact_statement,
    get_owasp_api_category,
)


def escape_html(value: object) -> str:
    return html.escape(str(value), quote=True)


def format_check(ok: bool) -> str:
    return "OK" if ok else "FAILED"


def format_json_html(value: Any) -> str:
    redacted = redact_sensitive_values(value)
    if redacted is None:
        rendered = "null"
    else:
        rendered = json.dumps(redacted, indent=2)
    return f"<pre><code>{escape_html(rendered)}</code></pre>"


def build_html_report(result: Any, generated_at: datetime | None = None) -> str:
    timestamp = generated_at or datetime.now(UTC)
    class_counts = count_findings_by_class(result)
    severity_counts = count_findings_by_severity(result)
    max_risk_score = max((finding.risk_score for finding in result.findings), default=0)
    skipped_rows = "\n".join(
        "<tr>"
        f"<td>{escape_html(skipped_test.module)}</td>"
        f"<td>{escape_html(skipped_test.name)}</td>"
        f"<td>{escape_html(skipped_test.reason)}</td>"
        f"<td>{'yes' if skipped_test.reset_recommended else 'no'}</td>"
        "</tr>"
        for skipped_test in result.skipped_tests
    )
    findings_rows = "\n".join(
        "<tr>"
        f"<td>{index}</td>"
        f"<td><span class=\"severity severity-{escape_html(finding.severity.value)}\">{escape_html(finding.severity.value)}</span></td>"
        f"<td>{finding.risk_score}</td>"
        f"<td>{escape_html(finding.vulnerability_class.value)}</td>"
        f"<td>{escape_html(finding.method)}</td>"
        f"<td><code>{escape_html(finding.endpoint)}</code></td>"
        f"<td>{escape_html(finding.identity_name)}</td>"
        "</tr>"
        for index, finding in enumerate(result.findings, start=1)
    )
    class_rows = "\n".join(
        "<tr>"
        f"<td>{escape_html(class_name)}</td>"
        f"<td>{count}</td>"
        "</tr>"
        for class_name, count in class_counts.items()
    )
    severity_rows = "\n".join(
        "<tr>"
        f"<td><span class=\"severity severity-{escape_html(severity)}\">{escape_html(severity)}</span></td>"
        f"<td>{count}</td>"
        "</tr>"
        for severity, count in severity_counts.items()
    )
    identities_rows = "\n".join(
        "<tr>"
        f"<td>{escape_html(identity.name)}</td>"
        f"<td>{escape_html(identity.email)}</td>"
        f"<td>{escape_html(identity.role)}</td>"
        "</tr>"
        for identity in result.identities.values()
    )

    finding_sections = []
    appendix_sections = []
    for finding_index, finding in enumerate(result.findings, start=1):
        steps = "\n".join(
            f"<li>{escape_html(step)}</li>" for step in build_reproduction_steps(finding)
        )
        evidence_items = []
        for evidence_index, evidence in enumerate(finding.evidence, start=1):
            observed = evidence.observed
            evidence_items.append(
                "<li>"
                f"<p>{escape_html(evidence.description)}</p>"
                "<dl>"
                f"<dt>Expected Status</dt><dd>{evidence.expected_status_code}</dd>"
                f"<dt>Observed Status</dt><dd>{observed.status_code}</dd>"
                f"<dt>Observed Request</dt><dd><code>{escape_html(observed.method)} {escape_html(observed.path)}</code></dd>"
                f"<dt>Full Evidence</dt><dd>Appendix {finding_index}.{evidence_index}</dd>"
                "</dl>"
                "</li>"
            )
            response_body = observed.response_json
            if response_body is None:
                response_body = observed.response_text
            appendix_sections.append(
                "<section class=\"appendix-entry\">"
                f"<h3>Appendix {finding_index}.{evidence_index}</h3>"
                f"<p><strong>Finding:</strong> {escape_html(finding.title)}</p>"
                f"<p><strong>Observed Request:</strong> <code>{escape_html(observed.method)} {escape_html(observed.path)}</code></p>"
                f"<p><strong>Expected Status:</strong> {evidence.expected_status_code}</p>"
                f"<p><strong>Observed Status:</strong> {observed.status_code}</p>"
                "<h4>Request Body</h4>"
                f"{format_json_html(observed.request_json)}"
                "<h4>Response Body</h4>"
                f"{format_json_html(response_body)}"
                "</section>"
            )

        finding_sections.append(
            "<section class=\"finding\">"
            f"<h3>{finding_index}. {escape_html(finding.title)}</h3>"
            "<dl class=\"finding-meta\">"
            f"<dt>Severity</dt><dd>{escape_html(finding.severity.value)}</dd>"
            f"<dt>Risk Score</dt><dd>{finding.risk_score}</dd>"
            f"<dt>Destructive Test</dt><dd>{'yes' if finding.destructive else 'no'}</dd>"
            f"<dt>Reset Recommended</dt><dd>{'yes' if finding.reset_recommended else 'no'}</dd>"
            f"<dt>Class</dt><dd>{escape_html(finding.vulnerability_class.value)}</dd>"
            f"<dt>OWASP API Category</dt><dd>{escape_html(get_owasp_api_category(finding.vulnerability_class.value))}</dd>"
            f"<dt>Endpoint</dt><dd><code>{escape_html(finding.method)} {escape_html(finding.endpoint)}</code></dd>"
            f"<dt>Identity</dt><dd>{escape_html(finding.identity_name)}</dd>"
            "</dl>"
            "<h4>Overview</h4>"
            f"<p>{escape_html(finding.description)}</p>"
            "<h4>Impact</h4>"
            f"<p>{escape_html(get_impact_statement(finding.vulnerability_class.value))}</p>"
            "<h4>Business Impact</h4>"
            f"<p>{escape_html(finding.business_impact)}</p>"
            "<h4>Steps to Reproduce</h4>"
            f"<ol>{steps}</ol>"
            "<h4>Evidence</h4>"
            f"<ol class=\"evidence-list\">{''.join(evidence_items)}</ol>"
            "<h4>Remediation</h4>"
            f"<p>{escape_html(finding.recommendation)}</p>"
            "</section>"
        )

    no_findings = ""
    if not result.findings:
        no_findings = "<p class=\"empty-state\">No findings were identified.</p>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AuthZ Scanner Report - {escape_html(result.target_name)}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --ink: #111827;
      --muted: #4b5563;
      --line: #d1d5db;
      --soft-line: #e5e7eb;
      --accent: #2563eb;
      --danger: #dc2626;
      --success: #15803d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.55;
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 0 auto;
      padding: 40px 0 56px;
    }}
    header {{
      background: var(--surface);
      border: 1px solid var(--soft-line);
      padding: 32px;
      margin-bottom: 24px;
    }}
    h1, h2, h3, h4 {{
      line-height: 1.2;
      margin: 0;
    }}
    h1 {{ font-size: 36px; }}
    h2 {{
      font-size: 24px;
      margin-bottom: 16px;
    }}
    h3 {{
      font-size: 20px;
      margin-bottom: 16px;
    }}
    h4 {{
      font-size: 16px;
      margin: 24px 0 8px;
    }}
    p {{ margin: 8px 0 0; }}
    code {{
      background: #eef2ff;
      border-radius: 4px;
      padding: 2px 5px;
      font-size: 0.94em;
    }}
    pre {{
      background: #111827;
      color: #f9fafb;
      overflow-x: auto;
      padding: 16px;
      border-radius: 6px;
      margin: 8px 0 0;
    }}
    pre code {{
      background: transparent;
      color: inherit;
      padding: 0;
    }}
    section {{
      background: var(--surface);
      border: 1px solid var(--soft-line);
      padding: 24px;
      margin-bottom: 20px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      background: var(--surface);
    }}
    th, td {{
      border: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #e5e7eb;
      font-weight: 700;
    }}
    dl {{
      display: grid;
      grid-template-columns: 190px 1fr;
      gap: 8px 16px;
      margin: 16px 0 0;
    }}
    dt {{
      color: var(--muted);
      font-weight: 700;
    }}
    dd {{
      margin: 0;
    }}
    ol {{
      margin: 8px 0 0 20px;
      padding: 0;
    }}
    li {{ margin-bottom: 8px; }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 12px;
      margin-top: 24px;
    }}
    .metric {{
      border: 1px solid var(--soft-line);
      padding: 16px;
      background: #f9fafb;
    }}
    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 13px;
    }}
    .metric strong {{
      display: block;
      font-size: 26px;
      margin-top: 4px;
    }}
	    .severity {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
    }}
	    .severity-high {{
	      background: #fee2e2;
	      color: #991b1b;
	    }}
	    .severity-critical {{
	      background: #7f1d1d;
	      color: #ffffff;
	    }}
	    .severity-medium {{
	      background: #fef3c7;
	      color: #92400e;
	    }}
	    .severity-low {{
	      background: #dcfce7;
	      color: #166534;
	    }}
    .empty-state {{
      color: var(--success);
      font-weight: 700;
    }}
    .finding {{
      border-left: 5px solid var(--danger);
    }}
    .appendix-entry {{
      border-left: 5px solid var(--accent);
    }}
    @media (max-width: 760px) {{
      main {{
        width: calc(100% - 20px);
        padding-top: 20px;
      }}
      header, section {{
        padding: 18px;
      }}
      .summary-grid {{
        grid-template-columns: 1fr;
      }}
      dl {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>AuthZ Scanner Report</h1>
      <p>Target: <strong>{escape_html(result.target_name)}</strong></p>
      <p>Base URL: <code>{escape_html(result.base_url)}</code></p>
      <div class="summary-grid">
	        <div class="metric"><span>Generated At</span><strong>{escape_html(timestamp.isoformat())}</strong></div>
	        <div class="metric"><span>Total Findings</span><strong>{result.finding_count}</strong></div>
	        <div class="metric"><span>Skipped Tests</span><strong>{len(result.skipped_tests)}</strong></div>
	        <div class="metric"><span>Highest Risk</span><strong>{max_risk_score}</strong></div>
	        <div class="metric"><span>OpenAPI</span><strong>{escape_html(format_check(result.openapi_ok))}</strong></div>
      </div>
    </header>

    <section>
      <h2>Scan Metadata</h2>
      <table>
        <thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>
          <tr><td>Health</td><td>{escape_html(format_check(result.health_ok))}</td><td><code>{result.health_status_code}</code></td></tr>
          <tr><td>OpenAPI</td><td>{escape_html(format_check(result.openapi_ok))}</td><td><code>{escape_html(result.openapi_title or result.openapi_status_code)}</code></td></tr>
        </tbody>
      </table>
    </section>

    <section>
      <h2>Tested Identities</h2>
      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th></tr></thead>
        <tbody>{identities_rows}</tbody>
      </table>
    </section>

    <section>
      <h2>Skipped Tests</h2>
      <p>Tests marked destructive are skipped by default unless the scan is run with <code>--include-destructive</code>.</p>
      <table>
        <thead><tr><th>Module</th><th>Name</th><th>Reason</th><th>Reset Recommended</th></tr></thead>
        <tbody>{skipped_rows}</tbody>
      </table>
    </section>

    <section>
      <h2>Findings Summary</h2>
      {no_findings}
	      <table>
	        <thead><tr><th>Class</th><th>Count</th></tr></thead>
	        <tbody>{class_rows}</tbody>
	      </table>
	      <table>
	        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
	        <tbody>{severity_rows}</tbody>
	      </table>
	      <table>
	        <thead><tr><th>#</th><th>Severity</th><th>Risk Score</th><th>Class</th><th>Method</th><th>Endpoint</th><th>Identity</th></tr></thead>
	        <tbody>{findings_rows}</tbody>
	      </table>
    </section>

    <section>
      <h2>Detailed Findings</h2>
      {''.join(finding_sections)}
    </section>

    <section>
      <h2>Evidence Appendix</h2>
      {''.join(appendix_sections)}
    </section>
  </main>
</body>
</html>
"""


def write_html_report(
    result: Any,
    output_dir: str | Path = "reports",
    generated_at: datetime | None = None,
) -> Path:
    timestamp = generated_at or datetime.now(UTC)
    report = build_html_report(result, generated_at=timestamp)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    filename_target = sanitize_filename_part(result.target_name)
    filename_timestamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
    report_path = output_path / f"authz-scan-{filename_target}-{filename_timestamp}.html"
    report_path.write_text(report)
    return report_path
