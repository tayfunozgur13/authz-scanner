import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.reporting.json_report import write_json_report
from scanner.reporting.html_report import write_html_report
from scanner.reporting.manifest import (
    build_report_record,
    infer_report_format,
    update_report_manifest,
)
from scanner.reporting.markdown_report import write_markdown_report
from tests.test_json_report import build_result


def test_infer_report_format_from_file_suffix() -> None:
    assert infer_report_format(Path("report.json")) == "json"
    assert infer_report_format(Path("report.md")) == "markdown"
    assert infer_report_format(Path("report.html")) == "html"
    assert infer_report_format(Path("report.txt")) == "txt"


def test_build_report_record_uses_relative_report_path(tmp_path) -> None:
    report_path = tmp_path / "authz-scan-target.json"
    report_path.write_text("{}")

    record = build_report_record(
        result=build_result(),
        report_path=report_path,
        output_dir=tmp_path,
        generated_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
    )

    assert record == {
        "target_name": "External API",
        "base_url": "http://testserver",
        "format": "json",
        "path": "authz-scan-target.json",
        "generated_at": "2026-09-04T12:00:00+00:00",
        "finding_count": 1,
    }


def test_update_report_manifest_records_reports_and_updates_latest_files(tmp_path) -> None:
    result = build_result()
    generated_at = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
    json_path = write_json_report(result, output_dir=tmp_path, generated_at=generated_at)
    markdown_path = write_markdown_report(result, output_dir=tmp_path, generated_at=generated_at)
    html_path = write_html_report(result, output_dir=tmp_path, generated_at=generated_at)

    manifest_path = update_report_manifest(
        result=result,
        report_paths=[json_path, markdown_path, html_path],
        output_dir=tmp_path,
        generated_at=generated_at,
    )

    manifest = json.loads(manifest_path.read_text())
    assert manifest["updated_at"] == "2026-09-04T12:00:00+00:00"
    assert manifest["latest"] == {
        "json": "latest.json",
        "markdown": "latest.md",
        "html": "latest.html",
    }
    assert len(manifest["reports"]) == 3
    assert (tmp_path / "latest.json").read_text() == json_path.read_text()
    assert (tmp_path / "latest.md").read_text() == markdown_path.read_text()
    assert (tmp_path / "latest.html").read_text() == html_path.read_text()
