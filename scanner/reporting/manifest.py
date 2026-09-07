import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def infer_report_format(report_path: Path) -> str:
    if report_path.suffix == ".json":
        return "json"
    if report_path.suffix == ".md":
        return "markdown"
    return report_path.suffix.lstrip(".") or "unknown"


def build_report_record(
    result: Any,
    report_path: Path,
    output_dir: Path,
    generated_at: datetime,
) -> dict[str, Any]:
    return {
        "target_name": result.target_name,
        "base_url": result.base_url,
        "format": infer_report_format(report_path),
        "path": report_path.relative_to(output_dir).as_posix(),
        "generated_at": generated_at.isoformat(),
        "finding_count": result.finding_count,
    }


def update_latest_report(report_path: Path, output_dir: Path) -> Path | None:
    report_format = infer_report_format(report_path)
    latest_names = {
        "json": "latest.json",
        "markdown": "latest.md",
        "html": "latest.html",
    }
    latest_name = latest_names.get(report_format)
    if latest_name is None:
        return None

    latest_path = output_dir / latest_name
    shutil.copyfile(report_path, latest_path)
    return latest_path


def update_report_manifest(
    result: Any,
    report_paths: list[Path],
    output_dir: str | Path,
    generated_at: datetime | None = None,
) -> Path:
    timestamp = generated_at or datetime.now(UTC)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    manifest_path = output_path / "manifest.json"

    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
    else:
        manifest = {
            "schema_version": "1.0",
            "reports": [],
            "latest": {},
        }

    manifest["updated_at"] = timestamp.isoformat()
    manifest.setdefault("reports", [])
    manifest.setdefault("latest", {})

    for report_path in report_paths:
        latest_path = update_latest_report(report_path, output_path)
        record = build_report_record(
            result=result,
            report_path=report_path,
            output_dir=output_path,
            generated_at=timestamp,
        )
        manifest["reports"].append(record)
        if latest_path is not None:
            manifest["latest"][record["format"]] = latest_path.relative_to(output_path).as_posix()

    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest_path
