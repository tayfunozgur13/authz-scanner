import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

from scanner.core.config import ScannerConfig, load_config
from scanner.core.config_doctor import DoctorResult, run_config_doctor
from scanner.core.executor import HttpExecutor
from scanner.core.finding import Finding
from scanner.core.identity import AuthenticatedIdentity, IdentityLoginError, login_all_identities
from scanner.modules.bfla import run_bfla_tests
from scanner.modules.bola import run_bola_tests
from scanner.modules.property_auth import run_property_auth_tests
from scanner.reporting.html_report import write_html_report
from scanner.reporting.json_report import write_json_report
from scanner.reporting.manifest import update_report_manifest
from scanner.reporting.markdown_report import write_markdown_report


class ScannerCliError(RuntimeError):
    pass


class SmokeScanResult(BaseModel):
    target_name: str
    base_url: str
    identities: dict[str, AuthenticatedIdentity]
    health_status_code: int
    openapi_status_code: int
    openapi_title: str | None = None

    @property
    def health_ok(self) -> bool:
        return self.health_status_code == 200

    @property
    def openapi_ok(self) -> bool:
        return self.openapi_status_code == 200


class ScannerRunResult(SmokeScanResult):
    findings: list[Finding]

    @property
    def finding_count(self) -> int:
        return len(self.findings)


def run_scan(config: ScannerConfig) -> ScannerRunResult:
    with httpx.Client(base_url=config.target.base_url, timeout=10.0) as client:
        identities = login_all_identities(client, config)
        executor = HttpExecutor(client, auth_config=config.auth)
        health_response = client.get("/health")
        openapi_response = client.get("/openapi.json")
        findings = run_bola_tests(
            executor=executor,
            config=config,
            identities=identities,
        )
        findings.extend(
            run_bfla_tests(
                executor=executor,
                config=config,
                identities=identities,
            )
        )
        findings.extend(
            run_property_auth_tests(
                executor=executor,
                config=config,
                identities=identities,
            )
        )

    openapi_title = None
    if openapi_response.status_code == 200:
        try:
            openapi_body = openapi_response.json()
        except ValueError:
            openapi_body = None
        if isinstance(openapi_body, dict):
            info = openapi_body.get("info", {})
            if isinstance(info, dict):
                title = info.get("title")
                if isinstance(title, str):
                    openapi_title = title

    return ScannerRunResult(
        target_name=config.target.name,
        base_url=config.target.base_url,
        identities=identities,
        health_status_code=health_response.status_code,
        openapi_status_code=openapi_response.status_code,
        openapi_title=openapi_title,
        findings=findings,
    )


def run_smoke_scan(config: ScannerConfig) -> SmokeScanResult:
    return run_scan(config)


def print_scan_result(result: ScannerRunResult) -> None:
    console = Console()
    table = Table(title=f"AuthZ Scanner: {result.target_name}")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Detail")

    table.add_row("Target", "loaded", result.base_url)
    table.add_row("Identities", str(len(result.identities)), ", ".join(result.identities))
    table.add_row("Health", "ok" if result.health_ok else "failed", str(result.health_status_code))
    table.add_row(
        "OpenAPI",
        "ok" if result.openapi_ok else "failed",
        result.openapi_title or str(result.openapi_status_code),
    )
    table.add_row("Findings", str(result.finding_count), "BOLA, BFLA, and property checks completed")
    console.print(table)

    if result.findings:
        findings_table = Table(title="Findings")
        findings_table.add_column("Class")
        findings_table.add_column("Severity")
        findings_table.add_column("Method")
        findings_table.add_column("Endpoint")
        findings_table.add_column("Identity")
        findings_table.add_column("Evidence")

        for finding in result.findings:
            findings_table.add_row(
                finding.vulnerability_class.value,
                finding.severity.value,
                finding.method,
                finding.endpoint,
                finding.identity_name,
                str(finding.evidence_count),
            )

        console.print(findings_table)


def print_smoke_result(result: SmokeScanResult) -> None:
    if isinstance(result, ScannerRunResult):
        print_scan_result(result)
        return

    console = Console()
    table = Table(title=f"Scanner Smoke Check: {result.target_name}")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Detail")

    table.add_row("Target", "loaded", result.base_url)
    table.add_row("Identities", str(len(result.identities)), ", ".join(result.identities))
    table.add_row("Health", "ok" if result.health_ok else "failed", str(result.health_status_code))
    table.add_row(
        "OpenAPI",
        "ok" if result.openapi_ok else "failed",
        result.openapi_title or str(result.openapi_status_code),
    )
    console.print(table)


def write_reports(result: ScannerRunResult, report_format: str, report_dir: Path) -> list[Path]:
    report_paths: list[Path] = []
    generated_at = datetime.now(UTC)
    if report_format in {"json", "all"}:
        report_paths.append(write_json_report(result, report_dir, generated_at=generated_at))
    if report_format in {"markdown", "all"}:
        report_paths.append(write_markdown_report(result, report_dir, generated_at=generated_at))
    if report_format in {"html", "all"}:
        report_paths.append(write_html_report(result, report_dir, generated_at=generated_at))
    if report_paths:
        update_report_manifest(result, report_paths, report_dir, generated_at=generated_at)
    return report_paths


def print_comparison_result(results: list[ScannerRunResult]) -> None:
    console = Console()
    table = Table(title="AuthZ Scanner Comparison")
    table.add_column("Target")
    table.add_column("Base URL")
    table.add_column("Health")
    table.add_column("OpenAPI")
    table.add_column("Findings")

    for result in results:
        table.add_row(
            result.target_name,
            result.base_url,
            "ok" if result.health_ok else str(result.health_status_code),
            "ok" if result.openapi_ok else str(result.openapi_status_code),
            str(result.finding_count),
        )

    console.print(table)


def print_doctor_result(result: DoctorResult) -> None:
    console = Console()
    table = Table(title=f"Config Doctor: {result.config_name}")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    table.add_column("Suggestion")

    for check in result.checks:
        table.add_row(
            check.name,
            check.status,
            check.detail,
            check.suggestion or "",
        )

    console.print(table)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) >= 2 and argv[:2] == ["config", "doctor"]:
        parser = argparse.ArgumentParser(description="Validate scanner YAML config before running a scan.")
        parser.add_argument("command", nargs="?")
        parser.add_argument("subcommand", nargs="?")
        parser.add_argument(
            "--config",
            type=Path,
            required=True,
            help="Path to scanner YAML config.",
        )
        parser.add_argument(
            "--offline",
            action="store_true",
            help="Run static config validation only.",
        )
        args = parser.parse_args(argv)
        args.doctor = True
        args.compare_config = None
        args.report_format = "none"
        args.report_dir = Path("reports")
        return args

    parser = argparse.ArgumentParser(description="AuthZ Scanner")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--config",
        type=Path,
        help="Path to scanner YAML config.",
    )
    target_group.add_argument(
        "--compare-config",
        nargs=2,
        type=Path,
        metavar=("FIRST_CONFIG", "SECOND_CONFIG"),
        help="Run two scanner configs and print a comparison summary.",
    )
    parser.add_argument(
        "--report-format",
        choices=["none", "json", "markdown", "html", "all"],
        default="none",
        help="Optional report output format.",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=Path("reports"),
        help="Directory for generated report files.",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Validate scanner config before running a scan.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="With --doctor, run static config validation only.",
    )
    return parser.parse_args(argv)


def load_scanner_config(config_path: Path) -> ScannerConfig:
    try:
        return load_config(config_path)
    except FileNotFoundError as exc:
        raise ScannerCliError(f"Config file not found: {config_path}") from exc
    except PermissionError as exc:
        raise ScannerCliError(f"Config file is not readable: {config_path}") from exc
    except ValueError as exc:
        raise ScannerCliError(f"Config file is invalid: {exc}") from exc


def run_cli(argv: list[str] | None = None) -> int:
    console = Console(stderr=True)
    try:
        args = parse_args(argv)
        if args.config is not None:
            config = load_scanner_config(args.config)
            if args.doctor:
                doctor_result = run_config_doctor(config, live=not args.offline)
                print_doctor_result(doctor_result)
                return 1 if doctor_result.has_failures else 0
            result = run_scan(config)
            print_scan_result(result)
            results = [result]
        else:
            if args.doctor:
                raise ScannerCliError("--doctor can only be used with --config")
            results = [
                run_scan(load_scanner_config(config_path))
                for config_path in args.compare_config
            ]
            print_comparison_result(results)

        for result in results:
            for report_path in write_reports(result, args.report_format, args.report_dir):
                Console().print(f"Report written: {report_path}")
    except ScannerCliError as exc:
        console.print(f"Scanner error: {exc}")
        return 2
    except IdentityLoginError as exc:
        console.print(f"Authentication error: {exc}")
        return 2
    except httpx.RequestError as exc:
        console.print(f"Connection error: could not reach target API ({exc})")
        return 2

    return 0


def main() -> None:
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
