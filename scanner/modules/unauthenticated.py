from scanner.core.config import ScannerConfig, UnauthenticatedTestConfig
from scanner.core.evidence import HttpEvidence
from scanner.core.executor import HttpExecutor
from scanner.core.finding import Finding, VulnerabilityClass
from scanner.core.risk import resolve_risk


DEFAULT_UNAUTHENTICATED_BUSINESS_IMPACT = (
    "Protected API data or business functions may be reachable without a valid user session, "
    "allowing anonymous attackers to bypass the authentication boundary."
)


def run_unauthenticated_test(
    executor: HttpExecutor,
    test_config: UnauthenticatedTestConfig,
) -> list[Finding]:
    request_path = test_config.request.path_template
    result = executor.request_without_auth(
        method=test_config.request.method,
        path=request_path,
        json=test_config.request.json_body,
    )

    if result.status_code == test_config.expected_status:
        return []

    evidence = HttpEvidence(
        observed=result,
        expected_status_code=test_config.expected_status,
        description=(
            f"Unauthenticated request to '{test_config.request.path_template}' returned "
            f"{result.status_code} instead of {test_config.expected_status}."
        ),
    )
    severity, risk_score = resolve_risk(
        vulnerability_class=VulnerabilityClass.UNAUTHENTICATED_ACCESS,
        method=test_config.request.method,
        endpoint=test_config.request.path_template,
        severity_override=test_config.severity,
        risk_score_override=test_config.risk_score,
    )
    return [
        Finding(
            title=f"Unauthenticated Access: {test_config.name}",
            vulnerability_class=VulnerabilityClass.UNAUTHENTICATED_ACCESS,
            severity=severity,
            risk_score=risk_score,
            endpoint=test_config.request.path_template,
            method=test_config.request.method.upper(),
            identity_name="unauthenticated",
            description=(
                "An endpoint configured as authentication-required accepted a request "
                "without scanner-managed credentials."
            ),
            business_impact=test_config.business_impact or DEFAULT_UNAUTHENTICATED_BUSINESS_IMPACT,
            recommendation=(
                "Require authentication before executing this endpoint and return a consistent "
                "401 response when credentials are missing or invalid."
            ),
            destructive=test_config.destructive,
            reset_recommended=test_config.reset_recommended,
            evidence=[evidence],
        )
    ]


def run_unauthenticated_tests(
    executor: HttpExecutor,
    config: ScannerConfig,
) -> list[Finding]:
    findings: list[Finding] = []
    for test_config in config.unauthenticated.tests:
        findings.extend(
            run_unauthenticated_test(
                executor=executor,
                test_config=test_config,
            )
        )
    return findings
