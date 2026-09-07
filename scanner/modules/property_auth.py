from typing import Any

from scanner.core.config import PropertyAuthTestConfig, PropertyPayloadConfig, ScannerConfig
from scanner.core.evidence import HttpEvidence
from scanner.core.executor import HttpExecutor
from scanner.core.finding import Finding, Severity, VulnerabilityClass
from scanner.core.identity import AuthenticatedIdentity
from scanner.modules.bfla import select_identity_by_role
from scanner.modules.bola import get_identity_subject_id


class PropertyAuthScanError(RuntimeError):
    pass


DEFAULT_EXCESSIVE_DATA_EXPOSURE_BUSINESS_IMPACT = (
    "Sensitive fields may leak into client applications or logs, increasing the risk of "
    "credential exposure, privacy incidents, and compliance findings."
)
DEFAULT_MASS_ASSIGNMENT_BUSINESS_IMPACT = (
    "A client may manipulate server-owned business fields, which can create unauthorized "
    "state changes, pricing errors, or workflow bypasses."
)
DEFAULT_PRIVILEGE_ESCALATION_BUSINESS_IMPACT = (
    "A low-privilege user may gain elevated access, exposing administrative functions and "
    "sensitive data across the application."
)


def find_forbidden_fields(data: Any, forbidden_fields: list[str], prefix: str = "") -> list[str]:
    matches: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            if key in forbidden_fields:
                matches.append(path)
            matches.extend(find_forbidden_fields(value, forbidden_fields, path))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            path = f"{prefix}.{index}" if prefix else str(index)
            matches.extend(find_forbidden_fields(item, forbidden_fields, path))

    return matches


def get_value_by_path(data: Any, dotted_path: str) -> Any:
    current_value = data
    for segment in dotted_path.split("."):
        if isinstance(current_value, dict):
            current_value = current_value.get(segment)
            continue
        if isinstance(current_value, list) and segment.isdigit():
            index = int(segment)
            if index >= len(current_value):
                return None
            current_value = current_value[index]
            continue
        return None
    return current_value


def find_forbidden_effects(data: Any, forbidden_effects: dict[str, Any]) -> dict[str, Any]:
    observed_effects: dict[str, Any] = {}
    for field_path, forbidden_value in forbidden_effects.items():
        observed_value = get_value_by_path(data, field_path)
        if str(observed_value) == str(forbidden_value):
            observed_effects[field_path] = observed_value
    return observed_effects


def build_subject_path(path_template: str, subject_id: str) -> str:
    return path_template.format(subject_id=subject_id)


def build_property_finding(
    test_config: PropertyAuthTestConfig,
    identity: AuthenticatedIdentity,
    evidence: HttpEvidence,
    vulnerability_class: VulnerabilityClass,
    description: str,
    business_impact: str,
    recommendation: str,
) -> Finding:
    return Finding(
        title=f"{vulnerability_class.value}: {test_config.name}",
        vulnerability_class=vulnerability_class,
        severity=Severity.HIGH,
        endpoint=test_config.request.path_template,
        method=test_config.request.method.upper(),
        identity_name=identity.name,
        description=description,
        business_impact=business_impact,
        recommendation=recommendation,
        evidence=[evidence],
    )


def run_excessive_data_exposure_test(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
    test_config: PropertyAuthTestConfig,
) -> list[Finding]:
    identity = select_identity_by_role(identities, test_config.role)
    result = executor.request(
        identity=identity,
        method=test_config.request.method,
        path=test_config.request.path_template,
    )
    if result.response_json is None:
        return []

    matches = find_forbidden_fields(result.response_json, test_config.forbidden_fields)
    if not matches:
        return []

    evidence = HttpEvidence(
        observed=result,
        expected_status_code=result.status_code,
        description=f"Response exposed forbidden fields: {', '.join(matches)}",
    )
    return [
        build_property_finding(
            test_config=test_config,
            identity=identity,
            evidence=evidence,
            vulnerability_class=VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE,
            description="The API response includes fields marked as sensitive in scanner config.",
            business_impact=(
                test_config.business_impact
                or DEFAULT_EXCESSIVE_DATA_EXPOSURE_BUSINESS_IMPACT
            ),
            recommendation="Return explicit response DTOs or allowlists that exclude sensitive fields.",
        )
    ]


def run_payload_effect_test(
    executor: HttpExecutor,
    config: ScannerConfig,
    identity: AuthenticatedIdentity,
    test_config: PropertyAuthTestConfig,
    payload: PropertyPayloadConfig,
) -> list[Finding]:
    subject_id = get_identity_subject_id(executor, identity, config)
    request_path = build_subject_path(test_config.request.path_template, subject_id)
    request_result = executor.request(
        identity=identity,
        method=test_config.request.method,
        path=request_path,
        json=payload.json_body,
    )

    verification_result = request_result
    if payload.verification is not None:
        verification_path = build_subject_path(payload.verification.path_template, subject_id)
        verification_result = executor.request(
            identity=identity,
            method=payload.verification.method,
            path=verification_path,
            json=payload.verification.json_body,
        )

    if verification_result.response_json is None:
        return []

    observed_effects = find_forbidden_effects(
        verification_result.response_json,
        payload.forbidden_effects,
    )
    if not observed_effects:
        return []

    evidence = HttpEvidence(
        observed=verification_result,
        expected_status_code=verification_result.status_code,
        description=(
            f"Payload '{payload.name}' caused forbidden effects: "
            f"{', '.join(observed_effects)}"
        ),
    )
    if test_config.type == "privilege_escalation":
        vulnerability_class = VulnerabilityClass.PRIVILEGE_ESCALATION
        description = "A low-privilege identity was able to change a privilege-related property."
        business_impact = (
            payload.business_impact
            or test_config.business_impact
            or DEFAULT_PRIVILEGE_ESCALATION_BUSINESS_IMPACT
        )
        recommendation = "Reject role or permission fields from self-service update payloads."
    else:
        vulnerability_class = VulnerabilityClass.MASS_ASSIGNMENT
        description = "The API accepted client-controlled values for server-controlled properties."
        business_impact = (
            payload.business_impact
            or test_config.business_impact
            or DEFAULT_MASS_ASSIGNMENT_BUSINESS_IMPACT
        )
        recommendation = "Use explicit input DTOs and ignore or reject server-controlled fields."

    return [
        build_property_finding(
            test_config=test_config,
            identity=identity,
            evidence=evidence,
            vulnerability_class=vulnerability_class,
            description=description,
            business_impact=business_impact,
            recommendation=recommendation,
        )
    ]


def run_property_auth_test(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
    test_config: PropertyAuthTestConfig,
) -> list[Finding]:
    if test_config.type == "excessive_data_exposure":
        return run_excessive_data_exposure_test(
            executor=executor,
            config=config,
            identities=identities,
            test_config=test_config,
        )

    if test_config.type not in {"mass_assignment", "privilege_escalation"}:
        raise PropertyAuthScanError(f"Unsupported property auth test type '{test_config.type}'")

    identity = select_identity_by_role(identities, test_config.role)
    findings: list[Finding] = []
    for payload in test_config.payloads:
        findings.extend(
            run_payload_effect_test(
                executor=executor,
                config=config,
                identity=identity,
                test_config=test_config,
                payload=payload,
            )
        )
    return findings


def run_property_auth_tests(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
) -> list[Finding]:
    findings: list[Finding] = []
    for test_config in config.property_auth.tests:
        findings.extend(
            run_property_auth_test(
                executor=executor,
                config=config,
                identities=identities,
                test_config=test_config,
            )
        )
    return findings
