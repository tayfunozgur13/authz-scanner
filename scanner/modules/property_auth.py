import json
from typing import Any

from scanner.core.config import (
    PropertyAuthTestConfig,
    PropertyPayloadConfig,
    ResponseMatcherConfig,
    ScannerConfig,
)
from scanner.core.evidence import HttpEvidence
from scanner.core.executor import HttpExecutor
from scanner.core.finding import Finding, VulnerabilityClass
from scanner.core.risk import resolve_risk
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
DEFAULT_RESPONSE_BODY_MISMATCH_BUSINESS_IMPACT = (
    "The API may return response data that violates the configured security contract, "
    "which can hide authorization bypasses or expose data clients should not receive."
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


def response_body_as_text(data: Any, response_text: str | None = None) -> str:
    if data is not None:
        return json.dumps(data, sort_keys=True)
    return response_text or ""


def evaluate_response_matchers(
    data: Any,
    response_text: str | None,
    matchers: ResponseMatcherConfig,
) -> list[str]:
    body_text = response_body_as_text(data, response_text)
    violations: list[str] = []

    for expected_text in matchers.body_should_contain:
        if expected_text not in body_text:
            violations.append(f"body did not contain '{expected_text}'")

    for forbidden_text in matchers.body_should_not_contain:
        if forbidden_text in body_text:
            violations.append(f"body contained forbidden text '{forbidden_text}'")

    for field_path, expected_value in matchers.field_should_equal.items():
        observed_value = get_value_by_path(data, field_path)
        if str(observed_value) != str(expected_value):
            violations.append(
                f"field '{field_path}' was '{observed_value}', expected '{expected_value}'"
            )

    for field_path, forbidden_value in matchers.field_should_not_equal.items():
        observed_value = get_value_by_path(data, field_path)
        if str(observed_value) == str(forbidden_value):
            violations.append(
                f"field '{field_path}' matched forbidden value '{forbidden_value}'"
            )

    return violations


def select_property_resource(
    executor: HttpExecutor,
    identity: AuthenticatedIdentity,
    config: ScannerConfig,
    test_config: PropertyAuthTestConfig,
) -> dict[str, Any]:
    if test_config.resource is None:
        return {}
    if test_config.resource.list_method.upper() != "GET":
        raise PropertyAuthScanError(
            f"Property resource lookup for test '{test_config.name}' requires a GET list endpoint"
        )

    subject_id = get_identity_subject_id(executor, identity, config)
    list_result = executor.request(
        identity=identity,
        method=test_config.resource.list_method,
        path=test_config.resource.list_path,
    )
    if list_result.response_json is None or not isinstance(list_result.response_json, list):
        raise PropertyAuthScanError(
            f"Resource list response for property test '{test_config.name}' is not a JSON list"
        )

    for resource in list_result.response_json:
        if not isinstance(resource, dict):
            continue
        if test_config.resource.owner_field is not None and resource.get(test_config.resource.owner_field) != subject_id:
            continue
        resource_id = resource.get(test_config.resource.id_field)
        if isinstance(resource_id, str) and resource_id:
            return resource

    raise PropertyAuthScanError(
        f"No resource found for property test '{test_config.name}' using id field "
        f"'{test_config.resource.id_field}'"
    )


def build_property_request_path(
    test_config: PropertyAuthTestConfig,
    subject_id: str,
    resource: dict[str, Any],
) -> str:
    path_values: dict[str, Any] = {"subject_id": subject_id}
    if test_config.resource is not None:
        resource_id = resource.get(test_config.resource.id_field)
        if not isinstance(resource_id, str) or not resource_id:
            raise PropertyAuthScanError(
                f"Resource id field '{test_config.resource.id_field}' could not be resolved "
                f"for property test '{test_config.name}'"
            )
        path_values["id"] = resource_id

    return test_config.request.path_template.format(**path_values)


def build_property_verification_path(
    path_template: str,
    subject_id: str,
    resource: dict[str, Any],
    test_config: PropertyAuthTestConfig,
) -> str:
    path_values: dict[str, Any] = {"subject_id": subject_id}
    if test_config.resource is not None:
        path_values["id"] = resource[test_config.resource.id_field]
    return path_template.format(**path_values)


def build_property_finding(
    test_config: PropertyAuthTestConfig,
    identity: AuthenticatedIdentity,
    evidence: HttpEvidence,
    vulnerability_class: VulnerabilityClass,
    description: str,
    business_impact: str,
    recommendation: str,
    severity_override: Any = None,
    risk_score_override: int | None = None,
    destructive: bool = False,
    reset_recommended: bool = False,
) -> Finding:
    severity, risk_score = resolve_risk(
        vulnerability_class=vulnerability_class,
        method=test_config.request.method,
        endpoint=test_config.request.path_template,
        severity_override=severity_override,
        risk_score_override=risk_score_override,
    )
    return Finding(
        title=f"{vulnerability_class.value}: {test_config.name}",
        vulnerability_class=vulnerability_class,
        severity=severity,
        risk_score=risk_score,
        endpoint=test_config.request.path_template,
        method=test_config.request.method.upper(),
        identity_name=identity.name,
        description=description,
        business_impact=business_impact,
        recommendation=recommendation,
        destructive=destructive,
        reset_recommended=reset_recommended,
        evidence=[evidence],
    )


def run_excessive_data_exposure_test(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
    test_config: PropertyAuthTestConfig,
) -> list[Finding]:
    identity = select_identity_by_role(identities, test_config.role)
    subject_id = get_identity_subject_id(executor, identity, config)
    resource = select_property_resource(
        executor=executor,
        identity=identity,
        config=config,
        test_config=test_config,
    )
    request_path = build_property_request_path(test_config, subject_id, resource)
    result = executor.request(
        identity=identity,
        method=test_config.request.method,
        path=request_path,
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
            severity_override=test_config.severity,
            risk_score_override=test_config.risk_score,
            destructive=test_config.destructive,
            reset_recommended=test_config.reset_recommended,
        )
    ]


def run_response_body_matcher_test(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
    test_config: PropertyAuthTestConfig,
) -> list[Finding]:
    identity = select_identity_by_role(identities, test_config.role)
    subject_id = get_identity_subject_id(executor, identity, config)
    resource = select_property_resource(
        executor=executor,
        identity=identity,
        config=config,
        test_config=test_config,
    )
    request_path = build_property_request_path(test_config, subject_id, resource)
    result = executor.request(
        identity=identity,
        method=test_config.request.method,
        path=request_path,
        json=test_config.request.json_body,
    )
    violations = evaluate_response_matchers(
        result.response_json,
        result.response_text,
        test_config.response_matchers,
    )
    if not violations:
        return []

    evidence = HttpEvidence(
        observed=result,
        expected_status_code=result.status_code,
        description=f"Response matcher violations: {', '.join(violations)}",
    )
    return [
        build_property_finding(
            test_config=test_config,
            identity=identity,
            evidence=evidence,
            vulnerability_class=VulnerabilityClass.RESPONSE_BODY_MISMATCH,
            description="The API response body did not satisfy the configured response matchers.",
            business_impact=(
                test_config.business_impact
                or DEFAULT_RESPONSE_BODY_MISMATCH_BUSINESS_IMPACT
            ),
            recommendation=(
                "Use explicit response DTOs, response allowlists, and field-level authorization "
                "checks so returned data matches the security contract."
            ),
            severity_override=test_config.severity,
            risk_score_override=test_config.risk_score,
            destructive=test_config.destructive,
            reset_recommended=test_config.reset_recommended,
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
    resource = select_property_resource(
        executor=executor,
        identity=identity,
        config=config,
        test_config=test_config,
    )
    request_path = build_property_request_path(test_config, subject_id, resource)
    request_result = executor.request(
        identity=identity,
        method=test_config.request.method,
        path=request_path,
        json=payload.json_body,
    )

    verification_result = request_result
    if payload.verification is not None:
        verification_path = build_property_verification_path(
            payload.verification.path_template,
            subject_id,
            resource,
            test_config,
        )
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
            severity_override=payload.severity or test_config.severity,
            risk_score_override=payload.risk_score or test_config.risk_score,
            destructive=payload.destructive or test_config.destructive,
            reset_recommended=payload.reset_recommended or test_config.reset_recommended,
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

    if test_config.type == "response_body_matcher":
        return run_response_body_matcher_test(
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
