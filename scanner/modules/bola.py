from typing import Any

from scanner.core.config import BolaTestConfig, ScannerConfig
from scanner.core.evidence import HttpEvidence
from scanner.core.executor import HttpExecutor
from scanner.core.finding import Finding, VulnerabilityClass
from scanner.core.risk import resolve_risk
from scanner.core.identity import AuthenticatedIdentity


class BolaScanError(RuntimeError):
    pass


DEFAULT_BOLA_BUSINESS_IMPACT = (
    "A user may view or change another user's business records, which can cause "
    "privacy exposure, unauthorized account activity, and loss of trust in customer data handling."
)


def select_role_pair(
    identities: dict[str, AuthenticatedIdentity],
    role: str,
) -> tuple[AuthenticatedIdentity, AuthenticatedIdentity]:
    matching_identities = [
        identity for identity in identities.values() if identity.role == role
    ]
    if len(matching_identities) < 2:
        raise BolaScanError(f"BOLA test requires at least two identities with role '{role}'")

    return matching_identities[0], matching_identities[1]


def get_identity_subject_id(
    executor: HttpExecutor,
    identity: AuthenticatedIdentity,
    config: ScannerConfig,
) -> str:
    result = executor.request(
        identity=identity,
        method="GET",
        path=config.profile.path,
    )
    if result.response_json is None or not isinstance(result.response_json, dict):
        raise BolaScanError(f"Profile response for identity '{identity.name}' is not a JSON object")

    subject_id = result.response_json.get(config.profile.id_field)
    if not isinstance(subject_id, str) or not subject_id:
        raise BolaScanError(
            f"Profile response for identity '{identity.name}' did not include "
            f"id field '{config.profile.id_field}'"
        )

    return subject_id


def select_owned_resource(
    resources: list[Any],
    subject_id: str,
    test_config: BolaTestConfig,
) -> dict[str, Any]:
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if resource.get(test_config.owner_field) == subject_id:
            resource_id = resource.get(test_config.resource.id_field)
            if isinstance(resource_id, str) and resource_id:
                return resource

    raise BolaScanError(
        f"No owned resource found for owner field '{test_config.owner_field}' "
        f"and subject id '{subject_id}'"
    )


def resolve_resource_path(resource: dict[str, Any], dotted_path: str) -> Any:
    current_value: Any = resource
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


def build_attack_path(test_config: BolaTestConfig, owned_resource: dict[str, Any]) -> str:
    resource_id = owned_resource[test_config.resource.id_field]
    path_values: dict[str, Any] = {"id": resource_id}

    for placeholder, dotted_path in test_config.attack.path_params.items():
        value = resolve_resource_path(owned_resource, dotted_path)
        if not isinstance(value, str) or not value:
            raise BolaScanError(
                f"Could not resolve path parameter '{placeholder}' from resource path '{dotted_path}'"
            )
        path_values[placeholder] = value

    return test_config.attack.path_template.format(**path_values)


def run_bola_test(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
    test_config: BolaTestConfig,
) -> list[Finding]:
    owner, attacker = select_role_pair(identities, test_config.role)
    owner_subject_id = get_identity_subject_id(executor, owner, config)

    list_result = executor.request(
        identity=owner,
        method=test_config.resource.list_method,
        path=test_config.resource.list_path,
    )
    if list_result.response_json is None or not isinstance(list_result.response_json, list):
        raise BolaScanError(f"Resource list response for test '{test_config.name}' is not a JSON list")

    owned_resource = select_owned_resource(
        resources=list_result.response_json,
        subject_id=owner_subject_id,
        test_config=test_config,
    )
    resource_id = owned_resource[test_config.resource.id_field]
    attack_path = build_attack_path(test_config, owned_resource)

    attack_result = executor.request(
        identity=attacker,
        method=test_config.attack.method,
        path=attack_path,
        json=test_config.attack.json_body,
    )

    if attack_result.status_code == test_config.expected_status:
        return []

    evidence = HttpEvidence(
        observed=attack_result,
        expected_status_code=test_config.expected_status,
        description=(
            f"Identity '{attacker.name}' accessed resource '{resource_id}' "
            f"owned by identity '{owner.name}'."
        ),
    )
    severity, risk_score = resolve_risk(
        vulnerability_class=VulnerabilityClass.BOLA,
        method=test_config.attack.method,
        endpoint=test_config.attack.path_template,
        severity_override=test_config.severity,
        risk_score_override=test_config.risk_score,
    )
    finding = Finding(
        title=f"BOLA: {test_config.name}",
        vulnerability_class=VulnerabilityClass.BOLA,
        severity=severity,
        risk_score=risk_score,
        endpoint=test_config.attack.path_template,
        method=test_config.attack.method.upper(),
        identity_name=attacker.name,
        description=(
            f"A user with role '{test_config.role}' received status "
            f"{attack_result.status_code} when accessing another user's resource. "
            f"Expected status was {test_config.expected_status}."
        ),
        business_impact=test_config.business_impact or DEFAULT_BOLA_BUSINESS_IMPACT,
        recommendation=(
            "Verify resource ownership before returning or modifying the object. "
            "Allow access only when the current identity owns the resource or has an explicit privileged role."
        ),
        destructive=test_config.destructive,
        reset_recommended=test_config.reset_recommended,
        evidence=[evidence],
    )
    return [finding]


def run_bola_tests(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
) -> list[Finding]:
    findings: list[Finding] = []
    for test_config in config.bola.tests:
        findings.extend(
            run_bola_test(
                executor=executor,
                config=config,
                identities=identities,
                test_config=test_config,
            )
        )
    return findings
