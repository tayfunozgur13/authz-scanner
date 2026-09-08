from typing import Any

from scanner.core.config import BflaResourceConfig, BflaTestConfig, ScannerConfig
from scanner.core.evidence import HttpEvidence
from scanner.core.executor import HttpExecutor
from scanner.core.finding import Finding, VulnerabilityClass
from scanner.core.risk import resolve_risk
from scanner.core.identity import AuthenticatedIdentity
from scanner.modules.bola import get_identity_subject_id


class BflaScanError(RuntimeError):
    pass


DEFAULT_BFLA_BUSINESS_IMPACT = (
    "A low-privilege user may execute restricted business operations, which can bypass "
    "approval workflows and create unauthorized operational or financial actions."
)


def select_identity_by_role(
    identities: dict[str, AuthenticatedIdentity],
    role: str,
) -> AuthenticatedIdentity:
    for identity in identities.values():
        if identity.role == role:
            return identity

    raise BflaScanError(f"BFLA test requires an identity with role '{role}'")


def select_resource_for_identity(
    resources: list[Any],
    subject_id: str,
    resource_config: BflaResourceConfig,
) -> dict[str, Any]:
    for resource in resources:
        if not isinstance(resource, dict):
            continue

        if resource_config.owner_field is not None and resource.get(resource_config.owner_field) != subject_id:
            continue

        resource_id = resource.get(resource_config.id_field)
        if isinstance(resource_id, str) and resource_id:
            return resource

    raise BflaScanError(f"No resource found for BFLA resource config '{resource_config.list_path}'")


def build_bfla_attack_path(
    executor: HttpExecutor,
    config: ScannerConfig,
    identity: AuthenticatedIdentity,
    test_config: BflaTestConfig,
) -> str:
    if test_config.resource is None:
        return test_config.attack.path_template

    subject_id = get_identity_subject_id(executor, identity, config)
    list_result = executor.request(
        identity=identity,
        method=test_config.resource.list_method,
        path=test_config.resource.list_path,
    )
    if list_result.response_json is None or not isinstance(list_result.response_json, list):
        raise BflaScanError(f"Resource list response for test '{test_config.name}' is not a JSON list")

    resource = select_resource_for_identity(
        resources=list_result.response_json,
        subject_id=subject_id,
        resource_config=test_config.resource,
    )
    resource_id = resource[test_config.resource.id_field]
    return test_config.attack.path_template.format(id=resource_id)


def run_bfla_test(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
    test_config: BflaTestConfig,
) -> list[Finding]:
    identity = select_identity_by_role(identities, test_config.role)
    attack_path = build_bfla_attack_path(
        executor=executor,
        config=config,
        identity=identity,
        test_config=test_config,
    )
    attack_result = executor.request(
        identity=identity,
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
            f"Identity '{identity.name}' with role '{identity.role}' called privileged function "
            f"'{test_config.attack.path_template}'."
        ),
    )
    severity, risk_score = resolve_risk(
        vulnerability_class=VulnerabilityClass.BFLA,
        method=test_config.attack.method,
        endpoint=test_config.attack.path_template,
        severity_override=test_config.severity,
        risk_score_override=test_config.risk_score,
    )
    finding = Finding(
        title=f"BFLA: {test_config.name}",
        vulnerability_class=VulnerabilityClass.BFLA,
        severity=severity,
        risk_score=risk_score,
        endpoint=test_config.attack.path_template,
        method=test_config.attack.method.upper(),
        identity_name=identity.name,
        description=(
            f"A user with role '{test_config.role}' received status "
            f"{attack_result.status_code} when calling a privileged function. "
            f"Expected status was {test_config.expected_status}."
        ),
        business_impact=test_config.business_impact or DEFAULT_BFLA_BUSINESS_IMPACT,
        recommendation=(
            "Enforce role checks before executing privileged functions. "
            "Return a consistent forbidden response for identities without the required role."
        ),
        evidence=[evidence],
    )
    return [finding]


def run_bfla_tests(
    executor: HttpExecutor,
    config: ScannerConfig,
    identities: dict[str, AuthenticatedIdentity],
) -> list[Finding]:
    findings: list[Finding] = []
    for test_config in config.bfla.tests:
        findings.extend(
            run_bfla_test(
                executor=executor,
                config=config,
                identities=identities,
                test_config=test_config,
            )
        )
    return findings
