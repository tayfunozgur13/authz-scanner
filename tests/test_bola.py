import json

import httpx

from scanner.core.config import (
    AuthConfig,
    BflaConfig,
    BolaAttackConfig,
    BolaConfig,
    BolaResourceConfig,
    BolaTestConfig,
    IdentityConfig,
    ProfileConfig,
    PropertyAuthConfig,
    ScannerConfig,
    TargetConfig,
)
from scanner.core.executor import HttpExecutor
from scanner.core.identity import AuthenticatedIdentity
from scanner.modules.bola import (
    BolaScanError,
    build_attack_path,
    resolve_resource_path,
    run_bola_tests,
    select_owned_resource,
    select_role_pair,
)


def build_config(expected_status: int = 403) -> ScannerConfig:
    return ScannerConfig(
        target=TargetConfig(name="external-api", base_url="http://testserver"),
        auth=AuthConfig(login_path="/session", token_field="token"),
        profile=ProfileConfig(path="/me", id_field="subject_id"),
        identities={
            "owner": IdentityConfig(
                email="owner@example.test",
                password="owner-secret",
                role="user",
            ),
            "attacker": IdentityConfig(
                email="attacker@example.test",
                password="attacker-secret",
                role="user",
            ),
        },
        bola=BolaConfig(
            tests=[
                BolaTestConfig(
                    name="same_role_users_cannot_read_each_others_resources",
                    role="user",
                    owner_field="owner_id",
                    resource=BolaResourceConfig(
                        list_method="GET",
                        list_path="/resources",
                        id_field="id",
                    ),
                    attack=BolaAttackConfig(
                        method="GET",
                        path_template="/resources/{id}",
                    ),
                    expected_status=expected_status,
                    business_impact="Cross-user access may expose customer records.",
                )
            ]
        ),
        bfla=BflaConfig(tests=[]),
        property_auth=PropertyAuthConfig(tests=[]),
    )


def build_identities() -> dict[str, AuthenticatedIdentity]:
    return {
        "owner": AuthenticatedIdentity(
            name="owner",
            email="owner@example.test",
            role="user",
            access_token="owner-token",
        ),
        "attacker": AuthenticatedIdentity(
            name="attacker",
            email="attacker@example.test",
            role="user",
            access_token="attacker-token",
        ),
        "privileged": AuthenticatedIdentity(
            name="privileged",
            email="privileged@example.test",
            role="admin",
            access_token="privileged-token",
        ),
    }


def test_select_role_pair_returns_two_identities_with_matching_role() -> None:
    owner, attacker = select_role_pair(build_identities(), "user")

    assert owner.name == "owner"
    assert attacker.name == "attacker"


def test_select_role_pair_requires_two_matching_identities() -> None:
    try:
        select_role_pair(build_identities(), "admin")
    except BolaScanError as exc:
        assert "at least two identities" in str(exc)
    else:
        raise AssertionError("Expected BolaScanError")


def test_select_owned_resource_returns_resource_matching_subject_id() -> None:
    resource = select_owned_resource(
        resources=[
            {"id": "resource-1", "owner_id": "subject-1"},
            {"id": "resource-2", "owner_id": "subject-2"},
        ],
        subject_id="subject-2",
        test_config=build_config().bola.tests[0],
    )

    assert resource["id"] == "resource-2"


def test_resolve_resource_path_reads_nested_list_values() -> None:
    value = resolve_resource_path(
        {
            "id": "resource-1",
            "children": [
                {"id": "child-1"},
            ],
        },
        "children.0.id",
    )

    assert value == "child-1"


def test_build_attack_path_supports_additional_path_params() -> None:
    config = build_config()
    test_config = config.bola.tests[0].model_copy(
        update={
            "attack": BolaAttackConfig(
                method="GET",
                path_template="/resources/{id}/children/{child_id}",
                path_params={"child_id": "children.0.id"},
            )
        }
    )

    path = build_attack_path(
        test_config,
        {
            "id": "resource-1",
            "children": [
                {"id": "child-1"},
            ],
        },
    )

    assert path == "/resources/resource-1/children/child-1"


def test_run_bola_tests_returns_finding_when_cross_user_access_succeeds() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer owner-token" and request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.headers["authorization"] == "Bearer owner-token" and request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "resource-owned-by-owner", "owner_id": "subject-owner"},
                ],
            )
        if (
            request.headers["authorization"] == "Bearer attacker-token"
            and request.url.path == "/resources/resource-owned-by-owner"
        ):
            return httpx.Response(200, json={"id": "resource-owned-by-owner"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_bola_tests(
        executor=executor,
        config=build_config(),
        identities=build_identities(),
    )

    assert len(findings) == 1
    assert findings[0].vulnerability_class == "BOLA"
    assert findings[0].method == "GET"
    assert findings[0].endpoint == "/resources/{id}"
    assert findings[0].identity_name == "attacker"
    assert findings[0].business_impact == "Cross-user access may expose customer records."
    assert findings[0].evidence[0].observed.status_code == 200
    assert findings[0].evidence[0].expected_status_code == 403


def test_run_bola_tests_sends_configured_attack_json_body() -> None:
    config = build_config()
    config.bola.tests[0].attack.method = "PUT"
    config.bola.tests[0].attack.json_body = {"name": "changed"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer owner-token" and request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.headers["authorization"] == "Bearer owner-token" and request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "resource-owned-by-owner", "owner_id": "subject-owner"},
                ],
            )
        if (
            request.headers["authorization"] == "Bearer attacker-token"
            and request.url.path == "/resources/resource-owned-by-owner"
        ):
            assert request.method == "PUT"
            assert json.loads(request.content.decode()) == {"name": "changed"}
            return httpx.Response(200, json={"id": "resource-owned-by-owner"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_bola_tests(
        executor=executor,
        config=config,
        identities=build_identities(),
    )

    assert len(findings) == 1
    assert findings[0].method == "PUT"


def test_run_bola_tests_returns_no_finding_when_cross_user_access_is_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer owner-token" and request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.headers["authorization"] == "Bearer owner-token" and request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "resource-owned-by-owner", "owner_id": "subject-owner"},
                ],
            )
        if (
            request.headers["authorization"] == "Bearer attacker-token"
            and request.url.path == "/resources/resource-owned-by-owner"
        ):
            return httpx.Response(403, json={"detail": "Forbidden"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_bola_tests(
        executor=executor,
        config=build_config(),
        identities=build_identities(),
    )

    assert findings == []
