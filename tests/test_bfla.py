import httpx

from scanner.core.config import (
    AuthConfig,
    BflaAttackConfig,
    BflaConfig,
    BflaResourceConfig,
    BflaTestConfig,
    BolaConfig,
    IdentityConfig,
    ProfileConfig,
    PropertyAuthConfig,
    ScannerConfig,
    TargetConfig,
)
from scanner.core.executor import HttpExecutor
from scanner.core.identity import AuthenticatedIdentity
from scanner.modules.bfla import (
    BflaScanError,
    run_bfla_tests,
    select_identity_by_role,
    select_resource_for_identity,
)


def build_config(resource_backed: bool = True) -> ScannerConfig:
    resource = (
        BflaResourceConfig(
            list_method="GET",
            list_path="/resources",
            id_field="id",
            owner_field="owner_id",
        )
        if resource_backed
        else None
    )
    return ScannerConfig(
        target=TargetConfig(name="external-api", base_url="http://testserver"),
        auth=AuthConfig(login_path="/session", token_field="token"),
        profile=ProfileConfig(path="/me", id_field="subject_id"),
        identities={
            "regular": IdentityConfig(
                email="regular@example.test",
                password="regular-secret",
                role="user",
            ),
            "privileged": IdentityConfig(
                email="privileged@example.test",
                password="privileged-secret",
                role="admin",
            ),
        },
        bola=BolaConfig(tests=[]),
        property_auth=PropertyAuthConfig(tests=[]),
        bfla=BflaConfig(
            tests=[
                BflaTestConfig(
                    name="regular_users_cannot_run_privileged_action",
                    role="user",
                    resource=resource,
                    attack=BflaAttackConfig(
                        method="POST" if resource_backed else "GET",
                        path_template=(
                            "/resources/{id}/privileged-action"
                            if resource_backed
                            else "/admin/users"
                        ),
                    ),
                    expected_status=403,
                    business_impact="Restricted workflow actions may be executed by regular users.",
                )
            ]
        ),
    )


def build_identities() -> dict[str, AuthenticatedIdentity]:
    return {
        "regular": AuthenticatedIdentity(
            name="regular",
            email="regular@example.test",
            role="user",
            access_token="regular-token",
        ),
        "privileged": AuthenticatedIdentity(
            name="privileged",
            email="privileged@example.test",
            role="admin",
            access_token="privileged-token",
        ),
    }


def test_select_identity_by_role_returns_first_matching_identity() -> None:
    identity = select_identity_by_role(build_identities(), "user")

    assert identity.name == "regular"


def test_select_identity_by_role_raises_when_role_is_missing() -> None:
    try:
        select_identity_by_role(build_identities(), "support")
    except BflaScanError as exc:
        assert "requires an identity" in str(exc)
    else:
        raise AssertionError("Expected BflaScanError")


def test_select_resource_for_identity_prefers_owned_resource() -> None:
    resource_config = build_config().bfla.tests[0].resource
    assert resource_config is not None

    resource = select_resource_for_identity(
        resources=[
            {"id": "resource-1", "owner_id": "other-subject"},
            {"id": "resource-2", "owner_id": "regular-subject"},
        ],
        subject_id="regular-subject",
        resource_config=resource_config,
    )

    assert resource["id"] == "resource-2"


def test_run_bfla_tests_returns_finding_when_privileged_function_succeeds() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer regular-token" and request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "regular-subject"})
        if request.headers["authorization"] == "Bearer regular-token" and request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "resource-owned-by-regular", "owner_id": "regular-subject"},
                ],
            )
        if request.url.path == "/resources/resource-owned-by-regular/privileged-action":
            return httpx.Response(200, json={"status": "done"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_bfla_tests(
        executor=executor,
        config=build_config(),
        identities=build_identities(),
    )

    assert len(findings) == 1
    assert findings[0].vulnerability_class == "BFLA"
    assert findings[0].method == "POST"
    assert findings[0].endpoint == "/resources/{id}/privileged-action"
    assert findings[0].identity_name == "regular"
    assert findings[0].business_impact == (
        "Restricted workflow actions may be executed by regular users."
    )
    assert findings[0].evidence[0].observed.status_code == 200
    assert findings[0].evidence[0].expected_status_code == 403


def test_run_bfla_tests_returns_no_finding_when_privileged_function_is_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer regular-token" and request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "regular-subject"})
        if request.headers["authorization"] == "Bearer regular-token" and request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "resource-owned-by-regular", "owner_id": "regular-subject"},
                ],
            )
        if request.url.path == "/resources/resource-owned-by-regular/privileged-action":
            return httpx.Response(403, json={"detail": "Forbidden"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_bfla_tests(
        executor=executor,
        config=build_config(),
        identities=build_identities(),
    )

    assert findings == []


def test_run_bfla_tests_supports_direct_function_without_resource_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["authorization"] == "Bearer regular-token" and request.url.path == "/admin/users":
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_bfla_tests(
        executor=executor,
        config=build_config(resource_backed=False),
        identities=build_identities(),
    )

    assert len(findings) == 1
    assert findings[0].method == "GET"
    assert findings[0].endpoint == "/admin/users"
