import json

import httpx

from scanner.core.config import (
    AuthConfig,
    BflaConfig,
    BolaConfig,
    IdentityConfig,
    ProfileConfig,
    PropertyAuthConfig,
    PropertyResourceConfig,
    PropertyAuthTestConfig,
    PropertyPayloadConfig,
    PropertyRequestConfig,
    ScannerConfig,
    TargetConfig,
)
from scanner.core.executor import HttpExecutor
from scanner.core.identity import AuthenticatedIdentity
from scanner.modules.property_auth import (
    find_forbidden_effects,
    find_forbidden_fields,
    run_property_auth_tests,
)


def build_config(tests: list[PropertyAuthTestConfig]) -> ScannerConfig:
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
        },
        bola=BolaConfig(tests=[]),
        bfla=BflaConfig(tests=[]),
        property_auth=PropertyAuthConfig(tests=tests),
    )


def build_identities() -> dict[str, AuthenticatedIdentity]:
    return {
        "regular": AuthenticatedIdentity(
            name="regular",
            email="regular@example.test",
            role="user",
            access_token="regular-token",
        )
    }


def test_find_forbidden_fields_searches_nested_dicts_and_lists() -> None:
    matches = find_forbidden_fields(
        {
            "id": "subject-1",
            "profile": {
                "api_key": "secret-api-key",
                "sessions": [
                    {"refresh_token": "secret-refresh-token"},
                ],
            },
        },
        ["api_key", "refresh_token", "password_hash"],
    )

    assert matches == ["profile.api_key", "profile.sessions.0.refresh_token"]


def test_find_forbidden_effects_compares_nested_values() -> None:
    observed_effects = find_forbidden_effects(
        {
            "state": {
                "approval": "approved",
            },
            "total_amount": "0.01",
        },
        {
            "state.approval": "approved",
            "total_amount": "0.01",
            "missing": "admin",
        },
    )

    assert observed_effects == {
        "state.approval": "approved",
        "total_amount": "0.01",
    }


def test_run_property_auth_tests_reports_excessive_data_exposure() -> None:
    test_config = PropertyAuthTestConfig(
        name="profile_must_not_expose_sensitive_fields",
        type="excessive_data_exposure",
        role="user",
        request=PropertyRequestConfig(method="GET", path_template="/me"),
        forbidden_fields=["password_hash", "api_key"],
        business_impact="Sensitive credential metadata may leak to clients.",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/me":
            return httpx.Response(
                200,
                json={
                    "subject_id": "regular-subject",
                    "credentials": {"password_hash": "secret-hash"},
                },
            )
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_property_auth_tests(
        executor=executor,
        config=build_config([test_config]),
        identities=build_identities(),
    )

    assert len(findings) == 1
    assert findings[0].vulnerability_class == "Excessive Data Exposure"
    assert findings[0].endpoint == "/me"
    assert findings[0].identity_name == "regular"
    assert findings[0].business_impact == "Sensitive credential metadata may leak to clients."
    assert "credentials.password_hash" in findings[0].evidence[0].description


def test_run_property_auth_tests_returns_no_finding_when_sensitive_fields_are_absent() -> None:
    test_config = PropertyAuthTestConfig(
        name="profile_must_not_expose_sensitive_fields",
        type="excessive_data_exposure",
        role="user",
        request=PropertyRequestConfig(method="GET", path_template="/me"),
        forbidden_fields=["password_hash", "api_key"],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "regular-subject", "email": "r@example.test"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_property_auth_tests(
        executor=executor,
        config=build_config([test_config]),
        identities=build_identities(),
    )

    assert findings == []


def test_run_property_auth_tests_tries_multiple_mass_assignment_payloads() -> None:
    test_config = PropertyAuthTestConfig(
        name="resource_create_must_not_accept_server_controlled_fields",
        type="mass_assignment",
        role="user",
        request=PropertyRequestConfig(method="POST", path_template="/resources"),
        payloads=[
            PropertyPayloadConfig(
                name="force_approved_state",
                json_body={"state": "approved"},
                forbidden_effects={"state": "approved"},
                business_impact="A user may bypass approval workflows.",
            ),
            PropertyPayloadConfig(
                name="force_low_total",
                json_body={"total_amount": "0.01"},
                forbidden_effects={"total_amount": "0.01"},
            ),
        ],
    )
    seen_payloads: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "regular-subject"})
        if request.url.path == "/resources":
            body = json.loads(request.content.decode())
            seen_payloads.append(body)
            return httpx.Response(201, json=body)
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_property_auth_tests(
        executor=executor,
        config=build_config([test_config]),
        identities=build_identities(),
    )

    assert seen_payloads == [{"state": "approved"}, {"total_amount": "0.01"}]
    assert len(findings) == 2
    assert {finding.vulnerability_class for finding in findings} == {"Mass Assignment"}
    assert findings[0].business_impact == "A user may bypass approval workflows."


def test_run_property_auth_tests_resolves_resource_id_for_mass_assignment() -> None:
    test_config = PropertyAuthTestConfig(
        name="resource_update_must_not_accept_server_controlled_fields",
        type="mass_assignment",
        role="user",
        request=PropertyRequestConfig(method="PUT", path_template="/resources/{id}"),
        resource=PropertyResourceConfig(
            list_method="GET",
            list_path="/resources",
            id_field="id",
            owner_field="owner_id",
        ),
        payloads=[
            PropertyPayloadConfig(
                name="force_approved_state",
                json_body={"state": "approved"},
                forbidden_effects={"state": "approved"},
            ),
        ],
    )
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        if request.method == "GET" and request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "regular-subject"})
        if request.method == "GET" and request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "other-resource", "owner_id": "other-subject"},
                    {"id": "resource-1", "owner_id": "regular-subject"},
                ],
            )
        if request.method == "PUT" and request.url.path == "/resources/resource-1":
            assert json.loads(request.content.decode()) == {"state": "approved"}
            return httpx.Response(200, json={"id": "resource-1", "state": "approved"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_property_auth_tests(
        executor=executor,
        config=build_config([test_config]),
        identities=build_identities(),
    )

    assert "/resources/resource-1" in seen_paths
    assert len(findings) == 1
    assert findings[0].vulnerability_class == "Mass Assignment"
    assert findings[0].endpoint == "/resources/{id}"


def test_run_property_auth_tests_verifies_privilege_escalation_after_payload() -> None:
    test_config = PropertyAuthTestConfig(
        name="users_cannot_promote_themselves_by_role_assignment",
        type="privilege_escalation",
        role="user",
        request=PropertyRequestConfig(method="PUT", path_template="/users/{subject_id}"),
        payloads=[
            PropertyPayloadConfig(
                name="promote_to_admin",
                json_body={"role": "admin"},
                verification=PropertyRequestConfig(method="GET", path_template="/me"),
                forbidden_effects={"role": "admin"},
                business_impact="A user may gain administrative privileges.",
            )
        ],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "regular-subject", "role": "admin"})
        if request.method == "PUT" and request.url.path == "/users/regular-subject":
            assert json.loads(request.content.decode()) == {"role": "admin"}
            return httpx.Response(200, json={"subject_id": "regular-subject", "role": "admin"})
        return httpx.Response(404, json={})

    executor = HttpExecutor(
        httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    )

    findings = run_property_auth_tests(
        executor=executor,
        config=build_config([test_config]),
        identities=build_identities(),
    )

    assert len(findings) == 1
    assert findings[0].vulnerability_class == "Privilege Escalation"
    assert findings[0].endpoint == "/users/{subject_id}"
    assert findings[0].business_impact == "A user may gain administrative privileges."
