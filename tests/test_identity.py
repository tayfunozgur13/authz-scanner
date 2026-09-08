import json

import httpx
import pytest

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
from scanner.core.identity import IdentityLoginError, login_all_identities, login_identity


def build_config() -> ScannerConfig:
    return ScannerConfig(
        target=TargetConfig(name="test", base_url="http://testserver"),
        auth=AuthConfig(login_path="/session", token_field="token"),
        profile=ProfileConfig(path="/me", id_field="subject_id"),
        identities={
            "owner": IdentityConfig(
                email="owner@example.test",
                password="owner-secret",
                role="user",
            ),
            "privileged": IdentityConfig(
                email="privileged@example.test",
                password="privileged-secret",
                role="admin",
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
                    expected_status=403,
                )
            ]
        ),
        bfla=BflaConfig(tests=[]),
        property_auth=PropertyAuthConfig(tests=[]),
    )


def test_login_identity_returns_authenticated_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/session"
        return httpx.Response(200, json={"token": "token-for-owner"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    config = build_config()

    identity = login_identity(
        client=client,
        auth_config=config.auth,
        name="owner",
        identity=config.identities["owner"],
    )

    assert identity.name == "owner"
    assert identity.email == "owner@example.test"
    assert identity.role == "user"
    assert identity.access_token == "token-for-owner"
    assert identity.authorization_header == {"Authorization": "Bearer token-for-owner"}


def test_login_all_identities_returns_identity_map() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        token = "privileged-token" if body["email"] == "privileged@example.test" else "owner-token"
        return httpx.Response(200, json={"token": token})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")

    identities = login_all_identities(client, build_config())

    assert set(identities) == {"owner", "privileged"}
    assert identities["owner"].access_token == "owner-token"
    assert identities["privileged"].access_token == "privileged-token"


def test_login_identity_raises_when_login_fails() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(401, json={})),
        base_url="http://testserver",
    )
    config = build_config()

    with pytest.raises(IdentityLoginError, match="Login failed"):
        login_identity(
            client=client,
            auth_config=config.auth,
            name="owner",
            identity=config.identities["owner"],
        )


def test_login_identity_raises_when_token_field_is_missing() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
        base_url="http://testserver",
    )
    config = build_config()

    with pytest.raises(IdentityLoginError, match="did not include token path"):
        login_identity(
            client=client,
            auth_config=config.auth,
            name="owner",
            identity=config.identities["owner"],
        )


def test_login_identity_raises_when_login_response_is_not_json() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text="not-json")),
        base_url="http://testserver",
    )
    config = build_config()

    with pytest.raises(IdentityLoginError, match="was not valid JSON"):
        login_identity(
            client=client,
            auth_config=config.auth,
            name="owner",
            identity=config.identities["owner"],
        )


def test_login_identity_supports_custom_login_body_and_nested_token_path() -> None:
    config = build_config()
    config.auth.login_body = {
        "username": "{email}",
        "secret": "{password}",
        "metadata": {"role": "{role}", "tenant": "{tenant}"},
    }
    config.auth.token_path = "data.tokens.access"
    config.identities["owner"].auth_values = {"tenant": "tenant-a"}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/session"
        assert json.loads(request.content.decode()) == {
            "username": "owner@example.test",
            "secret": "owner-secret",
            "metadata": {"role": "user", "tenant": "tenant-a"},
        }
        return httpx.Response(200, json={"data": {"tokens": {"access": "nested-token"}}})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")

    identity = login_identity(
        client=client,
        auth_config=config.auth,
        name="owner",
        identity=config.identities["owner"],
    )

    assert identity.access_token == "nested-token"
    assert identity.authorization_header == {"Authorization": "Bearer nested-token"}


def test_login_identity_supports_static_token_and_custom_auth_header() -> None:
    config = build_config()
    config.auth.auth_header_name = "X-API-Key"
    config.auth.auth_scheme = ""
    config.identities["owner"].access_token = "static-token"

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Static token identities should not call login endpoint")

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")

    identity = login_identity(
        client=client,
        auth_config=config.auth,
        name="owner",
        identity=config.identities["owner"],
    )

    assert identity.access_token == "static-token"
    assert identity.authorization_header == {"X-API-Key": "static-token"}


def test_login_identity_supports_cookie_from_login_response() -> None:
    config = build_config()
    config.auth.credential_location = "cookie"
    config.auth.cookie_name = "session_id"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/session"
        return httpx.Response(
            200,
            json={"detail": "ok"},
            headers={"Set-Cookie": "session_id=cookie-token; Path=/; HttpOnly"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")

    identity = login_identity(
        client=client,
        auth_config=config.auth,
        name="owner",
        identity=config.identities["owner"],
    )

    assert identity.access_token == "cookie-token"
    assert identity.authorization_header == {"Cookie": "session_id=cookie-token"}
    assert identity.auth_cookies == {"session_id": "cookie-token"}


def test_login_identity_supports_static_cookie_token() -> None:
    config = build_config()
    config.auth.credential_location = "cookie"
    config.auth.cookie_name = "session_id"
    config.identities["owner"].access_token = "static-cookie"

    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(500)),
        base_url="http://testserver",
    )

    identity = login_identity(
        client=client,
        auth_config=config.auth,
        name="owner",
        identity=config.identities["owner"],
    )

    assert identity.authorization_header == {"Cookie": "session_id=static-cookie"}
    assert identity.auth_cookies == {"session_id": "static-cookie"}
