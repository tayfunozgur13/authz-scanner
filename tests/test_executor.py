import json

import httpx

from scanner.core.executor import HttpExecutor
from scanner.core.identity import AuthenticatedIdentity


def build_identity() -> AuthenticatedIdentity:
    return AuthenticatedIdentity(
        name="owner",
        email="owner@example.test",
        role="user",
        access_token="owner-token",
    )


def test_executor_sends_authenticated_json_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/resources"
        assert request.headers["authorization"] == "Bearer owner-token"
        assert request.headers["x-test"] == "enabled"
        assert json.loads(request.content.decode()) == {"name": "demo"}
        return httpx.Response(201, json={"id": "resource-1", "name": "demo"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    executor = HttpExecutor(client)

    result = executor.request(
        identity=build_identity(),
        method="post",
        path="/resources",
        json={"name": "demo"},
        headers={"X-Test": "enabled"},
    )

    assert result.identity_name == "owner"
    assert result.method == "POST"
    assert result.path == "/resources"
    assert result.status_code == 201
    assert result.request_json == {"name": "demo"}
    assert result.response_json == {"id": "resource-1", "name": "demo"}
    assert result.response_text is None
    assert result.is_success is True


def test_executor_sends_identity_cookies() -> None:
    identity = AuthenticatedIdentity(
        name="owner",
        email="owner@example.test",
        role="user",
        access_token="cookie-token",
        auth_headers={},
        auth_cookies={"session_id": "cookie-token"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["cookie"] == "session_id=cookie-token"
        assert "authorization" not in request.headers
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://testserver")
    executor = HttpExecutor(client)

    result = executor.request(identity=identity, method="GET", path="/resources")

    assert result.status_code == 200


def test_executor_stores_text_response_when_body_is_not_json() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(403, text="Forbidden")),
        base_url="http://testserver",
    )
    executor = HttpExecutor(client)

    result = executor.request(
        identity=build_identity(),
        method="GET",
        path="/restricted",
    )

    assert result.status_code == 403
    assert result.response_json is None
    assert result.response_text == "Forbidden"
    assert result.is_success is False
