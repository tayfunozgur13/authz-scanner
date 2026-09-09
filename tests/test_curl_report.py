from scanner.core.evidence import HttpEvidence
from scanner.core.identity import AuthenticatedIdentity
from scanner.core.result import HttpRequestResult
from scanner.reporting.curl import build_curl_command
from tests.test_json_report import build_result


def test_build_curl_command_uses_placeholder_bearer_token() -> None:
    result = build_result()
    evidence = HttpEvidence(
        observed=HttpRequestResult(
            identity_name="regular",
            method="POST",
            path="/orders",
            status_code=201,
            request_json={"status": "approved", "password": "secret-password"},
        ),
        expected_status_code=403,
        description="Mass assignment succeeded.",
    )

    command = build_curl_command(result, evidence)

    assert command.startswith("curl -i -X POST http://testserver/orders")
    assert "'Authorization: Bearer <regular_token>'" in command
    assert "'Content-Type: application/json'" in command
    assert """'{"status":"approved","password":"[REDACTED]"}'""" in command
    assert "secret-token" not in command
    assert "secret-password" not in command


def test_build_curl_command_uses_placeholder_cookie_value() -> None:
    result = build_result()
    result.identities["regular"] = AuthenticatedIdentity(
        name="regular",
        email="regular@example.test",
        role="user",
        access_token="secret-cookie-token",
        auth_cookies={"session_id": "secret-cookie-token"},
    )
    evidence = HttpEvidence(
        observed=HttpRequestResult(
            identity_name="regular",
            method="GET",
            path="/resources/1",
            status_code=200,
        ),
        expected_status_code=403,
        description="Cross-user read succeeded.",
    )

    command = build_curl_command(result, evidence)

    assert "'Cookie: session_id=<regular_session_id>'" in command
    assert "secret-cookie-token" not in command
