import httpx

from scanner.core.config import (
    UnauthenticatedConfig,
    UnauthenticatedRequestConfig,
    UnauthenticatedTestConfig,
)
from scanner.core.executor import HttpExecutor
from scanner.core.finding import VulnerabilityClass
from scanner.modules.unauthenticated import run_unauthenticated_tests
from tests.test_scanner_main import build_config


def build_executor(handler) -> HttpExecutor:
    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://testserver",
        timeout=10.0,
    )
    return HttpExecutor(client)


def test_unauthenticated_test_reports_access_when_expected_denial_is_missing() -> None:
    config = build_config()
    config.unauthenticated = UnauthenticatedConfig(
        tests=[
            UnauthenticatedTestConfig(
                name="anonymous_users_cannot_list_admin_users",
                request=UnauthenticatedRequestConfig(
                    method="GET",
                    path_template="/admin/users",
                ),
                expected_status=401,
                severity="critical",
                risk_score=92,
            )
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        return httpx.Response(200, json=[{"id": "user-1", "email": "user@example.test"}])

    findings = run_unauthenticated_tests(build_executor(handler), config)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vulnerability_class == VulnerabilityClass.UNAUTHENTICATED_ACCESS
    assert finding.identity_name == "unauthenticated"
    assert finding.endpoint == "/admin/users"
    assert finding.severity == "critical"
    assert finding.risk_score == 92
    assert finding.evidence[0].observed.status_code == 200
    assert finding.evidence[0].expected_status_code == 401


def test_unauthenticated_test_stays_quiet_when_expected_denial_is_returned() -> None:
    config = build_config()
    config.unauthenticated = UnauthenticatedConfig(
        tests=[
            UnauthenticatedTestConfig(
                name="anonymous_users_cannot_read_profile",
                request=UnauthenticatedRequestConfig(
                    method="GET",
                    path_template="/users/me",
                ),
                expected_status=401,
            )
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        return httpx.Response(401, json={"detail": "Could not validate credentials"})

    assert run_unauthenticated_tests(build_executor(handler), config) == []
