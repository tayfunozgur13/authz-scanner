import httpx

from scanner.core.config import (
    AuthConfig,
    BflaAttackConfig,
    BflaConfig,
    BflaTestConfig,
    BolaAttackConfig,
    BolaConfig,
    BolaResourceConfig,
    BolaTestConfig,
    IdentityConfig,
    ProfileConfig,
    PropertyAuthConfig,
    PropertyAuthTestConfig,
    PropertyPayloadConfig,
    PropertyRequestConfig,
    PropertyResourceConfig,
    ScannerConfig,
    TargetConfig,
)
from scanner.core.identity import AuthenticatedIdentity
from scanner.main import (
    ScannerRunResult,
    load_scanner_config,
    print_comparison_result,
    run_cli,
    run_scan,
    write_reports,
)
from scanner.core.config_doctor import run_config_doctor


def build_config() -> ScannerConfig:
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
        bfla=BflaConfig(
            tests=[
                BflaTestConfig(
                    name="low_privilege_users_cannot_open_admin_panel",
                    role="user",
                    attack=BflaAttackConfig(
                        method="GET",
                        path_template="/admin/users",
                    ),
                    expected_status=403,
                )
            ]
        ),
        property_auth=PropertyAuthConfig(tests=[]),
    )


def test_run_scan_logs_in_identities_checks_api_and_runs_bola(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/session":
            return httpx.Response(200, json={"token": f"token-for-{request.url.host}"})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"info": {"title": "External API"}, "paths": {}})
        if request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.url.path == "/resources":
            return httpx.Response(
                200,
                json=[
                    {"id": "resource-owned-by-owner", "owner_id": "subject-owner"},
                ],
            )
        if request.url.path == "/resources/resource-owned-by-owner":
            return httpx.Response(403, json={"detail": "Forbidden"})
        if request.url.path == "/admin/users":
            return httpx.Response(403, json={"detail": "Forbidden"})
        return httpx.Response(404, json={})

    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(
                transport=httpx.MockTransport(handler),
                base_url=kwargs["base_url"],
                timeout=kwargs["timeout"],
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    result = run_scan(build_config())

    assert result.target_name == "external-api"
    assert result.base_url == "http://testserver"
    assert set(result.identities) == {"owner", "attacker", "privileged"}
    assert result.health_status_code == 200
    assert result.health_ok is True
    assert result.openapi_status_code == 200
    assert result.openapi_ok is True
    assert result.openapi_title == "External API"
    assert result.findings == []
    assert result.finding_count == 0


def test_run_scan_skips_destructive_tests_by_default(monkeypatch) -> None:
    config = build_config()
    config.bfla.tests[0].destructive = True
    config.bfla.tests[0].reset_recommended = True

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/session":
            return httpx.Response(200, json={"token": "identity-token"})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"info": {"title": "External API"}, "paths": {}})
        if request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.url.path == "/resources":
            return httpx.Response(200, json=[{"id": "resource-1", "owner_id": "subject-owner"}])
        if request.url.path == "/resources/resource-1":
            return httpx.Response(403, json={"detail": "Forbidden"})
        if request.url.path == "/admin/users":
            raise AssertionError("Destructive BFLA test should not run by default")
        return httpx.Response(404, json={})

    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(
                transport=httpx.MockTransport(handler),
                base_url=kwargs["base_url"],
                timeout=kwargs["timeout"],
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    result = run_scan(config)

    assert result.findings == []
    assert len(result.skipped_tests) == 1
    assert result.skipped_tests[0].name == "low_privilege_users_cannot_open_admin_panel"
    assert result.skipped_tests[0].reset_recommended is True


def test_write_reports_writes_json_markdown_and_html_when_format_is_all(tmp_path) -> None:
    scanner_result = ScannerRunResult(
        target_name="external-api",
        base_url="http://testserver",
        identities={
            "regular": AuthenticatedIdentity(
                name="regular",
                email="regular@example.test",
                role="user",
                access_token="secret-token",
            )
        },
        health_status_code=200,
        openapi_status_code=200,
        openapi_title="External API",
        findings=[],
    )

    report_paths = write_reports(scanner_result, "all", tmp_path)

    assert len(report_paths) == 3
    assert {path.suffix for path in report_paths} == {".json", ".md", ".html"}
    assert (tmp_path / "manifest.json").exists()
    assert (tmp_path / "latest.json").exists()
    assert (tmp_path / "latest.md").exists()
    assert (tmp_path / "latest.html").exists()


def test_load_scanner_config_reports_missing_file_as_cli_error(tmp_path) -> None:
    missing_config = tmp_path / "missing.yaml"

    try:
        load_scanner_config(missing_config)
    except RuntimeError as exc:
        assert "Config file not found" in str(exc)
    else:
        raise AssertionError("Expected missing config to raise RuntimeError")


def test_run_cli_returns_error_code_when_target_is_unreachable(tmp_path, capsys) -> None:
    config_path = tmp_path / "scanner.yaml"
    config_path.write_text(
        """
target:
  name: unreachable
  base_url: http://127.0.0.1:1

auth:
  login_path: /auth/login
  token_field: access_token

profile:
  path: /users/me
  id_field: id

identities:
  regular:
    email: regular@example.test
    password: regular-secret
    role: user

bola:
  tests: []

bfla:
  tests: []

property_auth:
  tests: []
"""
    )

    exit_code = run_cli(["--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Connection error" in captured.err


def test_print_comparison_result_shows_each_target(capsys) -> None:
    results = [
        ScannerRunResult(
            target_name="vulnerable",
            base_url="http://vulnerable.test",
            identities={},
            health_status_code=200,
            openapi_status_code=200,
            findings=[],
        ),
        ScannerRunResult(
            target_name="hardened",
            base_url="http://hardened.test",
            identities={},
            health_status_code=200,
            openapi_status_code=200,
            findings=[],
        ),
    ]

    print_comparison_result(results)

    captured = capsys.readouterr()
    assert "AuthZ Scanner Comparison" in captured.out
    assert "vulnerable" in captured.out
    assert "hardened" in captured.out


def test_run_cli_compare_config_runs_two_targets(tmp_path, monkeypatch, capsys) -> None:
    first_config = tmp_path / "first.yaml"
    second_config = tmp_path / "second.yaml"
    base_config = """
auth:
  login_path: /session
  token_field: token

profile:
  path: /me
  id_field: subject_id

identities:
  regular:
    email: regular@example.test
    password: regular-secret
    role: user

bola:
  tests: []

bfla:
  tests: []

property_auth:
  tests: []
"""
    first_config.write_text(
        "target:\n  name: first\n  base_url: http://first.test\n\n" + base_config
    )
    second_config.write_text(
        "target:\n  name: second\n  base_url: http://second.test\n\n" + base_config
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/session":
            return httpx.Response(200, json={"token": "regular-token"})
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"info": {"title": request.url.host}, "paths": {}})
        return httpx.Response(404, json={})

    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(
                transport=httpx.MockTransport(handler),
                base_url=kwargs["base_url"],
                timeout=kwargs["timeout"],
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    exit_code = run_cli(["--compare-config", str(first_config), str(second_config)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "AuthZ Scanner Comparison" in captured.out
    assert "first" in captured.out
    assert "second" in captured.out


def test_config_doctor_reports_missing_same_role_bola_identity() -> None:
    config = build_config()
    config.identities.pop("attacker")

    result = run_config_doctor(config, live=False)

    assert result.has_failures is True
    assert any(
        check.status == "fail"
        and "BOLA 'same_role_users_cannot_read_each_others_resources' role coverage" == check.name
        for check in result.checks
    )
    assert any(check.name == "Live target checks" and check.status == "warn" for check in result.checks)


def test_config_doctor_accepts_property_resource_id_placeholders() -> None:
    config = build_config()
    config.property_auth.tests.append(
        PropertyAuthTestConfig(
            name="resource_update_must_not_accept_server_controlled_fields",
            type="mass_assignment",
            role="user",
            resource=PropertyResourceConfig(
                list_method="GET",
                list_path="/resources",
                id_field="id",
                owner_field="owner_id",
            ),
            request=PropertyRequestConfig(method="PUT", path_template="/resources/{id}"),
            payloads=[
                PropertyPayloadConfig(
                    name="force_state",
                    json_body={"state": "approved"},
                    forbidden_effects={"state": "approved"},
                )
            ],
        )
    )

    result = run_config_doctor(config, live=False)

    assert result.has_failures is False
    assert any(
        check.name == "Property 'resource_update_must_not_accept_server_controlled_fields' request placeholders"
        and check.status == "pass"
        for check in result.checks
    )


def test_config_doctor_requires_cookie_name_for_cookie_auth() -> None:
    config = build_config()
    config.auth.credential_location = "cookie"

    result = run_config_doctor(config, live=False)

    assert result.has_failures is True
    assert any(check.name == "Auth cookie name" and check.status == "fail" for check in result.checks)


def test_config_doctor_requires_refresh_token_field_when_refresh_path_is_configured() -> None:
    config = build_config()
    config.auth.refresh_path = "/session/refresh"

    result = run_config_doctor(config, live=False)

    assert result.has_failures is True
    assert any(
        check.name == "Auth refresh token field" and check.status == "fail"
        for check in result.checks
    )


def test_run_cli_config_doctor_subcommand_checks_live_target(tmp_path, monkeypatch, capsys) -> None:
    config_path = tmp_path / "scanner.yaml"
    config_path.write_text(
        """
target:
  name: external-api
  base_url: http://testserver

auth:
  login_path: /session
  token_field: token

profile:
  path: /me
  id_field: subject_id

identities:
  owner:
    email: owner@example.test
    password: owner-secret
    role: user
  attacker:
    email: attacker@example.test
    password: attacker-secret
    role: user

bola:
  tests:
    - name: users_cannot_read_each_others_resources
      role: user
      owner_field: owner_id
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
      attack:
        method: GET
        path_template: /resources/{id}
      expected_status: 403

bfla:
  tests: []

property_auth:
  tests: []
"""
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"info": {"title": "External API"}})
        if request.url.path == "/session":
            return httpx.Response(200, json={"token": "identity-token"})
        if request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.url.path == "/resources":
            return httpx.Response(200, json=[{"id": "resource-1", "owner_id": "subject-owner"}])
        return httpx.Response(404, json={})

    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(
                transport=httpx.MockTransport(handler),
                base_url=kwargs["base_url"],
                timeout=kwargs["timeout"],
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    exit_code = run_cli(["config", "doctor", "--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Config Doctor: external-api" in captured.out
    assert "Health endpoint" in captured.out
    assert "owner_id" in captured.out


def test_run_cli_config_doctor_supports_cookie_auth(tmp_path, monkeypatch, capsys) -> None:
    config_path = tmp_path / "scanner.yaml"
    config_path.write_text(
        """
target:
  name: cookie-api
  base_url: http://testserver

auth:
  login_path: /session
  token_field: token
  credential_location: cookie
  cookie_name: session_id

profile:
  path: /me
  id_field: subject_id

identities:
  owner:
    email: owner@example.test
    password: owner-secret
    role: user
  attacker:
    email: attacker@example.test
    password: attacker-secret
    role: user

bola:
  tests:
    - name: users_cannot_read_each_others_resources
      role: user
      owner_field: owner_id
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
      attack:
        method: GET
        path_template: /resources/{id}
      expected_status: 403

bfla:
  tests: []

property_auth:
  tests: []
"""
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"info": {"title": "Cookie API"}})
        if request.url.path == "/session":
            body = request.content.decode()
            token = "owner-cookie" if "owner@example.test" in body else "attacker-cookie"
            return httpx.Response(
                200,
                json={"detail": "ok"},
                headers={"Set-Cookie": f"session_id={token}; Path=/; HttpOnly"},
            )
        if request.url.path == "/me":
            assert request.headers["cookie"] in {
                "session_id=owner-cookie",
                "session_id=attacker-cookie",
            }
        if request.url.path == "/resources":
            assert request.headers["cookie"] == "session_id=owner-cookie"
        if request.url.path == "/me":
            return httpx.Response(200, json={"subject_id": "subject-owner"})
        if request.url.path == "/resources":
            return httpx.Response(200, json=[{"id": "resource-1", "owner_id": "subject-owner"}])
        return httpx.Response(404, json={})

    class MockClient(httpx.Client):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(
                transport=httpx.MockTransport(handler),
                base_url=kwargs["base_url"],
                timeout=kwargs["timeout"],
            )

    monkeypatch.setattr(httpx, "Client", MockClient)

    exit_code = run_cli(["config", "doctor", "--config", str(config_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Config Doctor: cookie-api" in captured.out
    assert "Login 'owner'" in captured.out


def test_run_cli_doctor_flag_supports_offline_mode(tmp_path, capsys) -> None:
    config_path = tmp_path / "scanner.yaml"
    config_path.write_text(
        """
target:
  name: external-api
  base_url: http://testserver

auth:
  login_path: /session
  token_field: token

profile:
  path: /me
  id_field: subject_id

identities:
  owner:
    email: owner@example.test
    password: owner-secret
    role: user
  attacker:
    email: attacker@example.test
    password: attacker-secret
    role: user

bola:
  tests: []

bfla:
  tests: []

property_auth:
  tests: []
"""
    )

    exit_code = run_cli(["--config", str(config_path), "--doctor", "--offline"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Config Doctor: external-api" in captured.out
    assert "Live target checks" in captured.out
