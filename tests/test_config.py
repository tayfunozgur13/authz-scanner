from scanner.core.config import ScannerConfig, load_config


def test_demo_cookie_configs_load_successfully() -> None:
    vulnerable_config = load_config("config/vulnerable_cookie.yaml")
    hardened_config = load_config("config/hardened_cookie.yaml")

    assert vulnerable_config.target.name == "vulnerable-cookie"
    assert hardened_config.target.name == "hardened-cookie"
    assert vulnerable_config.auth.login_path == "/auth/session"
    assert hardened_config.auth.login_path == "/auth/session"
    assert vulnerable_config.auth.credential_location == "cookie"
    assert hardened_config.auth.credential_location == "cookie"
    assert vulnerable_config.auth.cookie_name == "session_id"
    assert hardened_config.auth.cookie_name == "session_id"


def test_demo_refresh_configs_load_successfully() -> None:
    vulnerable_config = load_config("config/vulnerable_refresh.yaml")
    hardened_config = load_config("config/hardened_refresh.yaml")

    assert vulnerable_config.target.name == "vulnerable-refresh"
    assert hardened_config.target.name == "hardened-refresh"
    assert vulnerable_config.auth.login_path == "/auth/login-expired-with-refresh"
    assert hardened_config.auth.login_path == "/auth/login-expired-with-refresh"
    assert vulnerable_config.auth.refresh_path == "/auth/refresh"
    assert hardened_config.auth.refresh_path == "/auth/refresh"
    assert vulnerable_config.auth.refresh_token_field == "refresh_token"
    assert hardened_config.auth.refresh_token_field == "refresh_token"


def test_loads_scanner_config_from_yaml(tmp_path) -> None:
    config_path = tmp_path / "scanner.yaml"
    config_path.write_text(
        """
target:
  name: external-api
  base_url: https://api.example.test

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
  privileged:
    email: privileged@example.test
    password: privileged-secret
    role: admin

bola:
  tests:
    - name: same_role_users_cannot_read_each_others_resources
      role: user
      owner_field: owner_id
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
      attack:
        method: GET
        path_template: /resources/{id}
        path_params:
          child_id: children.0.id
      expected_status: 403
      severity: critical
      risk_score: 91

bfla:
  tests:
    - name: low_privilege_users_cannot_run_privileged_action
      role: user
      resource:
        list_method: GET
        list_path: /resources
        id_field: id
        owner_field: owner_id
      attack:
        method: POST
        path_template: /resources/{id}/privileged-action
      expected_status: 403
      severity: high
      risk_score: 82
    - name: low_privilege_users_cannot_open_admin_panel
      role: user
      attack:
        method: GET
        path_template: /admin/users
      expected_status: 403

property_auth:
  tests:
    - name: profile_must_not_expose_sensitive_fields
      type: excessive_data_exposure
      role: user
      severity: medium
      risk_score: 45
      request:
        method: GET
        path_template: /me
      forbidden_fields:
        - password_hash
        - api_key
    - name: create_resource_must_not_accept_server_controlled_fields
      type: mass_assignment
      role: user
      request:
        method: POST
        path_template: /resources
      payloads:
        - name: force_admin_only_state
          severity: critical
          risk_score: 96
          json_body:
            state: approved
          forbidden_effects:
            state: approved
""",
    )

    config = load_config(config_path)

    assert isinstance(config, ScannerConfig)
    assert config.target.name == "external-api"
    assert config.target.base_url == "https://api.example.test"
    assert config.auth.login_path == "/session"
    assert config.auth.token_field == "token"
    assert config.profile.path == "/me"
    assert config.profile.id_field == "subject_id"
    assert set(config.identities) == {"owner", "attacker", "privileged"}
    assert config.identities["owner"].email == "owner@example.test"
    assert config.identities["owner"].role == "user"
    assert config.identities["privileged"].role == "admin"
    assert len(config.bola.tests) == 1
    bola_test = config.bola.tests[0]
    assert bola_test.name == "same_role_users_cannot_read_each_others_resources"
    assert bola_test.role == "user"
    assert bola_test.owner_field == "owner_id"
    assert bola_test.resource.list_method == "GET"
    assert bola_test.resource.list_path == "/resources"
    assert bola_test.resource.id_field == "id"
    assert bola_test.attack.method == "GET"
    assert bola_test.attack.path_template == "/resources/{id}"
    assert bola_test.attack.path_params == {"child_id": "children.0.id"}
    assert bola_test.expected_status == 403
    assert bola_test.severity == "critical"
    assert bola_test.risk_score == 91
    assert len(config.bfla.tests) == 2
    resource_bfla_test = config.bfla.tests[0]
    assert resource_bfla_test.name == "low_privilege_users_cannot_run_privileged_action"
    assert resource_bfla_test.role == "user"
    assert resource_bfla_test.resource is not None
    assert resource_bfla_test.resource.list_path == "/resources"
    assert resource_bfla_test.resource.owner_field == "owner_id"
    assert resource_bfla_test.attack.method == "POST"
    assert resource_bfla_test.attack.path_template == "/resources/{id}/privileged-action"
    assert resource_bfla_test.expected_status == 403
    assert resource_bfla_test.severity == "high"
    assert resource_bfla_test.risk_score == 82
    direct_bfla_test = config.bfla.tests[1]
    assert direct_bfla_test.resource is None
    assert direct_bfla_test.attack.path_template == "/admin/users"
    assert len(config.property_auth.tests) == 2
    exposure_test = config.property_auth.tests[0]
    assert exposure_test.type == "excessive_data_exposure"
    assert exposure_test.severity == "medium"
    assert exposure_test.risk_score == 45
    assert exposure_test.request.path_template == "/me"
    assert exposure_test.forbidden_fields == ["password_hash", "api_key"]
    mass_assignment_test = config.property_auth.tests[1]
    assert mass_assignment_test.type == "mass_assignment"
    assert mass_assignment_test.payloads[0].name == "force_admin_only_state"
    assert mass_assignment_test.payloads[0].severity == "critical"
    assert mass_assignment_test.payloads[0].risk_score == 96
    assert mass_assignment_test.payloads[0].forbidden_effects == {"state": "approved"}


def test_loads_empty_yaml_as_invalid_config(tmp_path) -> None:
    config_path = tmp_path / "empty.yaml"
    config_path.write_text("")

    try:
        load_config(config_path)
    except ValueError as exc:
        assert "target" in str(exc)
    else:
        raise AssertionError("Expected invalid config to raise ValueError")
