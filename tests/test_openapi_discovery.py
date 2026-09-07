import json

import yaml

from scanner.discovery.openapi import (
    compare_configs,
    generate_config,
    load_openapi_document,
    normalize_path_template,
    normalize_subject_path_template,
    run_cli,
    write_config,
)


def build_openapi() -> dict[str, object]:
    return {
        "openapi": "3.1.0",
        "info": {"title": "Demo Shop API", "version": "1.0.0"},
        "servers": [{"url": "http://127.0.0.1:8001"}],
        "paths": {
            "/auth/login": {
                "post": {"operationId": "login"},
            },
            "/orders": {
                "get": {"operationId": "list_orders"},
                "post": {
                    "operationId": "create_order",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/OrderCreate"}
                            }
                        }
                    },
                },
            },
            "/orders/{order_id}": {
                "get": {"operationId": "read_order"},
                "put": {"operationId": "update_order"},
                "delete": {"operationId": "delete_order"},
            },
            "/orders/{order_id}/items": {
                "get": {"operationId": "list_order_items"},
            },
            "/orders/{order_id}/items/{item_id}": {
                "get": {"operationId": "read_order_item"},
            },
            "/orders/{order_id}/refund": {
                "post": {"operationId": "refund_order"},
            },
            "/admin/users": {
                "get": {"operationId": "list_admin_users"},
            },
            "/users/me": {
                "get": {"operationId": "read_me"},
            },
            "/users/{user_id}": {
                "put": {
                    "operationId": "update_user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserUpdate"}
                            }
                        }
                    },
                },
            },
        },
        "components": {
            "schemas": {
                "OrderCreate": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "total_amount": {"type": "string"},
                    },
                },
                "UserUpdate": {
                    "type": "object",
                    "properties": {
                        "role": {"type": "string"},
                    },
                },
            }
        },
    }


def test_normalize_path_template_replaces_primary_openapi_param_with_scanner_id() -> None:
    assert normalize_path_template("/orders/{order_id}/items/{item_id}") == (
        "/orders/{id}/items/{item_id}"
    )


def test_normalize_subject_path_template_uses_scanner_subject_id() -> None:
    assert normalize_subject_path_template("/users/{user_id}") == "/users/{subject_id}"


def test_generate_config_creates_reviewable_starter_config_from_openapi() -> None:
    config = generate_config(build_openapi(), source="openapi.json")

    assert config["target"] == {
        "name": "demo-shop-api",
        "base_url": "http://127.0.0.1:8001",
    }
    assert config["auth"] == {
        "login_path": "/auth/login",
        "token_field": "access_token",
    }
    assert config["profile"] == {
        "path": "/users/me",
        "id_field": "id",
    }
    assert config["identities"]["owner"]["email"] == "TODO_OWNER_EMAIL"

    bola_tests = config["bola"]["tests"]
    bola_paths = {test["attack"]["path_template"] for test in bola_tests}
    assert "/orders/{id}" in bola_paths
    assert "/orders/{id}/items" in bola_paths
    assert "/orders/{id}/items/{item_id}" in bola_paths
    assert all(test["review_required"] is True for test in bola_tests)
    assert any(test["attack"].get("path_params") == {"item_id": "items.0.id"} for test in bola_tests)

    bfla_tests = config["bfla"]["tests"]
    bfla_paths = {test["attack"]["path_template"] for test in bfla_tests}
    assert "/orders/{id}/refund" in bfla_paths
    assert "/admin/users" in bfla_paths
    assert all(test["review_notes"] for test in bfla_tests)

    property_tests = config["property_auth"]["tests"]
    assert any(test["type"] == "excessive_data_exposure" for test in property_tests)
    assert any(test["type"] == "mass_assignment" for test in property_tests)
    assert any(test["type"] == "privilege_escalation" for test in property_tests)
    assert any(
        test["type"] == "privilege_escalation"
        and test["request"]["path_template"] == "/users/{subject_id}"
        for test in property_tests
    )


def test_write_config_outputs_valid_yaml(tmp_path) -> None:
    output_path = tmp_path / "generated.yaml"

    write_config(generate_config(build_openapi(), source="openapi.json"), output_path)

    written = yaml.safe_load(output_path.read_text())
    assert written["target"]["name"] == "demo-shop-api"
    assert written["bola"]["tests"][0]["review_required"] is True


def test_compare_configs_reports_matching_and_missing_candidates() -> None:
    manual = {
        "bola": {
            "tests": [
                {"attack": {"method": "GET", "path_template": "/orders/{id}"}},
                {"attack": {"method": "DELETE", "path_template": "/orders/{id}"}},
            ]
        },
        "bfla": {
            "tests": [
                {"attack": {"method": "POST", "path_template": "/orders/{id}/refund"}},
            ]
        },
        "property_auth": {
            "tests": [
                {"request": {"method": "POST", "path_template": "/orders"}},
            ]
        },
    }
    generated = {
        "bola": {
            "tests": [
                {"attack": {"method": "GET", "path_template": "/orders/{order_id}"}},
            ]
        },
        "bfla": {
            "tests": [
                {"attack": {"method": "POST", "path_template": "/orders/{id}/refund"}},
                {"attack": {"method": "GET", "path_template": "/admin/users"}},
            ]
        },
        "property_auth": {
            "tests": [
                {"request": {"method": "POST", "path_template": "/orders"}},
            ]
        },
    }

    summary = compare_configs(manual, generated)

    assert summary["bola"]["matched_count"] == 1
    assert summary["bola"]["manual_count"] == 2
    assert summary["bola"]["generated_count"] == 1
    assert summary["bfla"]["matched_count"] == 1
    assert summary["bfla"]["extra_generated"] == [("GET", "/admin/users")]
    assert summary["property_auth"]["matched_count"] == 1


def test_run_cli_generates_file_and_prints_comparison(tmp_path, capsys) -> None:
    openapi_path = tmp_path / "openapi.json"
    output_path = tmp_path / "generated.yaml"
    manual_path = tmp_path / "manual.yaml"
    openapi_path.write_text(json.dumps(build_openapi()))
    manual_path.write_text(
        """
target:
  name: manual
bola:
  tests:
    - attack:
        method: GET
        path_template: /orders/{id}
bfla:
  tests: []
property_auth:
  tests: []
"""
    )

    exit_code = run_cli(
        [
            "--openapi",
            str(openapi_path),
            "--output",
            str(output_path),
            "--compare-with",
            str(manual_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert output_path.exists()
    assert "Starter config written" in captured.out
    assert "OpenAPI Starter Config Comparison" in captured.out


def test_load_openapi_document_reads_json_file(tmp_path) -> None:
    openapi_path = tmp_path / "openapi.json"
    openapi_path.write_text(json.dumps(build_openapi()))

    loaded = load_openapi_document(str(openapi_path))

    assert loaded["info"]["title"] == "Demo Shop API"
