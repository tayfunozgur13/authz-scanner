import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml
from rich.console import Console
from rich.table import Table


PATH_PARAM_PATTERN = re.compile(r"\{([^}]+)\}")
SENSITIVE_FIELDS = [
    "password",
    "password_hash",
    "hashed_password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "private_key",
    "ssn",
    "national_id",
    "credit_card",
    "card_number",
    "cvv",
    "otp_secret",
    "mfa_secret",
    "reset_token",
]
PRIVILEGED_PATH_KEYWORDS = {
    "admin",
    "approve",
    "approval",
    "refund",
    "manage",
    "export",
    "impersonate",
}
MASS_ASSIGNMENT_FIELD_VALUES = {
    "status": "approved",
    "state": "approved",
    "role": "admin",
    "is_admin": True,
    "is_verified": True,
    "total_amount": "0.01",
    "owner_id": "TODO_OTHER_OWNER_ID",
    "user_id": "TODO_OTHER_USER_ID",
    "tenant_id": "TODO_OTHER_TENANT_ID",
    "permissions": ["admin"],
}


def load_openapi_document(source: str) -> dict[str, Any]:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        response = httpx.get(source, timeout=10.0)
        response.raise_for_status()
        document = response.json()
    else:
        document = json.loads(Path(source).read_text())

    if not isinstance(document, dict):
        raise ValueError("OpenAPI document must be a JSON object")
    return document


def normalize_path_template(path: str) -> str:
    params = PATH_PARAM_PATTERN.findall(path)
    if not params:
        return path
    normalized = path.replace("{" + params[0] + "}", "{id}", 1)
    return normalized


def normalize_subject_path_template(path: str) -> str:
    params = PATH_PARAM_PATTERN.findall(path)
    if not params:
        return path
    normalized = path.replace("{" + params[0] + "}", "{subject_id}", 1)
    return normalized


def extract_path_params(path: str) -> list[str]:
    return PATH_PARAM_PATTERN.findall(path)


def operation_methods(operations: Any) -> list[str]:
    if not isinstance(operations, dict):
        return []
    return [
        method.upper()
        for method in operations
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    ]


def stable_test_name(prefix: str, method: str, path: str) -> str:
    cleaned = path.strip("/").replace("{", "").replace("}", "")
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", cleaned).strip("_").lower()
    return f"{prefix}_{method.lower()}_{cleaned or 'root'}"


def infer_target(openapi: dict[str, Any], source: str, base_url: str | None) -> dict[str, str]:
    info = openapi.get("info", {})
    title = info.get("title") if isinstance(info, dict) else None
    target_name = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(title or "generated-api").lower()).strip("-")

    if base_url:
        target_base_url = base_url
    else:
        servers = openapi.get("servers", [])
        target_base_url = "TODO_BASE_URL"
        if isinstance(servers, list) and servers:
            first_server = servers[0]
            if isinstance(first_server, dict) and isinstance(first_server.get("url"), str):
                target_base_url = first_server["url"]
        elif urlparse(source).scheme in {"http", "https"}:
            parsed = urlparse(source)
            target_base_url = f"{parsed.scheme}://{parsed.netloc}"

    return {
        "name": target_name or "generated-api",
        "base_url": target_base_url,
    }


def infer_auth(paths: dict[str, Any]) -> dict[str, str]:
    candidates = ["/auth/login", "/login", "/session", "/token", "/auth/token"]
    for candidate in candidates:
        operations = paths.get(candidate)
        if isinstance(operations, dict) and "post" in operations:
            token_field = "access_token" if "auth" in candidate or "login" in candidate else "token"
            return {"login_path": candidate, "token_field": token_field}
    return {"login_path": "TODO_LOGIN_PATH", "token_field": "TODO_TOKEN_FIELD"}


def infer_profile(paths: dict[str, Any]) -> dict[str, str]:
    candidates = ["/users/me", "/me", "/profile", "/account/me"]
    for candidate in candidates:
        operations = paths.get(candidate)
        if isinstance(operations, dict) and "get" in operations:
            return {"path": candidate, "id_field": "id"}
    return {"path": "TODO_PROFILE_PATH", "id_field": "TODO_ID_FIELD"}


def build_placeholder_identities() -> dict[str, dict[str, str]]:
    return {
        "owner": {
            "email": "TODO_OWNER_EMAIL",
            "password": "TODO_OWNER_PASSWORD",
            "role": "user",
        },
        "attacker": {
            "email": "TODO_ATTACKER_EMAIL",
            "password": "TODO_ATTACKER_PASSWORD",
            "role": "user",
        },
        "admin": {
            "email": "TODO_ADMIN_EMAIL",
            "password": "TODO_ADMIN_PASSWORD",
            "role": "admin",
        },
    }


def path_has_keyword(path: str, keywords: set[str]) -> bool:
    lowered = path.lower()
    return any(keyword in lowered for keyword in keywords)


def find_collection_path(paths: dict[str, Any], detail_path: str) -> str | None:
    before_param = detail_path.split("{", 1)[0].rstrip("/")
    if before_param and before_param in paths:
        operations = paths[before_param]
        if isinstance(operations, dict) and "get" in operations:
            return before_param
    segments = before_param.split("/")
    while len(segments) > 1:
        candidate = "/".join(segments).rstrip("/") or "/"
        operations = paths.get(candidate)
        if isinstance(operations, dict) and "get" in operations:
            return candidate
        segments.pop()
    return None


def infer_business_impact(path: str, vulnerability_type: str) -> str:
    lowered = path.lower()
    if "refund" in lowered:
        return "Unauthorized refunds may cause direct financial loss and reconciliation issues."
    if "approve" in lowered or "approval" in lowered:
        return "Unauthorized approvals may bypass business review workflows."
    if "admin" in lowered:
        return "Unauthorized administrative access may expose account metadata or privileged operations."
    if "order" in lowered:
        return "Unauthorized order access or manipulation may expose customer purchase data or disrupt fulfillment."
    if vulnerability_type == "mass_assignment":
        return "A user may manipulate server-controlled business fields and bypass normal workflow controls."
    if vulnerability_type == "excessive_data_exposure":
        return "Sensitive fields may leak into clients, logs, or third-party monitoring systems."
    return "TODO_BUSINESS_IMPACT"


def build_review_notes(*notes: str) -> list[str]:
    return [note for note in notes if note]


def generate_bola_tests(paths: dict[str, Any]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for path, operations in paths.items():
        params = extract_path_params(path)
        if not params:
            continue
        if path_has_keyword(path, PRIVILEGED_PATH_KEYWORDS):
            continue

        collection_path = find_collection_path(paths, path)
        if collection_path is None:
            continue

        for method in operation_methods(operations):
            if method not in {"GET", "PUT", "DELETE"}:
                continue
            template = normalize_path_template(path)
            key = (method, template)
            if key in seen:
                continue
            seen.add(key)

            path_params = {}
            for extra_param in params[1:]:
                path_params[extra_param] = f"TODO_PATH_TO_{extra_param.upper()}"
            if params[1:] and "item_id" in params[1:]:
                path_params["item_id"] = "items.0.id"

            attack: dict[str, Any] = {
                "method": method,
                "path_template": template,
            }
            if path_params:
                attack["path_params"] = path_params

            tests.append(
                {
                    "name": stable_test_name("generated_bola", method, path),
                    "role": "user",
                    "owner_field": "owner_id",
                    "resource": {
                        "list_method": "GET",
                        "list_path": collection_path,
                        "id_field": "id",
                    },
                    "attack": attack,
                    "expected_status": 403,
                    "business_impact": infer_business_impact(path, "bola"),
                    "review_required": True,
                    "review_notes": build_review_notes(
                        f"Generated from OpenAPI path {method} {path}.",
                        "Confirm owner_field and resource.id_field against the real response body.",
                        "Confirm this resource should be isolated between identities with role user.",
                        (
                            "Confirm attack.json_body if this non-GET endpoint requires a request body."
                            if method != "GET"
                            else ""
                        ),
                    ),
                }
            )
    return tests


def generate_bfla_tests(paths: dict[str, Any]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    for path, operations in paths.items():
        if not path_has_keyword(path, PRIVILEGED_PATH_KEYWORDS):
            continue
        for method in operation_methods(operations):
            test: dict[str, Any] = {
                "name": stable_test_name("generated_bfla", method, path),
                "role": "user",
                "attack": {
                    "method": method,
                    "path_template": normalize_path_template(path),
                },
                "expected_status": 403,
                "business_impact": infer_business_impact(path, "bfla"),
                "review_required": True,
                "review_notes": build_review_notes(
                    f"Generated from privileged-looking OpenAPI path {method} {path}.",
                    "Confirm which role should be allowed to execute this function.",
                ),
            }
            collection_path = find_collection_path(paths, path)
            if collection_path is not None and extract_path_params(path):
                test["resource"] = {
                    "list_method": "GET",
                    "list_path": collection_path,
                    "id_field": "id",
                    "owner_field": "owner_id",
                }
                test["review_notes"].append("Resource lookup was inferred from a nearby collection endpoint.")
            tests.append(test)
    return tests


def generate_exposure_tests(paths: dict[str, Any], profile_path: str) -> list[dict[str, Any]]:
    target_path = profile_path if profile_path != "TODO_PROFILE_PATH" else "/me"
    if target_path not in paths:
        return []
    return [
        {
            "name": stable_test_name("generated_sensitive_fields", "GET", target_path),
            "type": "excessive_data_exposure",
            "role": "user",
            "request": {
                "method": "GET",
                "path_template": target_path,
            },
            "forbidden_fields": SENSITIVE_FIELDS,
            "business_impact": infer_business_impact(target_path, "excessive_data_exposure"),
            "review_required": True,
            "review_notes": [
                "Default sensitive field list was applied.",
                "Remove fields that are not relevant and add API-specific sensitive fields.",
            ],
        }
    ]


def extract_schema_properties(schema: Any, components: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    if "$ref" in schema and isinstance(schema["$ref"], str):
        ref_name = schema["$ref"].rsplit("/", 1)[-1]
        schemas = components.get("schemas", {})
        if isinstance(schemas, dict):
            return extract_schema_properties(schemas.get(ref_name), components)
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return properties
    return {}


def request_body_properties(operation: Any, components: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(operation, dict):
        return {}
    request_body = operation.get("requestBody", {})
    if not isinstance(request_body, dict):
        return {}
    content = request_body.get("content", {})
    if not isinstance(content, dict):
        return {}
    media = content.get("application/json", {})
    if not isinstance(media, dict):
        return {}
    return extract_schema_properties(media.get("schema"), components)


def generate_property_payloads(properties: dict[str, Any]) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for field, value in MASS_ASSIGNMENT_FIELD_VALUES.items():
        if field not in properties:
            continue
        payloads.append(
            {
                "name": f"generated_force_{field}",
                "json_body": {field: value},
                "forbidden_effects": {field: value},
                "business_impact": infer_business_impact(field, "mass_assignment"),
                "review_required": True,
                "review_notes": [
                    f"Generated because request body contains risk field '{field}'.",
                    "Confirm this field is server-controlled for this API.",
                ],
            }
        )
    return payloads


def generate_property_tests(paths: dict[str, Any], components: dict[str, Any], profile_path: str) -> list[dict[str, Any]]:
    tests = generate_exposure_tests(paths, profile_path)
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            method_upper = method.upper()
            if method_upper not in {"POST", "PUT", "PATCH"}:
                continue
            properties = request_body_properties(operation, components)
            payloads = generate_property_payloads(properties)
            if not payloads:
                continue
            test_type = "privilege_escalation" if any(payload["json_body"].get("role") == "admin" for payload in payloads) else "mass_assignment"
            path_template = (
                normalize_subject_path_template(path)
                if test_type == "privilege_escalation"
                else normalize_path_template(path)
            )
            test: dict[str, Any] = {
                "name": stable_test_name(f"generated_{test_type}", method_upper, path),
                "type": test_type,
                "role": "user",
                "request": {
                    "method": method_upper,
                    "path_template": path_template,
                },
                "payloads": payloads,
                "review_required": True,
                "review_notes": [
                    f"Generated from request body schema for {method_upper} {path}.",
                    "Confirm payload shape includes required non-risk fields before running the scanner.",
                ],
            }
            collection_path = find_collection_path(paths, path)
            if test_type == "mass_assignment" and extract_path_params(path) and collection_path is not None:
                test["resource"] = {
                    "list_method": "GET",
                    "list_path": collection_path,
                    "id_field": "id",
                    "owner_field": "owner_id",
                }
                test["review_notes"].append(
                    "Resource lookup was inferred for resolving the {id} placeholder."
                )
            if test_type == "privilege_escalation" and profile_path != "TODO_PROFILE_PATH":
                for payload in test["payloads"]:
                    payload["verification"] = {
                        "method": "GET",
                        "path_template": profile_path,
                    }
            tests.append(test)
    return tests


def generate_config(openapi: dict[str, Any], source: str, base_url: str | None = None) -> dict[str, Any]:
    paths = openapi.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI document must contain a paths object")
    components = openapi.get("components", {})
    if not isinstance(components, dict):
        components = {}
    profile = infer_profile(paths)
    return {
        "target": infer_target(openapi, source=source, base_url=base_url),
        "auth": infer_auth(paths),
        "profile": profile,
        "identities": build_placeholder_identities(),
        "bola": {
            "tests": generate_bola_tests(paths),
        },
        "bfla": {
            "tests": generate_bfla_tests(paths),
        },
        "property_auth": {
            "tests": generate_property_tests(paths, components, profile["path"]),
        },
    }


def write_config(config: dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=False))
    return output_path


def load_yaml_config(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text()) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Config file is not a YAML object: {path}")
    return loaded


def collect_test_keys(config: dict[str, Any], section: str) -> set[tuple[str, str]]:
    tests = config.get(section, {}).get("tests", [])
    keys: set[tuple[str, str]] = set()
    if not isinstance(tests, list):
        return keys
    for test in tests:
        if not isinstance(test, dict):
            continue
        attack = test.get("attack") or test.get("request") or {}
        if not isinstance(attack, dict):
            continue
        method = str(attack.get("method", "")).upper()
        path = str(attack.get("path_template", ""))
        if method and path:
            keys.add((method, normalize_path_template(path)))
    return keys


def compare_configs(manual_config: dict[str, Any], generated_config: dict[str, Any]) -> dict[str, Any]:
    sections = ["bola", "bfla", "property_auth"]
    result: dict[str, Any] = {}
    for section in sections:
        manual_keys = collect_test_keys(manual_config, section)
        generated_keys = collect_test_keys(generated_config, section)
        matched = manual_keys & generated_keys
        result[section] = {
            "manual_count": len(manual_keys),
            "generated_count": len(generated_keys),
            "matched_count": len(matched),
            "missing_from_generated": sorted(manual_keys - generated_keys),
            "extra_generated": sorted(generated_keys - manual_keys),
        }
    return result


def print_comparison(summary: dict[str, Any]) -> None:
    console = Console()
    table = Table(title="OpenAPI Starter Config Comparison")
    table.add_column("Section")
    table.add_column("Manual")
    table.add_column("Generated")
    table.add_column("Matched")
    table.add_column("Missing")
    table.add_column("Extra")
    for section, data in summary.items():
        table.add_row(
            section,
            str(data["manual_count"]),
            str(data["generated_count"]),
            str(data["matched_count"]),
            str(len(data["missing_from_generated"])),
            str(len(data["extra_generated"])),
        )
    console.print(table)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate starter scanner config from OpenAPI")
    parser.add_argument("--openapi", required=True, help="OpenAPI JSON file path or URL")
    parser.add_argument("--output", required=True, type=Path, help="Output YAML config path")
    parser.add_argument("--base-url", help="Target base URL to write into generated config")
    parser.add_argument("--compare-with", type=Path, help="Optional manual config to compare with")
    return parser.parse_args(argv)


def run_cli(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    openapi = load_openapi_document(args.openapi)
    generated_config = generate_config(openapi, source=args.openapi, base_url=args.base_url)
    write_config(generated_config, args.output)
    Console().print(f"Starter config written: {args.output}")

    if args.compare_with is not None:
        manual_config = load_yaml_config(args.compare_with)
        print_comparison(compare_configs(manual_config, generated_config))
    return 0


def main() -> None:
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
