from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import SecretStr

from scanner.core.config import ScannerConfig
from scanner.core.identity import (
    build_auth_headers,
    extract_cookie_token,
    get_value_by_path,
    render_login_body,
)


@dataclass
class DoctorCheck:
    name: str
    status: str
    detail: str
    suggestion: str | None = None


@dataclass
class DoctorResult:
    config_name: str
    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return any(check.status == "fail" for check in self.checks)

    @property
    def has_warnings(self) -> bool:
        return any(check.status == "warn" for check in self.checks)


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def run_config_doctor(config: ScannerConfig, *, live: bool = True) -> DoctorResult:
    result = DoctorResult(config_name=config.target.name)
    _check_static_config(config, result)
    if live:
        _check_live_target(config, result)
    else:
        result.checks.append(
            DoctorCheck(
                name="Live target checks",
                status="warn",
                detail="Skipped because offline mode is enabled.",
                suggestion="Run without --offline to verify target reachability, login, profile, and resource list endpoints.",
            )
        )
    return result


def _add(
    result: DoctorResult,
    name: str,
    status: str,
    detail: str,
    suggestion: str | None = None,
) -> None:
    result.checks.append(
        DoctorCheck(
            name=name,
            status=status,
            detail=detail,
            suggestion=suggestion,
        )
    )


def _check_static_config(config: ScannerConfig, result: DoctorResult) -> None:
    parsed_base_url = urlparse(config.target.base_url)
    if parsed_base_url.scheme in {"http", "https"} and parsed_base_url.netloc:
        _add(result, "Target base URL", "pass", config.target.base_url)
    else:
        _add(
            result,
            "Target base URL",
            "fail",
            f"Invalid base URL: {config.target.base_url}",
            "Use an absolute http(s) URL such as http://127.0.0.1:8001.",
        )

    _check_path(result, "Auth login path", config.auth.login_path)
    _check_path(result, "Profile path", config.profile.path)
    _check_required_text(result, "Auth token field", config.auth.token_field)
    _check_required_text(result, "Profile id field", config.profile.id_field)
    _check_method(result, "Auth login method", config.auth.login_method)
    _check_credential_location(config, result)
    _check_refresh_config(config, result)
    _check_required_text(result, "Auth header name", config.auth.auth_header_name)
    _check_identities(config, result)
    _check_bola_tests(config, result)
    _check_bfla_tests(config, result)
    _check_property_auth_tests(config, result)
    _check_unauthenticated_tests(config, result)
    _check_placeholders(config, result)


def _check_required_text(result: DoctorResult, name: str, value: str) -> None:
    if value.strip():
        _add(result, name, "pass", value)
    else:
        _add(result, name, "fail", "Value is empty.", "Set a non-empty value in the config file.")


def _check_path(result: DoctorResult, name: str, path: str) -> None:
    if path.startswith("/") and not path.startswith("//"):
        _add(result, name, "pass", path)
    else:
        _add(result, name, "fail", f"Invalid path: {path}", "Use an absolute API path starting with '/'.")


def _check_method(result: DoctorResult, name: str, method: str) -> None:
    normalized_method = method.upper()
    if normalized_method in HTTP_METHODS:
        _add(result, name, "pass", normalized_method)
    else:
        _add(
            result,
            name,
            "fail",
            f"Unknown HTTP method: {method}",
            f"Use one of: {', '.join(sorted(HTTP_METHODS))}.",
        )


def _check_credential_location(config: ScannerConfig, result: DoctorResult) -> None:
    if config.auth.credential_location in {"header", "cookie"}:
        _add(result, "Auth credential location", "pass", config.auth.credential_location)
    else:
        _add(
            result,
            "Auth credential location",
            "fail",
            f"Unsupported credential location: {config.auth.credential_location}",
            "Use 'header' or 'cookie'.",
        )
        return

    if config.auth.credential_location == "cookie" and not config.auth.cookie_name:
        _add(
            result,
            "Auth cookie name",
            "fail",
            "Cookie auth is enabled but auth.cookie_name is empty.",
            "Set auth.cookie_name to the session cookie name returned by the API.",
        )


def _check_refresh_config(config: ScannerConfig, result: DoctorResult) -> None:
    if not config.auth.refresh_path:
        return

    _check_path(result, "Auth refresh path", config.auth.refresh_path)
    _check_method(result, "Auth refresh method", config.auth.refresh_method)
    if config.auth.refresh_token_field or config.auth.refresh_token_path:
        _add(
            result,
            "Auth refresh token field",
            "pass",
            config.auth.refresh_token_path or config.auth.refresh_token_field or "",
        )
    else:
        _add(
            result,
            "Auth refresh token field",
            "fail",
            "Refresh path is configured but refresh token field/path is empty.",
            "Set auth.refresh_token_field or auth.refresh_token_path so the scanner can store the refresh token from login.",
        )

    for status_code in config.auth.refresh_on_status_codes:
        if 100 <= status_code <= 599:
            _add(result, "Auth refresh trigger status", "pass", str(status_code))
        else:
            _add(
                result,
                "Auth refresh trigger status",
                "fail",
                f"Invalid HTTP status code: {status_code}",
                "Use status codes between 100 and 599.",
            )


def _check_expected_status(result: DoctorResult, name: str, expected_status: int) -> None:
    if 100 <= expected_status <= 599:
        status = "pass" if expected_status == 403 else "warn"
        suggestion = None
        if expected_status != 403:
            suggestion = "Authorization-denial tests usually expect 403 in this project."
        _add(result, name, status, str(expected_status), suggestion)
    else:
        _add(
            result,
            name,
            "fail",
            f"Invalid HTTP status code: {expected_status}",
            "Use a status code between 100 and 599.",
        )


def _check_identities(config: ScannerConfig, result: DoctorResult) -> None:
    if config.identities:
        _add(result, "Identities", "pass", f"{len(config.identities)} configured")
    else:
        _add(result, "Identities", "fail", "No identities are configured.", "Add at least two user identities and one admin identity for the demo matrix.")
        return

    role_counts: dict[str, int] = {}
    for name, identity in config.identities.items():
        role_counts[identity.role] = role_counts.get(identity.role, 0) + 1
        if not identity.email.strip() or not identity.password.strip() or not identity.role.strip():
            _add(
                result,
                f"Identity '{name}'",
                "fail",
                "Email, password, or role is empty.",
                "Set non-empty email, password, and role values.",
            )

    _add(
        result,
        "Identity roles",
        "pass",
        ", ".join(f"{role}={count}" for role, count in sorted(role_counts.items())),
    )


def _check_bola_tests(config: ScannerConfig, result: DoctorResult) -> None:
    for test in config.bola.tests:
        role_count = _identity_count_for_role(config, test.role)
        if role_count >= 2:
            _add(result, f"BOLA '{test.name}' role coverage", "pass", f"{role_count} identities with role '{test.role}'")
        else:
            _add(
                result,
                f"BOLA '{test.name}' role coverage",
                "fail",
                f"Only {role_count} identities with role '{test.role}' are configured.",
                "BOLA tests need two identities with the same role: one owner and one attacker.",
            )

        _check_method(result, f"BOLA '{test.name}' resource method", test.resource.list_method)
        _check_path(result, f"BOLA '{test.name}' resource path", test.resource.list_path)
        _check_method(result, f"BOLA '{test.name}' attack method", test.attack.method)
        _check_path(result, f"BOLA '{test.name}' attack path", test.attack.path_template)
        _check_expected_status(result, f"BOLA '{test.name}' expected status", test.expected_status)
        _check_template_placeholders(
            result,
            f"BOLA '{test.name}' attack placeholders",
            test.attack.path_template,
            {"id", *test.attack.path_params.keys()},
        )
        if test.attack.method.upper() in {"PUT", "PATCH"} and test.attack.json_body is None:
            _add(
                result,
                f"BOLA '{test.name}' request body",
                "warn",
                "PUT/PATCH attack has no json_body.",
                "Add json_body when the target endpoint requires a request payload.",
            )
        if test.review_required:
            _add(result, f"BOLA '{test.name}' review", "warn", "Marked review_required.", "Review and clear this flag after validating the test manually.")


def _check_bfla_tests(config: ScannerConfig, result: DoctorResult) -> None:
    for test in config.bfla.tests:
        role_count = _identity_count_for_role(config, test.role)
        if role_count >= 1:
            _add(result, f"BFLA '{test.name}' role coverage", "pass", f"{role_count} identities with role '{test.role}'")
        else:
            _add(
                result,
                f"BFLA '{test.name}' role coverage",
                "fail",
                f"No identity with role '{test.role}' is configured.",
                "Add an identity with this role or update the test role.",
            )

        if test.resource is not None:
            _check_method(result, f"BFLA '{test.name}' resource method", test.resource.list_method)
            _check_path(result, f"BFLA '{test.name}' resource path", test.resource.list_path)
        _check_method(result, f"BFLA '{test.name}' attack method", test.attack.method)
        _check_path(result, f"BFLA '{test.name}' attack path", test.attack.path_template)
        _check_expected_status(result, f"BFLA '{test.name}' expected status", test.expected_status)
        _check_template_placeholders(
            result,
            f"BFLA '{test.name}' attack placeholders",
            test.attack.path_template,
            {"id"} if test.resource is not None else set(),
        )
        if test.review_required:
            _add(result, f"BFLA '{test.name}' review", "warn", "Marked review_required.", "Review and clear this flag after validating the test manually.")


def _check_property_auth_tests(config: ScannerConfig, result: DoctorResult) -> None:
    supported_types = {"excessive_data_exposure", "mass_assignment", "privilege_escalation"}
    for test in config.property_auth.tests:
        if test.type in supported_types:
            _add(result, f"Property '{test.name}' type", "pass", test.type)
        else:
            _add(
                result,
                f"Property '{test.name}' type",
                "fail",
                f"Unsupported type: {test.type}",
                f"Use one of: {', '.join(sorted(supported_types))}.",
            )

        role_count = _identity_count_for_role(config, test.role)
        if role_count >= 1:
            _add(result, f"Property '{test.name}' role coverage", "pass", f"{role_count} identities with role '{test.role}'")
        else:
            _add(
                result,
                f"Property '{test.name}' role coverage",
                "fail",
                f"No identity with role '{test.role}' is configured.",
                "Add an identity with this role or update the test role.",
            )

        _check_method(result, f"Property '{test.name}' request method", test.request.method)
        _check_path(result, f"Property '{test.name}' request path", test.request.path_template)
        if test.resource is not None:
            _check_method(result, f"Property '{test.name}' resource method", test.resource.list_method)
            _check_path(result, f"Property '{test.name}' resource path", test.resource.list_path)
        _check_template_placeholders(
            result,
            f"Property '{test.name}' request placeholders",
            test.request.path_template,
            {"subject_id", "id"} if test.resource is not None else {"subject_id"},
        )

        if test.type == "excessive_data_exposure" and not test.forbidden_fields:
            _add(
                result,
                f"Property '{test.name}' forbidden fields",
                "fail",
                "No forbidden_fields are configured.",
                "Add sensitive field names such as password_hash, token, api_key, or private_key.",
            )

        if test.type in {"mass_assignment", "privilege_escalation"} and not test.payloads:
            _add(
                result,
                f"Property '{test.name}' payloads",
                "fail",
                "No payloads are configured.",
                "Add at least one payload with json_body and forbidden_effects.",
            )

        for payload in test.payloads:
            if not payload.json_body:
                _add(
                    result,
                    f"Payload '{payload.name}' body",
                    "fail",
                    "json_body is empty.",
                    "Add the fields that should be rejected or ignored by the API.",
                )
            if not payload.forbidden_effects:
                _add(
                    result,
                    f"Payload '{payload.name}' effects",
                    "fail",
                    "forbidden_effects is empty.",
                    "Define the response or verification values that prove the forbidden effect happened.",
                )
            if payload.verification is not None:
                _check_method(result, f"Payload '{payload.name}' verification method", payload.verification.method)
                _check_path(result, f"Payload '{payload.name}' verification path", payload.verification.path_template)
                _check_template_placeholders(
                    result,
                    f"Payload '{payload.name}' verification placeholders",
                    payload.verification.path_template,
                    {"subject_id"},
                )
            if payload.review_required:
                _add(result, f"Payload '{payload.name}' review", "warn", "Marked review_required.", "Review and clear this flag after validating the payload manually.")

        if test.review_required:
            _add(result, f"Property '{test.name}' review", "warn", "Marked review_required.", "Review and clear this flag after validating the test manually.")


def _check_unauthenticated_tests(config: ScannerConfig, result: DoctorResult) -> None:
    for test in config.unauthenticated.tests:
        _check_method(result, f"Unauthenticated '{test.name}' request method", test.request.method)
        _check_path(result, f"Unauthenticated '{test.name}' request path", test.request.path_template)
        if 100 <= test.expected_status <= 599:
            status = "pass" if test.expected_status in {401, 403} else "warn"
            suggestion = None
            if status == "warn":
                suggestion = "Unauthenticated-denial tests usually expect 401 or 403."
            _add(
                result,
                f"Unauthenticated '{test.name}' expected status",
                status,
                str(test.expected_status),
                suggestion,
            )
        else:
            _add(
                result,
                f"Unauthenticated '{test.name}' expected status",
                "fail",
                f"Invalid HTTP status code: {test.expected_status}",
                "Use a status code between 100 and 599.",
            )
        _check_template_placeholders(
            result,
            f"Unauthenticated '{test.name}' request placeholders",
            test.request.path_template,
            set(),
        )
        if test.request.method.upper() in {"POST", "PUT", "PATCH"} and test.request.json_body is None:
            _add(
                result,
                f"Unauthenticated '{test.name}' request body",
                "warn",
                "Mutating request has no json_body.",
                "Add json_body when the target endpoint requires a request payload.",
            )
        if test.review_required:
            _add(result, f"Unauthenticated '{test.name}' review", "warn", "Marked review_required.", "Review and clear this flag after validating the test manually.")


def _identity_count_for_role(config: ScannerConfig, role: str) -> int:
    return sum(1 for identity in config.identities.values() if identity.role == role)


def _check_template_placeholders(
    result: DoctorResult,
    name: str,
    template: str,
    available_placeholders: set[str],
) -> None:
    placeholders = _extract_placeholders(template)
    missing = sorted(placeholders - available_placeholders)
    if not missing:
        _add(result, name, "pass", "All placeholders can be resolved.")
        return
    _add(
        result,
        name,
        "fail",
        f"Missing placeholder values: {', '.join(missing)}",
        "Add matching path_params or use a supported placeholder such as {id} or {subject_id}.",
    )


def _extract_placeholders(template: str) -> set[str]:
    placeholders: set[str] = set()
    parts = template.split("{")[1:]
    for part in parts:
        placeholder = part.split("}", 1)[0]
        if placeholder:
            placeholders.add(placeholder)
    return placeholders


def _check_placeholders(config: ScannerConfig, result: DoctorResult) -> None:
    paths = _find_placeholder_values(config.model_dump(mode="python"))
    if not paths:
        _add(result, "TODO placeholders", "pass", "No TODO placeholder values found.")
        return

    _add(
        result,
        "TODO placeholders",
        "warn",
        ", ".join(paths[:10]),
        "Replace placeholder values before running a scan against a real target.",
    )


def _find_placeholder_values(data: Any, prefix: str = "") -> list[str]:
    if isinstance(data, SecretStr):
        data = data.get_secret_value()
    if isinstance(data, str):
        upper_value = data.upper()
        if "TODO" in upper_value or "REPLACE_ME" in upper_value or "CHANGE_ME" in upper_value:
            return [prefix or "<root>"]
        return []
    if isinstance(data, dict):
        matches: list[str] = []
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            matches.extend(_find_placeholder_values(value, path))
        return matches
    if isinstance(data, list):
        matches = []
        for index, value in enumerate(data):
            path = f"{prefix}.{index}" if prefix else str(index)
            matches.extend(_find_placeholder_values(value, path))
        return matches
    return []


def _check_live_target(config: ScannerConfig, result: DoctorResult) -> None:
    try:
        with httpx.Client(base_url=config.target.base_url, timeout=10.0) as client:
            _check_simple_get(client, result, "Health endpoint", "/health")
            _check_simple_get(client, result, "OpenAPI endpoint", "/openapi.json")
            tokens = _check_login(client, config, result)
            _check_profiles(client, config, result, tokens)
            _check_resource_lists(client, config, result, tokens)
    except httpx.RequestError as exc:
        _add(
            result,
            "Target connection",
            "fail",
            f"Could not reach target API: {exc}",
            "Start the API, check target.base_url, or run with --offline for static-only validation.",
        )


def _check_simple_get(client: httpx.Client, result: DoctorResult, name: str, path: str) -> None:
    response = client.get(path)
    if response.status_code == 200:
        _add(result, name, "pass", f"GET {path} returned 200")
    else:
        _add(
            result,
            name,
            "warn",
            f"GET {path} returned {response.status_code}",
            "Confirm this endpoint exists and is reachable if the scanner depends on it.",
        )


def _check_login(
    client: httpx.Client,
    config: ScannerConfig,
    result: DoctorResult,
) -> dict[str, str]:
    tokens: dict[str, str] = {}
    for name, identity in config.identities.items():
        if identity.access_token:
            tokens[name] = identity.access_token
            _add(result, f"Login '{name}'", "pass", "Static token configured; login request skipped.")
            continue

        response = client.request(
            config.auth.login_method,
            config.auth.login_path,
            json=render_login_body(config.auth.login_body, name, identity),
        )
        if response.status_code != 200:
            _add(
                result,
                f"Login '{name}'",
                "fail",
                f"Login returned {response.status_code}.",
                "Check auth.login_path and the configured email/password for this identity.",
            )
            continue
        try:
            body = response.json()
        except ValueError:
            _add(result, f"Login '{name}'", "fail", "Login response is not JSON.", "Return a JSON body containing the configured token field.")
            continue
        token_path = config.auth.token_path or config.auth.token_field
        cookie_token = extract_cookie_token(response, config.auth)
        if cookie_token is not None:
            client.cookies.clear()
        token = cookie_token or get_value_by_path(body, token_path)
        if isinstance(token, str) and token:
            tokens[name] = token
            _add(result, f"Login '{name}'", "pass", "Token found.")
        else:
            _add(
                result,
                f"Login '{name}'",
                "fail",
                f"Token path '{token_path}' was not found.",
                "Update auth.token_field, auth.token_path, or the login response mapping.",
            )
    return tokens


def _check_profiles(
    client: httpx.Client,
    config: ScannerConfig,
    result: DoctorResult,
    tokens: dict[str, str],
) -> None:
    for name, token in tokens.items():
        response = client.get(
            config.profile.path,
            headers=build_auth_headers(config.auth, token),
        )
        if response.status_code != 200:
            _add(result, f"Profile '{name}'", "fail", f"Profile returned {response.status_code}.", "Check profile.path and bearer token handling.")
            continue
        try:
            body = response.json()
        except ValueError:
            _add(result, f"Profile '{name}'", "fail", "Profile response is not JSON.", "Return a JSON object with the configured profile id field.")
            continue
        subject_id = body.get(config.profile.id_field) if isinstance(body, dict) else None
        if isinstance(subject_id, str) and subject_id:
            _add(result, f"Profile '{name}'", "pass", f"Found {config.profile.id_field}.")
        else:
            _add(
                result,
                f"Profile '{name}'",
                "fail",
                f"Profile id field '{config.profile.id_field}' was not found.",
                "Update profile.id_field or the profile response mapping.",
            )


def _check_resource_lists(
    client: httpx.Client,
    config: ScannerConfig,
    result: DoctorResult,
    tokens: dict[str, str],
) -> None:
    seen_resources: set[tuple[str, str, str | None, str | None]] = set()
    for test in config.bola.tests:
        identity_name = _first_identity_name_for_role(config, test.role)
        resource_key = (test.resource.list_method, test.resource.list_path, test.resource.id_field, test.owner_field)
        if identity_name is not None and resource_key not in seen_resources and identity_name in tokens:
            seen_resources.add(resource_key)
            _check_resource_list(
                client,
                result,
                f"BOLA resource '{test.name}'",
                config,
                tokens[identity_name],
                test.resource.list_method,
                test.resource.list_path,
                test.resource.id_field,
                test.owner_field,
            )
    for test in config.bfla.tests:
        if test.resource is None:
            continue
        identity_name = _first_identity_name_for_role(config, test.role)
        resource_key = (
            test.resource.list_method,
            test.resource.list_path,
            test.resource.id_field,
            test.resource.owner_field,
        )
        if identity_name is not None and resource_key not in seen_resources and identity_name in tokens:
            seen_resources.add(resource_key)
            _check_resource_list(
                client,
                result,
                f"BFLA resource '{test.name}'",
                config,
                tokens[identity_name],
                test.resource.list_method,
                test.resource.list_path,
                test.resource.id_field,
                test.resource.owner_field,
            )
    for test in config.property_auth.tests:
        if test.resource is None:
            continue
        identity_name = _first_identity_name_for_role(config, test.role)
        resource_key = (
            test.resource.list_method,
            test.resource.list_path,
            test.resource.id_field,
            test.resource.owner_field,
        )
        if identity_name is not None and resource_key not in seen_resources and identity_name in tokens:
            seen_resources.add(resource_key)
            _check_resource_list(
                client,
                result,
                f"Property resource '{test.name}'",
                config,
                tokens[identity_name],
                test.resource.list_method,
                test.resource.list_path,
                test.resource.id_field,
                test.resource.owner_field,
            )


def _check_resource_list(
    client: httpx.Client,
    result: DoctorResult,
    name: str,
    config: ScannerConfig,
    token: str,
    method: str,
    path: str,
    id_field: str,
    owner_field: str | None,
) -> None:
    if method.upper() != "GET":
        _add(result, name, "warn", f"Skipped live list check for {method.upper()} {path}.", "Use GET list endpoints when possible so doctor can verify resource fields safely.")
        return
    response = client.get(
        path,
        headers=build_auth_headers(config.auth, token),
    )
    if response.status_code != 200:
        _add(result, name, "fail", f"Resource list returned {response.status_code}.", "Check the list path and whether the selected identity has access to its own resources.")
        return
    try:
        body = response.json()
    except ValueError:
        _add(result, name, "fail", "Resource list response is not JSON.", "Return a JSON array so the scanner can select an owned resource.")
        return
    if not isinstance(body, list):
        _add(result, name, "fail", "Resource list response is not a JSON array.", "Configure a list endpoint that returns an array of resources.")
        return
    if not body:
        _add(result, name, "warn", "Resource list is empty.", "Seed test data for the selected identity before scanning.")
        return
    first_object = next((item for item in body if isinstance(item, dict)), None)
    if first_object is None:
        _add(result, name, "fail", "Resource list does not contain JSON objects.", "Return object items containing configured id and owner fields.")
        return
    missing_fields = [field for field in [id_field, owner_field] if field and field not in first_object]
    if missing_fields:
        _add(
            result,
            name,
            "fail",
            f"Missing field(s): {', '.join(missing_fields)}",
            "Update id_field/owner_field or adjust the API response shape.",
        )
        return
    _add(result, name, "pass", f"Resource list contains {id_field}" + (f" and {owner_field}" if owner_field else "") + ".")


def _first_identity_name_for_role(config: ScannerConfig, role: str) -> str | None:
    for name, identity in config.identities.items():
        if identity.role == role:
            return name
    return None
