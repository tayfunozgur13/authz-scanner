import json
import shlex
from typing import Any
from urllib.parse import urljoin


SENSITIVE_CURL_FIELDS = {
    "access_token",
    "api_key",
    "card_number",
    "credit_card",
    "cvv",
    "hashed_password",
    "mfa_secret",
    "national_id",
    "otp_secret",
    "password",
    "password_hash",
    "private_key",
    "refresh_token",
    "reset_token",
    "secret",
    "ssn",
    "token",
}


def redact_curl_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key in SENSITIVE_CURL_FIELDS else redact_curl_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_curl_json(item) for item in value]
    return value


def placeholder_for_header(identity_name: str, header_name: str, header_value: str) -> str:
    placeholder = f"<{identity_name}_{header_name.lower().replace('-', '_')}>"
    if header_name.lower() == "authorization":
        scheme, _, _ = header_value.partition(" ")
        if scheme:
            return f"{scheme} <{identity_name}_token>"
    return placeholder


def build_auth_header_args(identity: Any) -> list[str]:
    if identity.auth_cookies:
        cookie_value = "; ".join(
            f"{name}=<{identity.name}_{name}>"
            for name in identity.auth_cookies
        )
        return ["-H", f"Cookie: {cookie_value}"]

    headers = identity.auth_headers or identity.authorization_header
    return [
        item
        for header_name, header_value in headers.items()
        for item in [
            "-H",
            f"{header_name}: {placeholder_for_header(identity.name, header_name, header_value)}",
        ]
    ]


def build_curl_command(result: Any, evidence: Any) -> str:
    observed = evidence.observed
    identity = result.identities.get(observed.identity_name)
    url = urljoin(result.base_url.rstrip("/") + "/", observed.path.lstrip("/"))
    args = ["curl", "-i", "-X", observed.method.upper(), url]

    if identity is not None:
        args.extend(build_auth_header_args(identity))

    if observed.request_json is not None:
        args.extend(
            [
                "-H",
                "Content-Type: application/json",
                "--data",
                json.dumps(redact_curl_json(observed.request_json), separators=(",", ":")),
            ]
        )

    return " ".join(shlex.quote(str(arg)) for arg in args)
