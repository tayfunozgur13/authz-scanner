from typing import Any

from pydantic import BaseModel, Field

from scanner.core.config import AuthConfig, IdentityConfig, ScannerConfig


class AuthenticatedIdentity(BaseModel):
    name: str
    email: str
    role: str
    access_token: str
    auth_headers: dict[str, str] = Field(default_factory=dict)

    @property
    def authorization_header(self) -> dict[str, str]:
        if self.auth_headers:
            return self.auth_headers
        return {"Authorization": f"Bearer {self.access_token}"}


class IdentityLoginError(RuntimeError):
    pass


def get_value_by_path(data: Any, dotted_path: str) -> Any:
    current_value = data
    for segment in dotted_path.split("."):
        if isinstance(current_value, dict):
            current_value = current_value.get(segment)
            continue
        if isinstance(current_value, list) and segment.isdigit():
            index = int(segment)
            if index >= len(current_value):
                return None
            current_value = current_value[index]
            continue
        return None
    return current_value


def render_login_body(template: Any, name: str, identity: IdentityConfig) -> Any:
    values = {
        "name": name,
        "email": identity.email,
        "password": identity.password,
        "role": identity.role,
        **identity.auth_values,
    }
    if isinstance(template, str):
        try:
            return template.format(**values)
        except KeyError as exc:
            missing_key = exc.args[0]
            raise IdentityLoginError(
                f"Login body references missing auth value '{missing_key}' for identity '{name}'"
            ) from exc
    if isinstance(template, dict):
        return {
            key: render_login_body(value, name, identity)
            for key, value in template.items()
        }
    if isinstance(template, list):
        return [render_login_body(value, name, identity) for value in template]
    return template


def build_auth_headers(auth_config: AuthConfig, access_token: str) -> dict[str, str]:
    if auth_config.auth_scheme:
        header_value = f"{auth_config.auth_scheme} {access_token}"
    else:
        header_value = access_token
    return {auth_config.auth_header_name: header_value}


def login_identity(
    client,
    auth_config: AuthConfig,
    name: str,
    identity: IdentityConfig,
) -> AuthenticatedIdentity:
    if identity.access_token:
        return AuthenticatedIdentity(
            name=name,
            email=identity.email,
            role=identity.role,
            access_token=identity.access_token,
            auth_headers=build_auth_headers(auth_config, identity.access_token),
        )

    response = client.request(
        auth_config.login_method,
        auth_config.login_path,
        json=render_login_body(auth_config.login_body, name, identity),
    )

    if response.status_code != 200:
        raise IdentityLoginError(
            f"Login failed for identity '{name}' with status {response.status_code}"
        )

    try:
        body = response.json()
    except ValueError as exc:
        raise IdentityLoginError(f"Login response for identity '{name}' was not valid JSON") from exc

    token_path = auth_config.token_path or auth_config.token_field
    access_token = get_value_by_path(body, token_path)
    if not isinstance(access_token, str) or not access_token:
        raise IdentityLoginError(
            f"Login response for identity '{name}' did not include token path '{token_path}'"
        )

    return AuthenticatedIdentity(
        name=name,
        email=identity.email,
        role=identity.role,
        access_token=access_token,
        auth_headers=build_auth_headers(auth_config, access_token),
    )


def login_all_identities(client, config: ScannerConfig) -> dict[str, AuthenticatedIdentity]:
    return {
        name: login_identity(
            client=client,
            auth_config=config.auth,
            name=name,
            identity=identity,
        )
        for name, identity in config.identities.items()
    }
