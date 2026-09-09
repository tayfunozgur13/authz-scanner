from typing import Any

import httpx

from scanner.core.config import AuthConfig
from scanner.core.identity import AuthenticatedIdentity, refresh_authenticated_identity
from scanner.core.result import HttpRequestResult


class HttpExecutor:
    def __init__(self, client: httpx.Client, auth_config: AuthConfig | None = None) -> None:
        self.client = client
        self.auth_config = auth_config

    def request(
        self,
        identity: AuthenticatedIdentity,
        method: str,
        path: str,
        json: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpRequestResult:
        request_headers = {
            **identity.authorization_header,
            **(headers or {}),
        }
        response = self._send(method=method, path=path, json=json, headers=request_headers)
        if self._should_refresh(response) and refresh_authenticated_identity(
            self.client,
            self.auth_config,
            identity,
        ):
            request_headers = {
                **identity.authorization_header,
                **(headers or {}),
            }
            response = self._send(method=method, path=path, json=json, headers=request_headers)

        response_json: dict[str, Any] | list[Any] | None = None
        response_text: str | None = None
        try:
            parsed_body = response.json()
        except ValueError:
            response_text = response.text
        else:
            if isinstance(parsed_body, dict | list):
                response_json = parsed_body
            else:
                response_text = str(parsed_body)

        return HttpRequestResult(
            identity_name=identity.name,
            method=method.upper(),
            path=path,
            status_code=response.status_code,
            request_json=json,
            response_json=response_json,
            response_text=response_text,
        )

    def request_without_auth(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpRequestResult:
        response = self._send(method=method, path=path, json=json, headers=headers or {})

        response_json: dict[str, Any] | list[Any] | None = None
        response_text: str | None = None
        try:
            parsed_body = response.json()
        except ValueError:
            response_text = response.text
        else:
            if isinstance(parsed_body, dict | list):
                response_json = parsed_body
            else:
                response_text = str(parsed_body)

        return HttpRequestResult(
            identity_name="unauthenticated",
            method=method.upper(),
            path=path,
            status_code=response.status_code,
            request_json=json,
            response_json=response_json,
            response_text=response_text,
        )

    def _send(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | list[Any] | None,
        headers: dict[str, str],
    ) -> httpx.Response:
        return self.client.request(
            method=method,
            url=path,
            json=json,
            headers=headers,
        )

    def _should_refresh(self, response: httpx.Response) -> bool:
        if self.auth_config is None:
            return False
        return response.status_code in self.auth_config.refresh_on_status_codes
