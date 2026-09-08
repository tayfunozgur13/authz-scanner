from pathlib import Path
from typing import Any

import yaml

from pydantic import BaseModel, Field

from scanner.core.finding import Severity


class TargetConfig(BaseModel):
    name: str
    base_url: str


class AuthConfig(BaseModel):
    login_path: str
    token_field: str
    login_method: str = "POST"
    credential_location: str = "header"
    token_path: str | None = None
    refresh_path: str | None = None
    refresh_method: str = "POST"
    refresh_token_field: str | None = None
    refresh_token_path: str | None = None
    refresh_on_status_codes: list[int] = Field(default_factory=lambda: [401])
    auth_header_name: str = "Authorization"
    auth_scheme: str = "Bearer"
    cookie_name: str | None = None
    login_body: dict[str, Any] = Field(
        default_factory=lambda: {
            "email": "{email}",
            "password": "{password}",
        }
    )
    refresh_body: dict[str, Any] = Field(
        default_factory=lambda: {
            "refresh_token": "{refresh_token}",
        }
    )


class ProfileConfig(BaseModel):
    path: str
    id_field: str


class IdentityConfig(BaseModel):
    email: str
    password: str
    role: str
    access_token: str | None = None
    refresh_token: str | None = None
    auth_values: dict[str, Any] = Field(default_factory=dict)


class BolaResourceConfig(BaseModel):
    list_method: str
    list_path: str
    id_field: str


class BolaAttackConfig(BaseModel):
    method: str
    path_template: str
    path_params: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None


class BolaTestConfig(BaseModel):
    name: str
    role: str
    owner_field: str
    resource: BolaResourceConfig
    attack: BolaAttackConfig
    expected_status: int
    severity: Severity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    business_impact: str | None = None
    review_required: bool = False
    review_notes: list[str] = Field(default_factory=list)


class BolaConfig(BaseModel):
    tests: list[BolaTestConfig]


class BflaResourceConfig(BaseModel):
    list_method: str
    list_path: str
    id_field: str
    owner_field: str | None = None


class BflaAttackConfig(BaseModel):
    method: str
    path_template: str
    json_body: dict[str, Any] | None = None


class BflaTestConfig(BaseModel):
    name: str
    role: str
    attack: BflaAttackConfig
    expected_status: int
    resource: BflaResourceConfig | None = None
    severity: Severity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    business_impact: str | None = None
    review_required: bool = False
    review_notes: list[str] = Field(default_factory=list)


class BflaConfig(BaseModel):
    tests: list[BflaTestConfig]


class PropertyRequestConfig(BaseModel):
    method: str
    path_template: str
    json_body: dict[str, Any] | None = None


class PropertyResourceConfig(BaseModel):
    list_method: str
    list_path: str
    id_field: str
    owner_field: str | None = None


class PropertyPayloadConfig(BaseModel):
    name: str
    json_body: dict[str, Any]
    forbidden_effects: dict[str, Any] = Field(default_factory=dict)
    verification: PropertyRequestConfig | None = None
    severity: Severity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    business_impact: str | None = None
    review_required: bool = False
    review_notes: list[str] = Field(default_factory=list)


class PropertyAuthTestConfig(BaseModel):
    name: str
    type: str
    role: str
    request: PropertyRequestConfig
    resource: PropertyResourceConfig | None = None
    forbidden_fields: list[str] = Field(default_factory=list)
    payloads: list[PropertyPayloadConfig] = Field(default_factory=list)
    severity: Severity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    business_impact: str | None = None
    review_required: bool = False
    review_notes: list[str] = Field(default_factory=list)


class PropertyAuthConfig(BaseModel):
    tests: list[PropertyAuthTestConfig]


class ScannerConfig(BaseModel):
    target: TargetConfig
    auth: AuthConfig
    profile: ProfileConfig
    identities: dict[str, IdentityConfig]
    bola: BolaConfig
    bfla: BflaConfig
    property_auth: PropertyAuthConfig


def load_config(path: str | Path) -> ScannerConfig:
    config_path = Path(path)
    raw_config = yaml.safe_load(config_path.read_text()) or {}
    return ScannerConfig.model_validate(raw_config)
