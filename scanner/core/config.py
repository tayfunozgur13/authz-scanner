from pathlib import Path
from typing import Any

import yaml

from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    name: str
    base_url: str


class AuthConfig(BaseModel):
    login_path: str
    token_field: str


class ProfileConfig(BaseModel):
    path: str
    id_field: str


class IdentityConfig(BaseModel):
    email: str
    password: str
    role: str


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
    business_impact: str | None = None


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
    business_impact: str | None = None


class BflaConfig(BaseModel):
    tests: list[BflaTestConfig]


class PropertyRequestConfig(BaseModel):
    method: str
    path_template: str
    json_body: dict[str, Any] | None = None


class PropertyPayloadConfig(BaseModel):
    name: str
    json_body: dict[str, Any]
    forbidden_effects: dict[str, Any] = Field(default_factory=dict)
    verification: PropertyRequestConfig | None = None
    business_impact: str | None = None


class PropertyAuthTestConfig(BaseModel):
    name: str
    type: str
    role: str
    request: PropertyRequestConfig
    forbidden_fields: list[str] = Field(default_factory=list)
    payloads: list[PropertyPayloadConfig] = Field(default_factory=list)
    business_impact: str | None = None


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
