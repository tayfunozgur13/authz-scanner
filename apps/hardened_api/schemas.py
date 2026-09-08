from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel

from apps.hardened_api.models import OrderStatus, UserRole


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenPairResponse(TokenResponse):
    refresh_token: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserPublic(BaseModel):
    id: str
    email: str
    role: UserRole

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    email: str | None = None


class OrganizationPublic(BaseModel):
    id: str
    name: str

    model_config = {"from_attributes": True}


class InvoicePublic(BaseModel):
    id: str
    organization_id: str
    owner_id: str
    invoice_number: str
    amount_due: Decimal
    status: str

    model_config = {"from_attributes": True}


class OrderItemCreate(BaseModel):
    product_name: str
    quantity: int
    unit_price: Decimal


class OrderItemPublic(OrderItemCreate):
    id: str
    order_id: str

    model_config = {"from_attributes": True}


class OrderPublic(BaseModel):
    id: str
    owner_id: str
    status: OrderStatus
    total_amount: Decimal
    created_at: datetime
    items: list[OrderItemPublic] = []

    model_config = {"from_attributes": True}


class OrderCreate(BaseModel):
    items: list[OrderItemCreate]


class OrderUpdate(BaseModel):
    total_amount: Decimal | None = None
