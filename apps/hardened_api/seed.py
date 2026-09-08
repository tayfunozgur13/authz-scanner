from decimal import Decimal

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from apps.hardened_api.auth import get_password_hash
from apps.hardened_api.models import (
    Invoice,
    Order,
    OrderItem,
    OrderStatus,
    Organization,
    User,
    UserRole,
)


SEED_PASSWORD = "Password123!"

USER_A_ID = "00000000-0000-4000-8000-000000000001"
USER_B_ID = "00000000-0000-4000-8000-000000000002"
ADMIN_ID = "00000000-0000-4000-8000-000000000003"

ORG_A_ID = "30000000-0000-4000-8000-000000000001"
ORG_B_ID = "30000000-0000-4000-8000-000000000002"

USER_A_ORDER_ID = "10000000-0000-4000-8000-000000000001"
USER_B_ORDER_ID = "10000000-0000-4000-8000-000000000002"

USER_A_INVOICE_ID = "40000000-0000-4000-8000-000000000001"
USER_B_INVOICE_ID = "40000000-0000-4000-8000-000000000002"

USER_A_KEYBOARD_ITEM_ID = "20000000-0000-4000-8000-000000000001"
USER_A_HUB_ITEM_ID = "20000000-0000-4000-8000-000000000002"
USER_B_EARBUDS_ITEM_ID = "20000000-0000-4000-8000-000000000003"


def seed_database(db: Session) -> None:
    existing_user = db.scalar(select(User).where(User.email == "userA@example.com"))
    if existing_user is not None:
        seed_invoice_data(db)
        return

    user_a = User(
        id=USER_A_ID,
        email="userA@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.USER,
    )
    user_b = User(
        id=USER_B_ID,
        email="userB@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.USER,
    )
    admin = User(
        id=ADMIN_ID,
        email="admin1@example.com",
        password_hash=get_password_hash(SEED_PASSWORD),
        role=UserRole.ADMIN,
    )

    org_a = Organization(id=ORG_A_ID, name="Acme Security Lab")
    org_b = Organization(id=ORG_B_ID, name="Beta Commerce Lab")

    db.add_all([user_a, user_b, admin, org_a, org_b])
    db.flush()

    user_a_order = Order(
        id=USER_A_ORDER_ID,
        owner_id=user_a.id,
        status=OrderStatus.PENDING,
        total_amount=Decimal("149.98"),
    )
    user_b_order = Order(
        id=USER_B_ORDER_ID,
        owner_id=user_b.id,
        status=OrderStatus.APPROVED,
        total_amount=Decimal("89.50"),
    )

    db.add_all([user_a_order, user_b_order])
    db.flush()

    db.add_all(
        [
            OrderItem(
                id=USER_A_KEYBOARD_ITEM_ID,
                order_id=user_a_order.id,
                product_name="Wireless Keyboard",
                quantity=1,
                unit_price=Decimal("79.99"),
            ),
            OrderItem(
                id=USER_A_HUB_ITEM_ID,
                order_id=user_a_order.id,
                product_name="USB-C Hub",
                quantity=1,
                unit_price=Decimal("69.99"),
            ),
            OrderItem(
                id=USER_B_EARBUDS_ITEM_ID,
                order_id=user_b_order.id,
                product_name="Noise Cancelling Earbuds",
                quantity=1,
                unit_price=Decimal("89.50"),
            ),
        ]
    )
    seed_invoice_data(db)
    db.commit()


def seed_invoice_data(db: Session) -> None:
    if db.get(Invoice, USER_A_INVOICE_ID) is not None:
        return

    org_a = db.get(Organization, ORG_A_ID) or Organization(
        id=ORG_A_ID,
        name="Acme Security Lab",
    )
    org_b = db.get(Organization, ORG_B_ID) or Organization(
        id=ORG_B_ID,
        name="Beta Commerce Lab",
    )
    user_a = db.get(User, USER_A_ID)
    user_b = db.get(User, USER_B_ID)
    if user_a is None or user_b is None:
        return

    db.add_all([org_a, org_b])
    db.flush()
    db.add_all(
        [
            Invoice(
                id=USER_A_INVOICE_ID,
                organization_id=org_a.id,
                owner_id=user_a.id,
                invoice_number="INV-ACME-1001",
                amount_due=Decimal("1299.00"),
                status="open",
            ),
            Invoice(
                id=USER_B_INVOICE_ID,
                organization_id=org_b.id,
                owner_id=user_b.id,
                invoice_number="INV-BETA-2001",
                amount_due=Decimal("845.50"),
                status="open",
            ),
        ]
    )
    db.commit()


def reset_database(db: Session) -> None:
    db.execute(delete(Invoice))
    db.execute(delete(OrderItem))
    db.execute(delete(Order))
    db.execute(delete(Organization))
    db.execute(delete(User))
    db.commit()
    seed_database(db)
