from apps.reset_demo_data import reset_demo_databases
from apps.hardened_api.database import SessionLocal as HardenedSessionLocal
from apps.hardened_api.models import Order as HardenedOrder
from apps.hardened_api.models import User as HardenedUser
from apps.hardened_api.seed import USER_A_ID as HARDENED_USER_A_ID
from apps.hardened_api.seed import USER_A_ORDER_ID as HARDENED_USER_A_ORDER_ID
from apps.vulnerable_api.database import SessionLocal
from apps.vulnerable_api.models import Order, User, UserRole
from apps.vulnerable_api.seed import USER_A_ID, USER_A_ORDER_ID


def test_reset_demo_databases_restores_vulnerable_seed_data() -> None:
    reset_demo_databases()

    with SessionLocal() as db:
        user = db.get(User, USER_A_ID)
        order = db.get(Order, USER_A_ORDER_ID)
        assert user is not None
        assert order is not None

        user.role = UserRole.ADMIN
        db.delete(order)
        db.commit()

    reset_demo_databases()

    with SessionLocal() as db:
        user = db.get(User, USER_A_ID)
        order = db.get(Order, USER_A_ORDER_ID)

        assert user is not None
        assert user.role == UserRole.CUSTOMER
        assert order is not None
        assert order.owner_id == USER_A_ID


def test_reset_demo_databases_restores_hardened_seed_data() -> None:
    reset_demo_databases()

    with HardenedSessionLocal() as db:
        order = db.get(HardenedOrder, HARDENED_USER_A_ORDER_ID)
        assert order is not None
        db.delete(order)
        db.commit()

    reset_demo_databases()

    with HardenedSessionLocal() as db:
        user = db.get(HardenedUser, HARDENED_USER_A_ID)
        order = db.get(HardenedOrder, HARDENED_USER_A_ORDER_ID)

        assert user is not None
        assert order is not None
        assert order.owner_id == HARDENED_USER_A_ID
