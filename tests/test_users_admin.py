from fastapi.testclient import TestClient

from apps.hardened_api.database import SessionLocal as HardenedSessionLocal
from apps.hardened_api.main import app as hardened_app
from apps.hardened_api.models import User as HardenedUser
from apps.hardened_api.models import UserRole as HardenedUserRole
from apps.vulnerable_api.database import SessionLocal as VulnerableSessionLocal
from apps.vulnerable_api.main import app as vulnerable_app
from apps.vulnerable_api.models import User as VulnerableUser
from apps.vulnerable_api.models import UserRole as VulnerableUserRole


SEED_PASSWORD = "Password123!"


def auth_headers(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/login",
        json={
            "email": email,
            "password": SEED_PASSWORD,
        },
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def current_user(client: TestClient, headers: dict[str, str]) -> dict:
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    return response.json()


def reset_vulnerable_user_a() -> None:
    with VulnerableSessionLocal() as db:
        user = db.query(VulnerableUser).filter_by(email="userA@example.com").one_or_none()
        if user is None:
            user = db.query(VulnerableUser).filter_by(email="userA-renamed@example.com").one()
        user.email = "userA@example.com"
        user.role = VulnerableUserRole.CUSTOMER
        db.commit()


def reset_hardened_user_a() -> None:
    with HardenedSessionLocal() as db:
        user = db.query(HardenedUser).filter_by(email="userA@example.com").one_or_none()
        if user is None:
            user = db.query(HardenedUser).filter_by(email="userA-renamed@example.com").one()
        user.email = "userA@example.com"
        user.role = HardenedUserRole.CUSTOMER
        db.commit()


def test_vulnerable_allows_regular_user_to_list_admin_users() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")

    response = client.get("/admin/users", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 3
    assert any(user["role"] == "admin" for user in body)
    assert any("password_hash" in user for user in body)


def test_hardened_blocks_regular_user_from_admin_users() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")

    response = client.get("/admin/users", headers=headers)

    assert response.status_code == 403


def test_hardened_allows_admin_to_list_users_without_password_hashes() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "admin1@example.com")

    response = client.get("/admin/users", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 3
    assert all("password_hash" not in user for user in body)


def test_vulnerable_allows_cross_user_profile_update() -> None:
    client = TestClient(vulnerable_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a = current_user(client, user_a_headers)

    try:
        response = client.put(
            f"/users/{user_a['id']}",
            headers=user_b_headers,
            json={"email": "userA-renamed@example.com"},
        )

        assert response.status_code == 200
        assert response.json()["email"] == "userA-renamed@example.com"
    finally:
        reset_vulnerable_user_a()


def test_hardened_blocks_cross_user_profile_update() -> None:
    client = TestClient(hardened_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a = current_user(client, user_a_headers)

    response = client.put(
        f"/users/{user_a['id']}",
        headers=user_b_headers,
        json={"email": "userA-renamed@example.com"},
    )

    assert response.status_code == 403
    reset_hardened_user_a()


def test_vulnerable_allows_role_mass_assignment() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")
    user_a = current_user(client, headers)

    try:
        response = client.put(
            f"/users/{user_a['id']}",
            headers=headers,
            json={"role": "admin"},
        )

        assert response.status_code == 200
        assert response.json()["role"] == "admin"
    finally:
        reset_vulnerable_user_a()


def test_hardened_ignores_role_mass_assignment() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")
    user_a = current_user(client, headers)

    response = client.put(
        f"/users/{user_a['id']}",
        headers=headers,
        json={"role": "admin"},
    )

    assert response.status_code == 200
    assert response.json()["role"] == "customer"
    reset_hardened_user_a()
