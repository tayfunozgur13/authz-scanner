from fastapi.testclient import TestClient

from apps.hardened_api.main import app as hardened_app
from apps.vulnerable_api.main import app as vulnerable_app


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


def get_current_user(client: TestClient, headers: dict[str, str]) -> dict:
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
    return response.json()


def get_owned_invoice(client: TestClient, headers: dict[str, str]) -> dict:
    current_user = get_current_user(client, headers)
    response = client.get("/invoices", headers=headers)
    assert response.status_code == 200
    for invoice in response.json():
        if invoice["owner_id"] == current_user["id"]:
            return invoice
    raise AssertionError("Expected at least one owned invoice")


def test_vulnerable_invoice_list_leaks_other_users_invoices() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")
    current_user = get_current_user(client, headers)

    response = client.get("/invoices", headers=headers)

    assert response.status_code == 200
    assert any(invoice["owner_id"] != current_user["id"] for invoice in response.json())


def test_hardened_invoice_list_returns_only_own_invoices_for_regular_user() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")
    current_user = get_current_user(client, headers)

    response = client.get("/invoices", headers=headers)

    assert response.status_code == 200
    assert response.json()
    assert all(invoice["owner_id"] == current_user["id"] for invoice in response.json())


def test_vulnerable_allows_cross_user_invoice_detail_access() -> None:
    client = TestClient(vulnerable_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_invoice = get_owned_invoice(client, user_a_headers)

    response = client.get(f"/invoices/{user_a_invoice['id']}", headers=user_b_headers)

    assert response.status_code == 200
    assert response.json()["id"] == user_a_invoice["id"]


def test_hardened_blocks_cross_user_invoice_detail_access() -> None:
    client = TestClient(hardened_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_invoice = get_owned_invoice(client, user_a_headers)

    response = client.get(f"/invoices/{user_a_invoice['id']}", headers=user_b_headers)

    assert response.status_code == 403


def test_vulnerable_allows_cross_tenant_invoice_detail_access() -> None:
    client = TestClient(vulnerable_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_invoice = get_owned_invoice(client, user_a_headers)

    response = client.get(
        (
            f"/organizations/{user_a_invoice['organization_id']}"
            f"/invoices/{user_a_invoice['id']}"
        ),
        headers=user_b_headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == user_a_invoice["id"]


def test_hardened_blocks_cross_tenant_invoice_detail_access() -> None:
    client = TestClient(hardened_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    user_a_invoice = get_owned_invoice(client, user_a_headers)

    response = client.get(
        (
            f"/organizations/{user_a_invoice['organization_id']}"
            f"/invoices/{user_a_invoice['id']}"
        ),
        headers=user_b_headers,
    )

    assert response.status_code == 403
