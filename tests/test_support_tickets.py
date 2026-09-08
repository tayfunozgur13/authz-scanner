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


def ticket_id_for_other_customer(client: TestClient, headers: dict[str, str]) -> str:
    response = client.get("/support/tickets", headers=headers)
    assert response.status_code == 200
    tickets = response.json()
    assert tickets
    return tickets[0]["id"]


def test_vulnerable_customer_can_list_other_users_support_tickets() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")

    response = client.get("/support/tickets", headers=headers)

    assert response.status_code == 200
    tickets = response.json()
    assert len(tickets) >= 2
    assert any(ticket["owner_id"] != tickets[0]["owner_id"] for ticket in tickets)


def test_hardened_customer_sees_only_own_support_tickets() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")

    profile = client.get("/users/me", headers=headers).json()
    response = client.get("/support/tickets", headers=headers)

    assert response.status_code == 200
    tickets = response.json()
    assert tickets
    assert all(ticket["owner_id"] == profile["id"] for ticket in tickets)


def test_vulnerable_customer_can_read_other_users_support_ticket_detail() -> None:
    client = TestClient(vulnerable_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    ticket_id = ticket_id_for_other_customer(client, user_a_headers)

    response = client.get(f"/support/tickets/{ticket_id}", headers=user_b_headers)

    assert response.status_code == 200
    assert response.json()["id"] == ticket_id


def test_hardened_blocks_cross_user_support_ticket_detail() -> None:
    client = TestClient(hardened_app)
    user_a_headers = auth_headers(client, "userA@example.com")
    user_b_headers = auth_headers(client, "userB@example.com")
    ticket_id = ticket_id_for_other_customer(client, user_a_headers)

    response = client.get(f"/support/tickets/{ticket_id}", headers=user_b_headers)

    assert response.status_code == 403


def test_vulnerable_customer_response_exposes_internal_notes() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")

    response = client.get("/support/tickets", headers=headers)

    assert response.status_code == 200
    assert "internal_notes" in response.json()[0]


def test_hardened_customer_response_hides_internal_notes() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")

    response = client.get("/support/tickets", headers=headers)

    assert response.status_code == 200
    assert "internal_notes" not in response.json()[0]


def test_vulnerable_customer_can_assign_support_ticket() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "userA@example.com")
    ticket_id = ticket_id_for_other_customer(client, headers)

    response = client.post(f"/support/tickets/{ticket_id}/assign", headers=headers)

    assert response.status_code == 200
    assert response.json()["assigned_support_id"]


def test_hardened_blocks_customer_ticket_assignment() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "userA@example.com")
    ticket_id = ticket_id_for_other_customer(client, headers)

    response = client.post(f"/support/tickets/{ticket_id}/assign", headers=headers)

    assert response.status_code == 403


def test_hardened_allows_support_user_to_assign_ticket() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "support1@example.com")

    response = client.get("/support/tickets", headers=headers)
    assert response.status_code == 200
    ticket_id = response.json()[0]["id"]

    assign_response = client.post(f"/support/tickets/{ticket_id}/assign", headers=headers)

    assert assign_response.status_code == 200
    assert assign_response.json()["assigned_support_id"]


def test_vulnerable_support_user_can_close_ticket_without_manager_approval() -> None:
    client = TestClient(vulnerable_app)
    headers = auth_headers(client, "support1@example.com")

    response = client.get("/support/tickets", headers=headers)
    assert response.status_code == 200
    ticket_id = response.json()[0]["id"]

    close_response = client.post(f"/support/tickets/{ticket_id}/close", headers=headers)

    assert close_response.status_code == 200
    assert close_response.json()["status"] == "closed"


def test_hardened_blocks_support_user_from_closing_ticket() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "support1@example.com")

    response = client.get("/support/tickets", headers=headers)
    assert response.status_code == 200
    ticket_id = response.json()[0]["id"]

    close_response = client.post(f"/support/tickets/{ticket_id}/close", headers=headers)

    assert close_response.status_code == 403


def test_hardened_allows_manager_to_close_ticket() -> None:
    client = TestClient(hardened_app)
    headers = auth_headers(client, "manager1@example.com")

    response = client.get("/support/tickets", headers=headers)
    assert response.status_code == 200
    ticket_id = response.json()[0]["id"]

    close_response = client.post(f"/support/tickets/{ticket_id}/close", headers=headers)

    assert close_response.status_code == 200
    assert close_response.json()["status"] == "closed"
