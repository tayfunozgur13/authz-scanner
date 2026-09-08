from fastapi.testclient import TestClient
from jose import jwt

from apps.hardened_api.auth import ALGORITHM, SECRET_KEY
from apps.hardened_api.main import app as hardened_app
from apps.vulnerable_api.main import app as vulnerable_app


SEED_PASSWORD = "Password123!"


def login(client: TestClient, email: str, password: str = SEED_PASSWORD) -> str:
    response = client.post(
        "/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str)
    assert body["access_token"]
    return body["access_token"]


def test_vulnerable_api_login_and_me_exposes_password_hash() -> None:
    client = TestClient(vulnerable_app)

    token = login(client, "userA@example.com")
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "userA@example.com"
    assert body["role"] == "customer"
    assert "password_hash" in body


def test_hardened_api_login_and_me_hides_password_hash() -> None:
    client = TestClient(hardened_app)

    token = login(client, "userA@example.com")
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "userA@example.com"
    assert body["role"] == "customer"
    assert "password_hash" not in body


def test_access_token_contains_only_identity_and_expiration_claims() -> None:
    client = TestClient(hardened_app)

    token = login(client, "userA@example.com")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    assert set(payload) == {"sub", "exp"}
    assert isinstance(payload["sub"], str)


def test_hardened_api_session_login_sets_cookie_and_allows_me() -> None:
    client = TestClient(hardened_app)

    response = client.post(
        "/auth/session",
        json={
            "email": "userA@example.com",
            "password": SEED_PASSWORD,
        },
    )

    assert response.status_code == 200
    assert response.json() == {"detail": "Session created"}
    assert response.cookies.get("session_id")

    client.cookies.set("session_id", response.cookies["session_id"])
    me_response = client.get("/users/me")

    assert me_response.status_code == 200
    assert me_response.json()["email"] == "userA@example.com"


def test_hardened_api_refresh_endpoint_issues_new_access_token() -> None:
    client = TestClient(hardened_app)

    login_response = client.post(
        "/auth/login-expired-with-refresh",
        json={
            "email": "userA@example.com",
            "password": SEED_PASSWORD,
        },
    )

    assert login_response.status_code == 200
    login_body = login_response.json()
    assert login_body["access_token"]
    assert login_body["refresh_token"]

    expired_response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {login_body['access_token']}"},
    )
    assert expired_response.status_code == 401

    refresh_response = client.post(
        "/auth/refresh",
        json={"refresh_token": login_body["refresh_token"]},
    )

    assert refresh_response.status_code == 200
    refresh_body = refresh_response.json()
    assert refresh_body["access_token"]
    assert refresh_body["refresh_token"]

    me_response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {refresh_body['access_token']}"},
    )

    assert me_response.status_code == 200
    assert me_response.json()["email"] == "userA@example.com"


def test_hardened_api_rejects_refresh_token_as_bearer_access_token() -> None:
    client = TestClient(hardened_app)

    login_response = client.post(
        "/auth/login-with-refresh",
        json={
            "email": "userA@example.com",
            "password": SEED_PASSWORD,
        },
    )

    assert login_response.status_code == 200
    refresh_token = login_response.json()["refresh_token"]

    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )

    assert response.status_code == 401


def test_vulnerable_api_session_login_sets_cookie_and_allows_me() -> None:
    client = TestClient(vulnerable_app)

    response = client.post(
        "/auth/session",
        json={
            "email": "userA@example.com",
            "password": SEED_PASSWORD,
        },
    )

    assert response.status_code == 200
    assert response.cookies.get("session_id")

    client.cookies.set("session_id", response.cookies["session_id"])
    me_response = client.get("/users/me")

    assert me_response.status_code == 200
    assert me_response.json()["email"] == "userA@example.com"


def test_vulnerable_api_refresh_endpoint_issues_new_access_token() -> None:
    client = TestClient(vulnerable_app)

    login_response = client.post(
        "/auth/login-expired-with-refresh",
        json={
            "email": "userA@example.com",
            "password": SEED_PASSWORD,
        },
    )

    assert login_response.status_code == 200
    login_body = login_response.json()

    expired_response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {login_body['access_token']}"},
    )
    assert expired_response.status_code == 401

    refresh_response = client.post(
        "/auth/refresh",
        json={"refresh_token": login_body["refresh_token"]},
    )

    assert refresh_response.status_code == 200
    refresh_body = refresh_response.json()
    assert refresh_body["access_token"]
    assert refresh_body["refresh_token"]

    me_response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {refresh_body['access_token']}"},
    )

    assert me_response.status_code == 200
    assert me_response.json()["email"] == "userA@example.com"


def test_login_rejects_wrong_password() -> None:
    response = TestClient(hardened_app).post(
        "/auth/login",
        json={
            "email": "userA@example.com",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401


def test_me_requires_bearer_token() -> None:
    response = TestClient(hardened_app).get("/users/me")

    assert response.status_code == 401
