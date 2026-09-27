import asyncio

import httpx
import pytest
from sqlalchemy import func, select

from app.db.models import User

pytestmark = pytest.mark.integration


async def test_bootstrap_is_once_even_when_concurrent(client, database):
    body = {
        "username": "admin",
        "password": "a long test password",
        "display_name": "Test admin",
    }
    responses = await asyncio.gather(
        *[client.post("/api/auth/bootstrap", json=body) for _ in range(4)]
    )
    assert sorted(response.status_code for response in responses) == [201, 409, 409, 409]
    async with database() as db:
        assert await db.scalar(select(func.count()).select_from(User)) == 1


async def test_first_account_requires_trusted_origin_without_a_setup_token(client):
    body = {
        "username": "admin",
        "password": "a long test password",
        "display_name": "Test admin",
    }
    assert (
        await client.post(
            "/api/auth/bootstrap", json=body, headers={"Origin": "https://untrusted.invalid"}
        )
    ).status_code == 403
    response = await client.post("/api/auth/bootstrap", json=body)
    assert response.status_code == 201
    assert response.json()["user"]["role"] == "admin"
    assert (await client.get("/api/auth/setup")).json() == {"needs_setup": False}
    assert (await client.post("/api/auth/bootstrap", json=body)).status_code == 409


async def test_session_csrf_and_revocation(client, admin):
    response = await client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "password" not in response.text
    assert (
        await client.post("/api/auth/logout", headers={"X-CSRF-Token": "incorrect"})
    ).status_code == 403
    previous = client.cookies.get("book_session")
    assert (await client.post("/api/auth/logout")).status_code == 204
    client.cookies.set("book_session", previous)
    assert (await client.get("/api/auth/me")).status_code == 401
    client.cookies.clear()
    login = await client.post(
        "/api/auth/login",
        json={
            "username": "ADMIN",
            "password": "a long test password",
        },
    )
    assert login.status_code == 200
    assert client.cookies.get("book_session") != previous


async def test_viewer_cannot_administer(client, admin):
    assert (
        await client.post(
            "/api/auth/users",
            json={
                "username": "viewer",
                "display_name": "Reader",
                "role": "viewer",
                "password": "a long viewer password",
            },
        )
    ).status_code == 201
    from app.main import create_app

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()),
        base_url="http://testserver",
        headers={"Origin": "http://testserver"},
    ) as viewer:
        login = await viewer.post(
            "/api/auth/login",
            json={
                "username": "viewer",
                "password": "a long viewer password",
            },
        )
        viewer.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        assert (await viewer.get("/api/auth/users")).status_code == 403
        assert (
            await viewer.post("/api/system/probe", headers={"Idempotency-Key": "viewer-probe"})
        ).status_code == 403


async def test_login_budget_persists_failed_requests(client, admin):
    for _ in range(15):
        response = await client.post(
            "/api/auth/login",
            json={
                "username": "unknown",
                "password": "a wrong long password",
            },
        )
        assert response.status_code == 401
    response = await client.post(
        "/api/auth/login",
        json={
            "username": "unknown",
            "password": "a wrong long password",
        },
    )
    assert response.status_code == 429


async def test_admin_can_remove_account_without_deleting_historical_user_row(client, admin, database):
    created = await client.post(
        "/api/auth/users",
        json={
            "username": "reader",
            "display_name": "Reader",
            "role": "member",
            "password": "a long reader password",
        },
    )
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]

    removed = await client.delete(f"/api/auth/users/{user_id}")
    assert removed.status_code == 204, removed.text
    assert all(user["id"] != user_id for user in (await client.get("/api/auth/users")).json())
    assert (
        await client.post(
            "/api/auth/login",
            json={"username": "reader", "password": "a long reader password"},
        )
    ).status_code == 401

    async with database() as db:
        user = await db.get(User, user_id)
        assert user is not None
        assert user.active is False
        assert user.username == f"deleted-{user.id}"
        assert user.display_name == "Deleted user"
        assert user.password_hash is None
        assert user.email is None
        assert user.onboarding["status"] == "deleted"


async def test_admin_cannot_remove_own_account(client, admin):
    me = (await client.get("/api/auth/me")).json()["user"]
    response = await client.delete(f"/api/auth/users/{me['id']}")
    assert response.status_code == 409
    assert response.json()["detail"] == "You cannot remove your own account"
