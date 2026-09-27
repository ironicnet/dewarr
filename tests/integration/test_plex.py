import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from app.db.models import User
from app.security import hash_password

pytestmark = pytest.mark.integration


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, message, *args):
        return

    def do_POST(self):
        server = self.server
        if urlsplit(self.path).path != "/api/v2/pins":
            self._send(404, {"error": "not_found"})
            return
        client_id = self.headers.get("X-Plex-Client-Identifier", "")
        if not client_id:
            self._send(400, {"error": "client"})
            return
        server.client_id = client_id
        self._send(200, {"id": server.pin_id, "code": server.code})

    def do_GET(self):
        server = self.server
        path = urlsplit(self.path).path
        if self.headers.get("X-Plex-Client-Identifier") != server.client_id:
            self._send(401, {"error": "client"})
            return
        if path == f"/api/v2/pins/{server.pin_id}":
            token = server.token if server.authorize else None
            self._send(200, {"id": server.pin_id, "code": server.code, "authToken": token})
        elif path == "/api/v2/user":
            if self.headers.get("X-Plex-Token") != server.token:
                self._send(401, {"error": "token"})
                return
            self._send(
                200,
                {"id": server.user_id, "username": server.username, "title": server.title},
            )
        elif path == "/api/v2/resources":
            if self.headers.get("X-Plex-Token") != server.token:
                self._send(401, {"error": "token"})
                return
            self._send(200, server.servers)
        else:
            self._send(404, {"error": "not_found"})

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PlexStub(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server_address[1]}"
        self.reset()

    def reset(self):
        self.client_id = ""
        self.pin_id = 41
        self.code = "ABCDE"
        self.token = "plex-token"
        self.user_id = 42
        self.username = "reader"
        self.title = "Reader"
        self.authorize = True
        self.servers = [
            {
                "name": "Home",
                "provides": "server",
                "clientIdentifier": "abcdef1234",
                "owned": True,
                "accessToken": "server-secret",
            }
        ]


@pytest.fixture
def plex(monkeypatch):
    server = PlexStub()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr("app.domain.plex.api_origin", lambda: server.origin)
    monkeypatch.setattr("app.domain.plex.auth_origin", lambda: server.origin)
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def fragment(location):
    value = urlsplit(location).fragment
    return parse_qs(value[1:] if value.startswith("?") else value)


async def finish_sign_in(client, response):
    assert response.status_code == 303, response.text
    assert urlsplit(response.headers["location"]).path == "/api/auth/finish"
    handoff = " ".join(response.headers.get_list("set-cookie")).lower()
    assert "book_handoff=" in handoff
    assert "samesite=lax" in handoff
    assert "book_session=" not in handoff
    finished = await client.get(response.headers["location"])
    session = " ".join(finished.headers.get_list("set-cookie")).lower()
    assert "book_session=" in session
    assert "samesite=strict" in session
    assert finished.status_code == 303
    assert finished.headers["location"] == "/"
    return finished


async def test_plex_stays_hidden_until_a_server_is_linked(admin, client):
    status = await client.get("/api/auth/plex")
    assert status.status_code == 200
    assert status.json() == {"enabled": False}
    settings = await client.get("/api/auth/plex/settings")
    assert settings.status_code == 200, settings.text
    assert settings.json()["enabled"] is False
    assert settings.json()["machine_id"] == ""
    assert settings.json()["server_name"] == ""
    denied = await client.put(
        "/api/auth/plex/settings",
        json={
            "enabled": True,
            "machine_id": "",
            "auto_register": True,
            "default_role": "member",
        },
    )
    assert denied.status_code == 422


async def test_link_then_sign_in_creates_a_member_without_a_password(admin, client, plex):
    started = await client.get("/api/auth/plex/link")
    assert started.status_code == 302, started.text
    query = fragment(started.headers["location"])
    assert query["code"] == ["ABCDE"]
    assert query["forwardUrl"] == ["http://testserver/api/auth/plex/callback"]
    assert "plex-token" not in started.headers["location"]
    returned = await client.get(
        "/api/auth/plex/callback", headers={"Origin": "https://evil.example"}
    )
    assert returned.status_code == 303, returned.text
    assert returned.headers["location"] == "/settings#accounts"
    assert "server-secret" not in returned.headers["location"]
    pending = await client.get("/api/auth/plex/pending")
    assert pending.status_code == 200, pending.text
    assert pending.json() == {"servers": [{"name": "Home", "machine_id": "abcdef1234"}]}
    assert "server-secret" not in pending.text
    saved = await client.put(
        "/api/auth/plex/settings",
        json={
            "enabled": True,
            "machine_id": "abcdef1234",
            "auto_register": True,
            "default_role": "member",
        },
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["server_name"] == "Home"
    assert saved.json()["enabled"] is True
    client.cookies.clear()
    sign_in = await client.get("/api/auth/plex/start")
    assert sign_in.status_code == 302, sign_in.text
    callback = await client.get("/api/auth/plex/callback")
    await finish_sign_in(client, callback)
    me = await client.get("/api/auth/me")
    assert me.status_code == 200, me.text
    assert me.json()["user"]["username"] == "reader"
    assert me.json()["user"]["display_name"] == "Reader"
    assert me.json()["user"]["role"] == "member"
    password = await client.post(
        "/api/auth/login",
        json={"username": "reader", "password": "a long test password"},
    )
    assert password.status_code == 401
    admin_login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a long test password"},
    )
    assert admin_login.status_code == 200, admin_login.text
    client.headers["X-CSRF-Token"] = admin_login.json()["csrf_token"]
    users = await client.get("/api/auth/users")
    assert sorted(user["username"] for user in users.json()) == ["admin", "reader"]
    again = await client.get("/api/auth/plex/start")
    assert again.status_code == 302
    repeat = await client.get("/api/auth/plex/callback")
    await finish_sign_in(client, repeat)
    repeat_me = await client.get("/api/auth/me")
    assert repeat_me.json()["user"]["id"] == me.json()["user"]["id"]


async def test_unknown_and_unshared_accounts_are_rejected(admin, client, plex):
    await client.get("/api/auth/plex/link")
    await client.get("/api/auth/plex/callback")
    saved = await client.put(
        "/api/auth/plex/settings",
        json={
            "enabled": True,
            "machine_id": "abcdef1234",
            "auto_register": False,
            "default_role": "member",
        },
    )
    assert saved.status_code == 200, saved.text
    client.cookies.clear()
    await client.get("/api/auth/plex/start")
    rejected = await client.get("/api/auth/plex/callback")
    assert rejected.status_code == 303
    assert "plex_error=rejected" in rejected.headers["location"]
    client.headers["X-CSRF-Token"] = (
        await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "a long test password"},
        )
    ).json()["csrf_token"]
    users = await client.get("/api/auth/users")
    assert [user["username"] for user in users.json()] == ["admin"]
    await client.put(
        "/api/auth/plex/settings",
        json={
            "enabled": True,
            "machine_id": "abcdef1234",
            "auto_register": True,
            "default_role": "member",
        },
    )
    plex.servers = [
        {
            "name": "Other",
            "provides": "server",
            "clientIdentifier": "zzzzzzzz",
            "accessToken": "other-secret",
        }
    ]
    client.cookies.clear()
    await client.get("/api/auth/plex/start")
    unshared = await client.get("/api/auth/plex/callback")
    assert "plex_error=rejected" in unshared.headers["location"]
    assert "other-secret" not in unshared.headers["location"]


async def test_admin_can_unlink_plex_when_another_sign_in_method_remains(
    admin, client, database, plex
):
    await client.get("/api/auth/plex/link")
    await client.get("/api/auth/plex/callback")
    await client.put(
        "/api/auth/plex/settings",
        json={
            "enabled": True,
            "machine_id": "abcdef1234",
            "auto_register": True,
            "default_role": "member",
        },
    )
    client.cookies.clear()
    await client.get("/api/auth/plex/start")
    callback = await client.get("/api/auth/plex/callback")
    await finish_sign_in(client, callback)
    plex_user = (await client.get("/api/auth/me")).json()["user"]

    client.cookies.clear()
    admin_login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a long test password"},
    )
    client.headers["X-CSRF-Token"] = admin_login.json()["csrf_token"]

    blocked = await client.delete(f"/api/auth/users/{plex_user['id']}/plex")
    assert blocked.status_code == 409
    assert "another sign-in method" in blocked.json()["detail"]

    async with database() as db:
        user = await db.get(User, plex_user["id"])
        user.password_hash = hash_password("a long reader password")
        await db.commit()

    users = (await client.get("/api/auth/users")).json()
    reader = next(user for user in users if user["id"] == plex_user["id"])
    assert reader["login_methods"] == ["password", "plex"]
    unlinked = await client.delete(f"/api/auth/users/{plex_user['id']}/plex")
    assert unlinked.status_code == 204
