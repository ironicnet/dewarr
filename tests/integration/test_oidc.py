import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwk, jwt
from sqlalchemy import func, select

from app.db.models import OidcIdentity, User
from app.main import create_app

pytestmark = pytest.mark.integration


def rsa_pair(kid):
    raw = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = jwk.import_key(
        raw.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "RSA",
        {"kid": kid, "use": "sig", "alg": "RS256"},
    )
    public = jwk.import_key(
        raw.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        "RSA",
        {"kid": kid, "use": "sig", "alg": "RS256"},
    )
    return private, public.as_dict()


PRIVATE, PUBLIC = rsa_pair("test")
OTHER, _ = rsa_pair("other")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, message, *args):
        return

    def do_GET(self):
        path = urlsplit(self.path).path
        server = self.server
        if path == "/.well-known/openid-configuration":
            self._send(
                200,
                {
                    "issuer": server.issuer,
                    "authorization_endpoint": server.issuer + "/authorize",
                    "token_endpoint": server.issuer + "/token",
                    "userinfo_endpoint": server.issuer + "/userinfo",
                    "jwks_uri": server.issuer + "/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        elif path == "/jwks":
            self._send(200, {"keys": [PUBLIC]})
        elif path == "/userinfo":
            if self.headers.get("Authorization") != "Bearer access-token":
                self._send(401, {"error": "invalid_token"})
                return
            self._send(200, server.profile())
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        server = self.server
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        expected = "Basic " + base64.b64encode(b"dewarr:test-client-secret").decode()
        verifier = form.get("code_verifier", [""])[0]
        if (
            server.reject_token
            or self.headers.get("Authorization") != expected
            or form.get("redirect_uri", [""])[0] != "http://testserver/api/auth/oidc/callback"
            or create_s256_code_challenge(verifier) != server.expected_challenge
        ):
            self._send(400, {"error": "invalid_grant"})
            return
        now = int(time.time())
        token = jwt.encode(
            {"alg": "RS256", "kid": "test"},
            {
                "iss": server.issuer,
                "sub": server.sub,
                "aud": server.aud,
                "exp": now + 300,
                "iat": now,
                "nonce": server.expected_nonce,
                **server.profile(),
            },
            server.signing_key,
        )
        self._send(200, {"access_token": "access-token", "id_token": token, "token_type": "Bearer"})

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Provider(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.issuer = f"http://127.0.0.1:{self.server_address[1]}"
        self.reset()

    def reset(self):
        self.expected_challenge = None
        self.expected_nonce = None
        self.sub = "subject-1"
        self.email = "reader@example.com"
        self.email_verified = True
        self.preferred_username = "reader"
        self.name = "Reader"
        self.groups = ["members"]
        self.aud = "dewarr"
        self.reject_token = False
        self.signing_key = PRIVATE

    def profile(self):
        claims = {
            "sub": self.sub,
            "email": self.email,
            "preferred_username": self.preferred_username,
            "name": self.name,
            "groups": self.groups,
        }
        if self.email_verified is not None:
            claims["email_verified"] = self.email_verified
        return claims


@pytest.fixture
def idp():
    server = Provider()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


async def save_provider(client, idp, **overrides):
    discovered = await client.post("/api/auth/oidc/discover", json={"issuer": idp.issuer})
    assert discovered.status_code == 200, discovered.text
    body = {
        "enabled": True,
        "label": "Pocket ID",
        "client_id": "dewarr",
        "client_secret": "test-client-secret",
        "match_existing": "off",
        "auto_register": False,
        "default_role": "member",
        "group_claim": "",
        "admin_group": "",
        "member_group": "",
        "viewer_group": "",
        **discovered.json(),
    }
    body.update(overrides)
    saved = await client.put("/api/auth/oidc/settings", json=body)
    assert saved.status_code == 200, saved.text
    assert "client_secret" not in saved.json()
    assert saved.json()["secret_set"] is True
    assert saved.json()["redirect_uri"] == "http://testserver/api/auth/oidc/callback"
    return saved.json()


async def start(client, idp):
    response = await client.get("/api/auth/oidc/start")
    assert response.status_code == 302, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    idp.expected_challenge = query["code_challenge"][0]
    idp.expected_nonce = query["nonce"][0]
    assert query["code_challenge_method"] == ["S256"]
    return query["state"][0]


async def callback(client, state, *, origin=None):
    headers = {"Origin": origin} if origin else None
    response = await client.get(
        "/api/auth/oidc/callback", params={"code": "once", "state": state}, headers=headers
    )
    location = response.headers.get("location", "")
    if response.status_code == 303 and urlsplit(location).path == "/api/auth/finish":
        handoff = " ".join(response.headers.get_list("set-cookie")).lower()
        assert "book_handoff=" in handoff
        assert "samesite=lax" in handoff
        assert "book_session=" not in handoff
        response = await client.get(location)
        session = " ".join(response.headers.get_list("set-cookie")).lower()
        assert "book_session=" in session
        assert "samesite=strict" in session
    return response


async def user_count(database):
    async with database() as db:
        return await db.scalar(select(func.count()).select_from(User))


async def test_provider_stays_hidden_until_enabled(client, admin, idp):
    public = await client.get("/api/auth/oidc")
    assert public.json() == {"enabled": False}
    assert (await client.get("/api/auth/oidc/start")).status_code == 404
    settings = await client.get("/api/auth/oidc/settings")
    assert settings.status_code == 200, settings.text
    assert settings.json()["enabled"] is False
    assert settings.json()["label"] == "your identity provider"
    assert settings.json()["redirect_uri"] == "http://testserver/api/auth/oidc/callback"
    assert settings.json()["secret_set"] is False
    assert (
        await client.post("/api/auth/oidc/discover", json={"issuer": "https://id.example"})
    ).status_code == 422
    saved = await save_provider(client, idp, enabled=False, client_secret="test-client-secret")
    assert saved["enabled"] is False
    assert (await client.get("/api/auth/oidc")).json() == {"enabled": False}


async def test_sign_in_links_subject_and_keeps_local_login(client, admin, database, idp):
    await save_provider(client, idp, auto_register=True)
    kept = await client.put(
        "/api/auth/oidc/settings",
        json={
            "enabled": True,
            "label": "Pocket ID",
            "issuer": idp.issuer,
            "authorization_endpoint": idp.issuer + "/authorize",
            "token_endpoint": idp.issuer + "/token",
            "userinfo_endpoint": idp.issuer + "/userinfo",
            "jwks_uri": idp.issuer + "/jwks",
            "client_id": "dewarr",
            "signing_algorithm": "RS256",
            "match_existing": "off",
            "auto_register": True,
            "default_role": "member",
            "group_claim": "",
            "admin_group": "",
            "member_group": "",
            "viewer_group": "",
        },
    )
    assert kept.status_code == 200, kept.text
    state = await start(client, idp)
    response = await callback(client, state, origin="http://127.0.0.1:9")
    assert response.status_code == 303
    assert urlsplit(response.headers["location"]).path == "/"
    assert "oidc_error" not in response.headers["location"]
    me = await client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "reader"
    assert me.json()["user"]["role"] == "member"
    async with database() as db:
        user = await db.scalar(select(User).where(User.username == "reader"))
        assert user.password_hash is None
        assert user.email == "reader@example.com"
        assert await db.scalar(select(func.count()).select_from(OidcIdentity)) == 1
    assert (
        await client.post(
            "/api/auth/login",
            json={"username": "reader", "password": "a long test password"},
        )
    ).status_code == 401
    assert (
        await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "a long test password"},
        )
    ).status_code == 200


async def test_rejected_callbacks_do_not_create_accounts(client, admin, database, idp):
    await save_provider(client, idp, auto_register=True)
    state = await start(client, idp)
    mismatch = await callback(client, "wrong-state")
    assert mismatch.status_code == 303
    assert "oidc_error=mismatch" in mismatch.headers["location"]

    async def rejected(**changes):
        idp.reset()
        state = await start(client, idp)
        for name, value in changes.items():
            setattr(idp, name, value)
        assert "oidc_error=rejected" in (await callback(client, state)).headers["location"]

    await rejected(expected_nonce="not-the-nonce")
    await rejected(expected_challenge="not-the-challenge")
    await rejected(signing_key=OTHER)
    await rejected(aud="other-client")
    await rejected(email_verified=False)
    await rejected(email_verified="false")
    await rejected(email_verified=0)
    idp.reset()
    await save_provider(client, idp, auto_register=False)
    state = await start(client, idp)
    assert "oidc_error=rejected" in (await callback(client, state)).headers["location"]
    assert await user_count(database) == 1
    assert (await client.get("/api/auth/me")).json()["user"]["username"] == "admin"


async def test_username_and_email_match_once(client, admin, database, idp):
    created = await client.post(
        "/api/auth/users",
        json={
            "username": "reader",
            "display_name": "Existing reader",
            "password": "a long reader password",
            "role": "member",
        },
    )
    assert created.status_code == 201, created.text
    await save_provider(client, idp, match_existing="username", auto_register=True)
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303
    assert (await client.get("/api/auth/me")).json()["user"]["username"] == "reader"
    async with database() as db:
        user = await db.scalar(select(User).where(User.username == "reader"))
        assert user.password_hash
    idp.sub = "subject-2"
    state = await start(client, idp)
    assert "oidc_error=rejected" in (await callback(client, state)).headers["location"]
    assert await user_count(database) == 2

    client.cookies.clear()
    login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a long test password"},
    )
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    async with database() as db, db.begin():
        member = User(
            username="person@example.com",
            display_name="Person",
            password_hash="unused",
            role="viewer",
        )
        db.add(member)
    idp.reset()
    idp.sub = "email-subject"
    idp.email = "person@example.com"
    idp.preferred_username = "someone-else"
    await save_provider(client, idp, match_existing="email", auto_register=True)
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303
    me = await client.get("/api/auth/me")
    assert me.json()["user"]["username"] == "person@example.com"
    assert me.json()["user"]["role"] == "viewer"
    idp.sub = "email-subject-2"
    state = await start(client, idp)
    assert "oidc_error=rejected" in (await callback(client, state)).headers["location"]


async def test_unverified_email_does_not_attach_an_existing_account(client, admin, database, idp):
    async with database() as db, db.begin():
        db.add(
            User(
                username="person@example.com",
                display_name="Person",
                password_hash="unused",
                role="admin",
            )
        )
    await save_provider(client, idp, match_existing="email", auto_register=True)
    idp.email = "person@example.com"
    idp.email_verified = None
    idp.preferred_username = "someone-else"
    state = await start(client, idp)
    signed_in = await callback(client, state)
    assert signed_in.status_code == 303
    assert "oidc_error" not in signed_in.headers["location"]
    me = await client.get("/api/auth/me")
    assert me.json()["user"]["username"] != "person@example.com"
    assert me.json()["user"]["role"] == "member"
    async with database() as db:
        owner = await db.scalar(select(User).where(User.username == "person@example.com"))
        created = await db.scalar(select(User).where(User.username == "someone-else"))
        assert owner.role == "admin"
        assert owner.email is None
        assert created.email is None
        linked = await db.scalar(
            select(OidcIdentity.user_id).where(OidcIdentity.user_id == owner.id)
        )
        assert linked is None
        assert created.password_hash is None


async def test_username_match_does_not_attach_an_administrator(client, admin, database, idp):
    await save_provider(client, idp, match_existing="username", auto_register=True)
    idp.preferred_username = "admin"
    state = await start(client, idp)
    assert "oidc_error=rejected" in (await callback(client, state)).headers["location"]
    assert await user_count(database) == 1
    assert (await client.get("/api/auth/me")).json()["user"]["username"] == "admin"
    async with database() as db:
        assert await db.scalar(select(func.count()).select_from(OidcIdentity)) == 0


async def test_groups_do_not_change_password_accounts(client, admin, idp):
    created = await client.post(
        "/api/auth/users",
        json={
            "username": "reader",
            "display_name": "Existing reader",
            "password": "a long reader password",
            "role": "member",
        },
    )
    assert created.status_code == 201, created.text
    await save_provider(
        client,
        idp,
        match_existing="username",
        auto_register=False,
        group_claim="groups",
        group_scope="groups",
        admin_group="dewarr-admins",
        member_group="dewarr-members",
        viewer_group="dewarr-viewers",
    )
    idp.preferred_username = "reader"
    idp.groups = ["dewarr-admins"]
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303
    me = await client.get("/api/auth/me")
    assert me.json()["user"]["username"] == "reader"
    assert me.json()["user"]["role"] == "member"


async def test_issuer_change_keeps_links_only_on_the_same_socket(client, admin, database, idp):
    await save_provider(client, idp, auto_register=True)
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303

    async def save_issuer(issuer: str):
        client.cookies.clear()
        login = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "a long test password"},
        )
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        current = (await client.get("/api/auth/oidc/settings")).json()
        current.pop("secret_set")
        current.pop("redirect_uri")
        current.update(
            {
                "issuer": issuer,
                "authorization_endpoint": issuer + "/authorize",
                "token_endpoint": issuer + "/token",
                "userinfo_endpoint": issuer + "/userinfo",
                "jwks_uri": issuer + "/jwks",
            }
        )
        updated = await client.put("/api/auth/oidc/settings", json=current)
        assert updated.status_code == 200, updated.text

    corrected = idp.issuer + "/application/o/dewarr"
    await save_issuer(corrected)
    async with database() as db:
        identity = await db.scalar(select(OidcIdentity))
        assert identity.issuer == corrected
        assert identity.subject == "subject-1"
    other_port = 9 if urlsplit(idp.issuer).port != 9 else 10
    await save_issuer(f"http://127.0.0.1:{other_port}/application/o/dewarr")
    async with database() as db:
        assert await db.scalar(select(OidcIdentity)) is None
    assert await user_count(database) == 2


async def test_groups_keep_password_admins_and_can_demote_provider_admins(
    client, admin, database, idp
):
    async with database() as db, db.begin():
        user = await db.scalar(select(User).where(User.username == "admin"))
        user.email = "admin@example.com"
    await save_provider(
        client,
        idp,
        match_existing="email",
        auto_register=True,
        group_claim="groups",
        admin_group="dewarr-admins",
        member_group="dewarr-members",
        viewer_group="dewarr-viewers",
    )
    idp.email = "admin@example.com"
    idp.preferred_username = "directory-admin"
    idp.groups = ["dewarr-viewers"]
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303
    assert (await client.get("/api/auth/me")).json()["user"]["role"] == "admin"

    client.cookies.clear()
    login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a long test password"},
    )
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    second = await client.post(
        "/api/auth/users",
        json={
            "username": "second-admin",
            "display_name": "Second",
            "password": "a long admin password",
            "role": "admin",
        },
    )
    assert second.status_code == 201, second.text
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303
    me = await client.get("/api/auth/me")
    assert me.json()["user"]["username"] == "admin"
    assert me.json()["user"]["role"] == "admin"

    client.cookies.clear()
    login = await client.post(
        "/api/auth/login",
        json={"username": "second-admin", "password": "a long admin password"},
    )
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    idp.reset()
    idp.sub = "new-admin"
    idp.email = "new-admin@example.com"
    idp.preferred_username = "new-admin"
    idp.groups = ["dewarr-admins"]
    state = await start(client, idp)
    signed_in = await callback(client, state)
    assert signed_in.status_code == 303
    assert "oidc_error" not in signed_in.headers["location"]
    created = await client.get("/api/auth/me")
    assert created.json()["user"]["role"] == "admin"
    assert created.json()["user"]["username"] == "new-admin"
    async with database() as db:
        user = await db.scalar(select(User).where(User.username == "new-admin"))
        assert user.password_hash is None
        assert user.can_automate is False
    idp.groups = ["dewarr-viewers"]
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303
    demoted = await client.get("/api/auth/me")
    assert demoted.json()["user"]["username"] == "new-admin"
    assert demoted.json()["user"]["role"] == "viewer"


async def test_viewer_cannot_change_the_provider(client, admin):
    created = await client.post(
        "/api/auth/users",
        json={
            "username": "viewer",
            "display_name": "Reader",
            "role": "viewer",
            "password": "a long viewer password",
        },
    )
    assert created.status_code == 201
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()),
        base_url="http://testserver",
        headers={"Origin": "http://testserver"},
    ) as viewer:
        login = await viewer.post(
            "/api/auth/login",
            json={"username": "viewer", "password": "a long viewer password"},
        )
        viewer.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        assert (await viewer.get("/api/auth/oidc/settings")).status_code == 403
        assert (
            await viewer.put(
                "/api/auth/oidc/settings",
                json={
                    "enabled": False,
                    "label": "Pocket ID",
                    "issuer": "",
                    "authorization_endpoint": "",
                    "token_endpoint": "",
                    "userinfo_endpoint": "",
                    "jwks_uri": "",
                    "client_id": "",
                    "signing_algorithm": "RS256",
                    "match_existing": "off",
                    "auto_register": False,
                    "default_role": "member",
                    "group_claim": "",
                    "admin_group": "",
                    "member_group": "",
                    "viewer_group": "",
                },
            )
        ).status_code == 403


async def test_admin_can_unlink_oidc_from_password_account(client, admin, database, idp):
    created = await client.post(
        "/api/auth/users",
        json={
            "username": "reader",
            "display_name": "Existing reader",
            "password": "a long reader password",
            "role": "member",
        },
    )
    assert created.status_code == 201, created.text
    user_id = created.json()["id"]
    await save_provider(client, idp, match_existing="username", auto_register=True)
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303

    client.cookies.clear()
    login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a long test password"},
    )
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]

    users = (await client.get("/api/auth/users")).json()
    reader = next(user for user in users if user["id"] == user_id)
    assert reader["login_methods"] == ["password", "oidc"]

    response = await client.delete(f"/api/auth/users/{user_id}/oidc")
    assert response.status_code == 204, response.text
    async with database() as db:
        assert await db.get(OidcIdentity, user_id) is None


async def test_oidc_only_account_cannot_unlink_its_only_sign_in(client, admin, database, idp):
    await save_provider(client, idp, auto_register=True)
    state = await start(client, idp)
    assert (await callback(client, state)).status_code == 303
    me = (await client.get("/api/auth/me")).json()["user"]

    client.cookies.clear()
    login = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a long test password"},
    )
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]

    response = await client.delete(f"/api/auth/users/{me['id']}/oidc")
    assert response.status_code == 409
    assert "another sign-in method" in response.json()["detail"]
    async with database() as db:
        assert await db.get(OidcIdentity, me["id"]) is not None
