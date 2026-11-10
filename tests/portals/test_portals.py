import time
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from httpx import ASGITransport, AsyncClient

from apps.hr_portal import create_app as hr_app
from apps.ops_portal import CHANGE_CONFIG, create_app as ops_app
from apps.portals.auth import Settings

ISSUER = "http://localhost:8080/realms/northstar-analytics"
HR = Settings("hr-portal", "test-secret", ISSUER, "http://localhost:8000")
OPS = Settings("ops-portal", "test-secret", ISSUER, "http://localhost:8001", "northstar-mfa")
CHANGE = {"reporting_interval": "5 minutes"}
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


class FakeOIDC:
    """Fixture at the identity-provider boundary."""

    def __init__(self, settings, acr=None, roles=None):
        self.acr = acr
        self.claims = {
            "active": True, "token_type": "Bearer", "iss": settings.issuer,
            "sub": "fictional-user", "client_id": settings.client_id,
            "aud": [settings.client_id], "exp": int(time.time()) + 300,
            "resource_access": roles or {},
        }
        self.exchanges = 0

    async def authorization_url(self, login, *, request_mfa):
        return ISSUER + "/authorize?" + urlencode({"state": login.state})

    async def exchange(self, code, login):
        self.exchanges += 1
        if code != "example":
            raise ValueError("Invalid code")
        return {
            "sub": "fictional-user", "preferred_username": "<synthetic>",
            "exp": int(time.time()) + 300, "acr": self.acr,
        }, "server-only-access-token"

    async def introspect(self, token):
        assert token == "server-only-access-token"
        return self.claims

    async def logout_url(self):
        return ISSUER + "/logout"


def client_for(settings, roles=None, acr=None, **kwargs):
    fake = FakeOIDC(settings, acr, roles)
    app = (hr_app if settings == HR else ops_app)(settings, oidc=fake, **kwargs)
    return AsyncClient(transport=ASGITransport(app=app), base_url=settings.origin), fake


async def login_state(client):
    redirect = await client.get("/login")
    return parse_qs(urlsplit(redirect.headers["location"]).query)["state"][0]


async def sign_in(client):
    state = await login_state(client)
    response = await client.get("/auth/callback", params={"state": state, "code": "example"})
    assert response.status_code == 303
    cookie = response.headers.get_list("set-cookie")[-1]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert "server-only-access-token" not in cookie
    identity = await client.get("/me")
    assert "&lt;synthetic&gt;" in identity.text
    csrf = identity.text.split('name="csrf-token" content="')[1].split('"')[0]
    return {"origin": str(client.base_url).rstrip("/"), "x-csrf-token": csrf}


@pytest.mark.parametrize(("settings", "route"), [(HR, "/hr/people"), (OPS, "/ops/metrics")])
async def test_anonymous(settings, route):
    client, _ = client_for(settings)
    assert (await client.get("/")).status_code == 200
    assert (await client.get(route)).status_code == 401
    assert (await client.get("/me")).status_code == 401


async def test_hr_read_write_and_role_freshness():
    client, oidc = client_for(HR, {"hr-portal": {"roles": ["hr-viewer"]}})
    headers = await sign_in(client)
    assert (await client.get("/hr/people")).status_code == 200
    record = "/hr/people/101"
    update = {"title": "Lead Analyst"}
    assert (await client.patch(record, json=update, headers=headers)).status_code == 403

    oidc.claims["resource_access"]["hr-portal"]["roles"].append("hr-editor")
    assert (await client.patch(record, json=update)).status_code == 403
    assert (await client.patch(record, json=update, headers=headers)).status_code == 200
    assert "Lead Analyst" in (await client.get("/hr/people")).text
    assert (await client.patch(record, json={**update, "department": "Payroll"}, headers=headers)).status_code == 422
    assert (await client.patch("/hr/people/999", json=update, headers=headers)).status_code == 404

    oidc.claims["resource_access"] = {}
    assert (await client.get("/hr/people")).status_code == 403


@pytest.mark.parametrize("claims", [
    {},
    {"ops-portal": {"roles": ["hr-viewer", "ops-admin"]}},
    {"hr-portal": {"roles": "hr-viewer"}},
    {"hr-portal": {"roles": ["hr-editor"]}},
])
async def test_no_implicit_roles_or_browser_grants(claims):
    client, _ = client_for(HR, claims)
    await sign_in(client)
    response = await client.get("/hr/people?role=hr-viewer", headers={"x-role": "hr-viewer"})
    assert response.status_code == 403
    assert "Access denied" in response.text


@pytest.mark.parametrize(("field", "value", "status"), [
    ("active", False, 401), ("exp", 1, 401), ("token_type", "ID", 401),
    ("iss", "other-issuer", 401), ("sub", "other-user", 401),
    ("client_id", "ops-portal", 401), ("aud", ["ops-portal"], 403),
])
async def test_access_token_validation(field, value, status):
    client, oidc = client_for(HR, {"hr-portal": {"roles": ["hr-viewer"]}})
    await sign_in(client)
    oidc.claims[field] = value
    assert (await client.get("/hr/people")).status_code == status


async def test_state_is_cookie_bound_and_single_use():
    client, oidc = client_for(HR)
    state = await login_state(client)
    callback = "/auth/callback"
    assert (await client.get(callback, params={"state": "forged", "code": "example"})).status_code == 401
    stranger, _ = client_for(HR)
    assert (await stranger.get(callback, params={"state": state, "code": "example"})).status_code == 401
    assert oidc.exchanges == 0
    assert (await client.get(callback, params={"state": state, "code": "bad"})).status_code == 401
    assert (await client.get(callback, params={"state": state, "code": "example"})).status_code == 401
    assert oidc.exchanges == 1


async def test_logout_checks_csrf_and_invalidates_session():
    client, _ = client_for(HR)
    headers = await sign_in(client)
    assert (await client.post("/logout", headers={**headers, "origin": OPS.origin})).status_code == 403
    assert (await client.get("/me")).status_code == 200
    response = await client.post("/logout", headers=headers)
    assert response.json() == {"redirect": ISSUER + "/logout"}
    assert (await client.get("/me")).status_code == 401


async def test_ops_viewer_cannot_write():
    client, _ = client_for(OPS, {"ops-portal": {"roles": ["ops-viewer"]}}, acr=OPS.mfa_acr)
    headers = await sign_in(client)
    assert (await client.get("/ops/metrics")).status_code == 200
    assert (await client.post("/ops/config", json=CHANGE, headers=headers)).status_code == 403


async def test_hr_role_cannot_read_operations_metrics():
    client, _ = client_for(OPS, {"hr-portal": {"roles": ["hr-viewer", "hr-editor"]}})
    await sign_in(client)
    assert (await client.get("/ops/metrics")).status_code == 403


@pytest.mark.parametrize("acr", [None, "northstar-basic", "unknown", "2"])
async def test_admin_requires_recognized_mfa(acr):
    def approval(*args):
        pytest.fail("Approval lookup must follow MFA validation")

    client, _ = client_for(
        OPS, {"ops-portal": {"roles": ["ops-admin"]}}, acr=acr, approval_lookup=approval
    )
    response = await client.post("/ops/config", json=CHANGE, headers=await sign_in(client))
    assert response.status_code == 403
    assert "MFA assurance" in response.text


@pytest.mark.parametrize("expiry", [None, 1, float("inf")])
async def test_admin_requires_time_bounded_approval(expiry):
    lookup = (lambda *args: expiry) if expiry is not None else None
    client, _ = client_for(
        OPS, {"ops-portal": {"roles": ["ops-admin"]}}, acr=OPS.mfa_acr, approval_lookup=lookup
    )
    response = await client.post("/ops/config", json=CHANGE, headers=await sign_in(client))
    assert response.status_code == 403
    assert "administrative approval" in response.text


async def test_admin_with_valid_grant_can_change_config():
    def approval(issuer, subject, action):
        assert (issuer, subject, action) == (ISSUER, "fictional-user", CHANGE_CONFIG)
        return time.time() + 30

    client, _ = client_for(
        OPS, {"ops-portal": {"roles": ["ops-admin", "ops-viewer"]}},
        acr=OPS.mfa_acr, approval_lookup=approval,
    )
    response = await client.post("/ops/config", json=CHANGE, headers=await sign_in(client))
    assert response.status_code == 200
    assert response.json() == CHANGE
    assert "<option selected>5 minutes</option>" in (await client.get("/ops/metrics")).text


@pytest.mark.parametrize("failure", [None, "signature", "iss", "aud", "exp", "nonce"])
async def test_real_oidc_exchange_with_mock_keycloak(monkeypatch, failure):
    import base64
    import hashlib
    from types import SimpleNamespace

    import httpx
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    from apps.portals import auth as portal_auth

    key = RSAKey.generate_key(2048, parameters={"kid": "test-key"})
    signing_key = RSAKey.generate_key(2048) if failure == "signature" else key
    protocol = ISSUER + "/protocol/openid-connect"
    metadata = {
        "issuer": ISSUER,
        "authorization_endpoint": protocol + "/auth",
        "token_endpoint": protocol + "/token",
        "jwks_uri": protocol + "/certs",
        "introspection_endpoint": protocol + "/token/introspect",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    auth = portal_auth.OIDC(OPS)
    authorization = {}

    def keycloak(request):
        path = str(request.url)
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=metadata)
        if path == metadata["jwks_uri"]:
            return httpx.Response(200, json={"keys": [key.as_dict(private=False)]})
        assert request.headers["authorization"].startswith("Basic ")
        form = parse_qs(request.content.decode())
        if path == metadata["introspection_endpoint"]:
            assert form["token"] == ["mock-access"]
            return httpx.Response(200, json={
                "active": True, "token_type": "Bearer", "iss": ISSUER,
                "sub": "mock-subject", "client_id": OPS.client_id,
                "aud": OPS.client_id, "exp": int(time.time()) + 60,
                "resource_access": {OPS.client_id: {"roles": ["ops-viewer"]}},
            })
        assert path == metadata["token_endpoint"]
        verifier = form["code_verifier"][0].encode()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b"=")
        assert authorization["code_challenge"] == [challenge.decode()]
        assert form["redirect_uri"] == [OPS.callback]
        assert form["code"] == ["example"]
        now = int(time.time())
        claims = {
            "iss": ISSUER, "sub": "mock-subject", "aud": OPS.client_id,
            "iat": now, "exp": now + 60, "nonce": authorization["nonce"][0],
            "acr": OPS.mfa_acr, "preferred_username": "Mock employee",
        }
        bad_values = {"iss": "wrong", "aud": "wrong", "exp": now - 30, "nonce": "wrong"}
        if failure in bad_values:
            claims[failure] = bad_values[failure]
        id_token = jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, signing_key)
        return httpx.Response(200, json={
            "access_token": "mock-access", "id_token": id_token, "token_type": "Bearer",
        })

    transport = httpx.MockTransport(keycloak)
    oauth_client = auth.client.client_cls
    monkeypatch.setattr(auth.client, "client_cls", lambda **kw: oauth_client(transport=transport, **kw))
    monkeypatch.setattr(portal_auth, "httpx", SimpleNamespace(
        AsyncClient=lambda **kw: AsyncClient(transport=transport, **kw),
    ))
    app = ops_app(OPS, oidc=auth)
    async with AsyncClient(transport=ASGITransport(app=app), base_url=OPS.origin) as client:
        redirect = await client.get("/login?mfa=true")
        assert redirect.status_code == 303
        authorization.update(parse_qs(urlsplit(redirect.headers["location"]).query))
        assert authorization["response_type"] == ["code"]
        assert authorization["code_challenge_method"] == ["S256"]
        assert authorization["acr_values"] == [OPS.mfa_acr]
        callback = await client.get(
            "/auth/callback", params={"state": authorization["state"][0], "code": "example"}
        )
        assert callback.status_code == (401 if failure else 303)
        assert (await client.get("/ops/metrics")).status_code == (401 if failure else 200)
