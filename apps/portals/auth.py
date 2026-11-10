"""OIDC and server-side session policy shared by the two portals."""

import os
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

SESSION_SECONDS = 600
LOGIN_SECONDS = 300


@dataclass(frozen=True)
class Settings:
    client_id: str
    client_secret: str = field(repr=False)
    issuer: str
    origin: str
    mfa_acr: str = ""

    @classmethod
    def from_env(cls, client_id: str, port: int):
        prefix = client_id.split("-")[0].upper()
        secret = os.getenv(f"NORTHSTAR_{prefix}_CLIENT_SECRET", "").strip()
        if not secret or secret == "REPLACE_WITH_CLIENT_SECRET":
            raise RuntimeError(f"Set NORTHSTAR_{prefix}_CLIENT_SECRET before starting")
        return cls(
            client_id=client_id,
            client_secret=secret,
            issuer=os.getenv(
                "NORTHSTAR_OIDC_ISSUER", "http://localhost:8080/realms/northstar-analytics"
            ).rstrip("/"),
            origin=f"http://localhost:{port}",
            mfa_acr=os.getenv("NORTHSTAR_OPS_MFA_ACR", "northstar-mfa")
            if client_id == "ops-portal" else "",
        )

    @property
    def callback(self):
        return f"{self.origin}/auth/callback"


@dataclass(frozen=True)
class Login:
    state: str
    nonce: str
    verifier: str = field(repr=False)
    expires: float


@dataclass(frozen=True)
class Session:
    subject: str
    name: str
    acr: str | None
    access_token: str = field(repr=False)
    csrf: str = field(repr=False)
    expires: float


def matches(value: str, expected: str) -> bool:
    return secrets.compare_digest(value.encode(), expected.encode())


class OIDC:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.client = OAuth().register(
            "portal",
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            server_metadata_url=f"{settings.issuer}/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid profile",
                "code_challenge_method": "S256",
                "token_endpoint_auth_method": "client_secret_basic",
                "timeout": 5.0,
                "trust_env": False,
            },
        )

    async def metadata(self):
        metadata = await self.client.load_server_metadata()
        if metadata.get("issuer") != self.settings.issuer:
            raise ValueError("Unexpected issuer")
        return metadata

    async def authorization_url(self, login: Login, *, request_mfa: bool):
        await self.metadata()
        acr = {"acr_values": self.settings.mfa_acr} if request_mfa else {}
        result = await self.client.create_authorization_url(
            redirect_uri=self.settings.callback,
            state=login.state,
            nonce=login.nonce,
            code_verifier=login.verifier,
            **acr,
        )
        return result["url"]

    async def exchange(self, code: str, login: Login):
        await self.metadata()
        tokens = await self.client.fetch_access_token(
            redirect_uri=self.settings.callback, code=code, code_verifier=login.verifier
        )
        access_token = tokens["access_token"]
        if not isinstance(access_token, str) or not access_token:
            raise ValueError("Missing access token")
        identity = await self.client.parse_id_token(tokens, nonce=login.nonce, leeway=0)
        if not identity or not isinstance(identity.get("sub"), str) or not identity["sub"]:
            raise ValueError("Missing identity")
        return identity, access_token

    async def introspect(self, access_token: str):
        metadata = await self.metadata()
        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
            response = await client.post(
                metadata["introspection_endpoint"],
                auth=(self.settings.client_id, self.settings.client_secret),
                data={"token": access_token, "token_type_hint": "access_token"},
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            claims = response.json()
            if not isinstance(claims, dict):
                raise ValueError("Invalid introspection response")
            return claims

    async def logout_url(self):
        metadata = await self.metadata()
        query = urlencode({
            "client_id": self.settings.client_id,
            "post_logout_redirect_uri": f"{self.settings.origin}/",
        })
        return f"{metadata['end_session_endpoint']}?{query}"


def install_auth(app: FastAPI, settings: Settings, oidc: OIDC):
    sessions: dict[str, Session] = {}
    pending: dict[str, Login] = {}
    cookie = f"northstar_{settings.client_id.replace('-', '_')}"
    login_cookie = f"{cookie}_login"

    def store(entries, key, value):
        now = time.time()
        for expired in [key for key, entry in entries.items() if entry.expires <= now]:
            del entries[expired]
        if len(entries) >= 1024:
            raise HTTPException(503, "Portal session capacity reached.")
        entries[key] = value

    def set_cookie(response, name, value, age):
        response.set_cookie(
            name, value, max_age=age, httponly=True, samesite="lax",
            secure=settings.origin.startswith("https://"),
        )

    def current_session(request: Request) -> Session | None:
        key = request.cookies.get(cookie, "")
        session = sessions.get(key)
        if session and session.expires <= time.time():
            sessions.pop(key, None)
            return None
        return session

    async def authenticated(request: Request) -> Session:
        session = current_session(request)
        if session is None:
            raise HTTPException(401, "Sign in to continue.")
        return session

    def check_csrf(request: Request, session: Session):
        if request.headers.get("origin") != settings.origin or not matches(
            request.headers.get("x-csrf-token", ""), session.csrf
        ):
            raise HTTPException(403, "Request verification failed. Reload the page and retry.")

    def require_role(role: str, *, write: bool = False):
        async def authorized(request: Request, session: Session = Depends(authenticated)):
            try:
                claims = await oidc.introspect(session.access_token)
            except Exception:
                raise HTTPException(502, "Unable to verify access with Keycloak.") from None
            # Recheck after the network call in case this session expired or was signed out.
            if current_session(request) is not session:
                raise HTTPException(401, "Sign in to continue.")
            expiry = claims.get("exp")
            if (
                claims.get("active") is not True
                or claims.get("token_type") != "Bearer"
                or claims.get("iss") != settings.issuer
                or claims.get("sub") != session.subject
                or claims.get("client_id") != settings.client_id
                or type(expiry) is not int
                or expiry <= time.time()
            ):
                raise HTTPException(401, "Access token is invalid or expired. Sign in again.")

            audience = claims.get("aud")
            audiences = [audience] if isinstance(audience, str) else audience
            resources = claims.get("resource_access")
            resource = resources.get(settings.client_id) if isinstance(resources, dict) else None
            roles = resource.get("roles") if isinstance(resource, dict) else None
            if (
                not isinstance(audiences, list) or settings.client_id not in audiences
                or not isinstance(roles, list) or role not in roles
            ):
                raise HTTPException(403, "Your account lacks the required portal permission.")
            if write:
                check_csrf(request, session)
            return session

        return authorized

    @app.get("/login")
    async def login(request: Request, mfa: bool = False):
        if mfa and not settings.mfa_acr:
            raise HTTPException(400, "MFA sign-in is unavailable for this portal.")
        attempt = Login(
            secrets.token_urlsafe(32), secrets.token_urlsafe(32),
            secrets.token_urlsafe(48), time.time() + LOGIN_SECONDS,
        )
        try:
            url = await oidc.authorization_url(attempt, request_mfa=mfa)
        except Exception:
            raise HTTPException(502, "Unable to start Keycloak sign-in.") from None
        pending.pop(request.cookies.get(login_cookie, ""), None)
        key = secrets.token_urlsafe(32)
        store(pending, key, attempt)
        response = RedirectResponse(url, status_code=303)
        set_cookie(response, login_cookie, key, LOGIN_SECONDS)
        return response

    @app.get("/auth/callback")
    async def callback(request: Request):
        key = request.cookies.get(login_cookie, "")
        attempt = pending.get(key)
        params = request.query_params
        if (
            not attempt or attempt.expires <= time.time()
            or len(params.getlist("state")) != 1
            or not matches(params["state"], attempt.state)
        ):
            raise HTTPException(401, "Invalid or expired sign-in request. Start again.")
        del pending[key]
        if "error" in params or len(params.getlist("code")) != 1 or not params["code"]:
            raise HTTPException(401, "Keycloak sign-in did not complete.")
        if params.get("iss", settings.issuer) != settings.issuer:
            raise HTTPException(401, "Unexpected sign-in issuer.")
        try:
            identity, token = await oidc.exchange(params["code"], attempt)
            expires = min(time.time() + SESSION_SECONDS, identity["exp"])
            name = identity.get("preferred_username") or identity.get("name")
            acr = identity.get("acr")
            session = Session(
                identity["sub"], name if isinstance(name, str) else identity["sub"],
                acr if isinstance(acr, str) else None, token, secrets.token_urlsafe(32), expires,
            )
        except Exception:
            raise HTTPException(401, "Keycloak sign-in could not be verified.") from None
        sessions.pop(request.cookies.get(cookie, ""), None)
        key = secrets.token_urlsafe(32)
        store(sessions, key, session)
        response = RedirectResponse("/", status_code=303)
        response.delete_cookie(login_cookie)
        set_cookie(response, cookie, key, SESSION_SECONDS)
        return response

    @app.post("/logout")
    async def logout(request: Request, session: Session = Depends(authenticated)):
        check_csrf(request, session)
        sessions.pop(request.cookies.get(cookie, ""), None)
        pending.pop(request.cookies.get(login_cookie, ""), None)
        try:
            url = await oidc.logout_url()
            response = JSONResponse({"redirect": url})
        except Exception:
            response = JSONResponse(
                {"detail": "Portal session ended. Keycloak sign-out is unavailable."},
                status_code=502,
            )
        response.delete_cookie(cookie)
        response.delete_cookie(login_cookie)
        return response

    return current_session, authenticated, require_role
