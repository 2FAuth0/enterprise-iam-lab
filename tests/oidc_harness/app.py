import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException
from authlib.integrations.base_client.errors import OAuthError

# Constants for the OIDC client configuration
ISSUER = "http://localhost:8080/realms/northstar-analytics"
CLIENT_ID = "northstar-auth-test"

CLIENT_SECRET = os.environ["NORTHSTAR_OIDC_CLIENT_SECRET"]
SESSION_SECRET = os.environ["NORTHSTAR_SESSION_SECRET"]

app = FastAPI(
    title="Northstar OIDC Test Harness"
)

# Add session middleware to manage user sessions
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="northstar_oidc_session",
    max_age=600,
    same_site="lax",
    https_only=False,  # Local HTTP lab only
)

# Initialize the OAuth client for OIDC interactions
oauth = OAuth()

# Register the OIDC client with the OAuth instance
oauth.register(
    name="northstar",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=(
        f"{ISSUER}/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid",
        "code_challenge_method": "S256",
    },
)

# Define a health check endpoint to verify that the application is running
@app.get("/health")
async def health():
    return {"status": "ok", "application": "oidc-harness"}


# Define the login endpoint that initiates the OIDC authorization flow
@app.get("/login")
async def login(request: Request, acr: str = "northstar-basic"):

    allowed_acr = {
        "northstar-basic",
        "northstar-mfa",
    }

    if acr not in allowed_acr:
        raise HTTPException(status_code=400, detail="Unsupported ACR value")

    callback_url = request.url_for("auth_callback")

    request.session["requested_acr"] = acr

    return await oauth.northstar.authorize_redirect(
        request,
        redirect_uri=callback_url,
        acr_values=acr
    )

# Define the callback endpoint that handles the OIDC authorization response

@app.get("/auth/callback")
async def auth_callback(request: Request):
    requested_acr = request.session.pop("requested_acr", None)

    if requested_acr not in {"northstar-basic", "northstar-mfa"}:
        return JSONResponse(
            status_code=400,
            content={"detail": "Missing authentication request context"},
        )

    try:
        token = await oauth.northstar.authorize_access_token(request)
    except OAuthError:
        return JSONResponse(
            status_code=401,
            content={"detail": "OIDC authentication failed"},
        )
    except Exception:
        return JSONResponse(
            status_code=502,
            content={"detail": "OIDC callback processing failed"},
        )

    userinfo = token.get("userinfo")

    if not userinfo:
        return JSONResponse(
            status_code=401,
            content={"detail": "Validated ID token claims unavailable"},
        )

    achieved_acr = userinfo.get("acr")

    if is_acr_acceptable(requested_acr, achieved_acr) is False:
        return JSONResponse(
            status_code=401,
            content={"detail": "Insufficient authentication assurance"},
        )
    
    return JSONResponse(
        status_code=200,
        content={
            "authenticated": True,
            "subject": userinfo.get("sub"),
            "requested_acr": requested_acr,
            "achieved_acr": achieved_acr,
        },
    )

def is_acr_acceptable(requested_acr: str, achieved_acr: str) -> bool:
    """
    Determine if the achieved ACR meets or exceeds the requested ACR.

    Args:
        requested_acr (str): The ACR value requested during authentication.
        achieved_acr (str): The ACR value achieved after authentication.

    Returns:
        bool: True if the achieved ACR is acceptable, False otherwise.
    """
    acr_hierarchy = {
        "northstar-basic": 1,
        "northstar-mfa": 2,
    }

    requested_level = acr_hierarchy.get(requested_acr)
    achieved_level = acr_hierarchy.get(achieved_acr)

    if requested_level is None or achieved_level is None:
        return False

    return achieved_level >= requested_level