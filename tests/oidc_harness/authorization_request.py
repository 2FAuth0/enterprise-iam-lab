
import secrets
from urllib.parse import urlencode

from pkce import generate_code_verifier, generate_code_challenge


CLIENT_ID = "northstar-auth-test"
REDIRECT_URI = "http://localhost:8002/auth/callback"

ALLOWED_ACR_VALUES = {
    "northstar-basic",
    "northstar-mfa",
}


def build_authorization_request(authorization_endpoint, acr_value):
    """
    Build an OIDC Authorization Code request using PKCE S256.

    Returns:
        authorization_url: URL for the browser redirect.
        transaction: Values retained locally for callback validation.
    """

    if not isinstance(authorization_endpoint, str):
        raise ValueError("Authorization endpoint must be a string")

    if not authorization_endpoint.startswith(
        "http://localhost:8080/realms/northstar-analytics/protocol/openid-connect/auth"
    ):
        raise ValueError("Unexpected authorization endpoint")

    if acr_value not in ALLOWED_ACR_VALUES:
        raise ValueError("Unsupported ACR value")

    # Generate a unique PKCE verifier for this transaction.
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    # State protects the authorization response.
    state = secrets.token_urlsafe(32)

    # Nonce binds the returned ID token to this request.
    nonce = secrets.token_urlsafe(32)

    parameters = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "acr_values": acr_value,
    }

    authorization_url = (
        authorization_endpoint + "?" + urlencode(parameters)
    )

    transaction = {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "requested_acr": acr_value,
    }

    return authorization_url, transaction
