
from urllib.parse import urlparse, parse_qs

from authorization_request import build_authorization_request


AUTH_ENDPOINT = (
    "http://localhost:8080/realms/northstar-analytics"
    "/protocol/openid-connect/auth"
)


def test_authorization_request():
    url, transaction = build_authorization_request(
        AUTH_ENDPOINT, "northstar-mfa"
    )

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    assert parsed.scheme == "http"
    assert parsed.netloc == "localhost:8080"
    assert parsed.path.endswith("/protocol/openid-connect/auth")

    assert params["client_id"] == ["northstar-auth-test"]
    assert params["response_type"] == ["code"]
    assert params["scope"] == ["openid"]
    assert params["redirect_uri"] == [
        "http://localhost:8002/auth/callback"
    ]
    assert params["acr_values"] == ["northstar-mfa"]
    assert params["code_challenge_method"] == ["S256"]

    assert params["state"][0] == transaction["state"]
    assert params["nonce"][0] == transaction["nonce"]

    assert "code_verifier" not in params
    assert transaction["code_verifier"] not in url


def test_fresh_transactions():
    _, first = build_authorization_request(
        AUTH_ENDPOINT, "northstar-basic"
    )
    _, second = build_authorization_request(
        AUTH_ENDPOINT, "northstar-basic"
    )

    assert first["state"] != second["state"]
    assert first["nonce"] != second["nonce"]
    assert first["code_verifier"] != second["code_verifier"]


def test_invalid_acr_rejected():
    try:
        build_authorization_request(AUTH_ENDPOINT, "unknown-acr")
    except ValueError:
        return

    raise AssertionError("Invalid ACR was accepted")
