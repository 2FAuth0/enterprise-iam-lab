import json
import sys
import urllib.error
import urllib.request


EXPECTED_ISSUER = "http://localhost:8080/realms/northstar-analytics" 

try:
    # Fetch the OpenID configuration from the specified URL
    url = "http://localhost:8080/realms/northstar-analytics/.well-known/openid-configuration"
    response = urllib.request.urlopen(url, None, 10)
    data = json.loads(response.read().decode())
    required_fields = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']
    # Validate that all required fields are present and are non-empty strings
    for field in required_fields:
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ValueError(f"Missing or invalid field: {field}")
    # Validate the issuer against the expected value
    issuer = data['issuer']
    if issuer != EXPECTED_ISSUER:
        raise ValueError(f"Unexpected issuer: {issuer}")
    # Extract and print the relevant fields
    authorization_endpoint = data['authorization_endpoint']
    token_endpoint = data['token_endpoint']
    jwks_uri = data['jwks_uri']
    # Print the extracted values
    print(f"Issuer: {issuer}")
    print(f"Authorization Endpoint: {authorization_endpoint}")
    print(f"Token Endpoint: {token_endpoint}")
    print(f"JWKS URI: {jwks_uri}")

# Handle specific exceptions and print error messages
except urllib.error.HTTPError as e:
    print(f"HTTP error occurred: {e.code} - {e.reason}")
    sys.exit(1)
except urllib.error.URLError as e:
    print(f"Failed to fetch OpenID configuration: {e}")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"Failed to parse JSON response: {e}")
    sys.exit(1)
except KeyError as e:
    print(f"Missing expected key in JSON response: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)