import secrets
import hashlib
import base64

# Generate a cryptographically secure URL-safe random string to be used as the code verifier
def generate_code_verifier():
    verifier = secrets.token_urlsafe(32)  # Generate a random string of 32 bytes = 43 characters
    return verifier

# Generate a code challenge from the code verifier using SHA256 and base64url encoding
def generate_code_challenge(code_verifier):
    # Hash the code verifier using SHA256
    sha256_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    # Encode the hash using base64url encoding
    code_challenge = base64.urlsafe_b64encode(sha256_hash).rstrip(b'=').decode('utf-8')
    return code_challenge