from pkce import generate_code_verifier, generate_code_challenge

def test_verifier_length():
    verifier = generate_code_verifier()
    assert len(verifier) >= 43  # Minimum length for a code verifier
    assert len(verifier) <= 128  # Maximum length for a code verifier

def test_verifier_characters():
    verifier = generate_code_verifier()
    allowed_characters = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    for char in verifier:
        assert char in allowed_characters, f"Character '{char}' is not allowed in the code verifier"

def test_verifier_uniqueness():
    verifier1 = generate_code_verifier()
    verifier2 = generate_code_verifier()
    assert verifier1 != verifier2, "Two generated code verifiers should not be the same"

def test_rfc7636_compliance():
    known_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    generated_challenge = generate_code_challenge(known_verifier)
    assert generated_challenge == expected_challenge, f"Expected {expected_challenge}, but got {generated_challenge}"

def test_challenge_format():
    generated_challenge = generate_code_challenge(generate_code_verifier())
    # The challenge should be a base64url-encoded string without padding
    assert isinstance(generated_challenge, str), "Code challenge should be a string"
    assert "=" not in generated_challenge, "Code challenge should not contain padding"




