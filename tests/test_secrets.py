from inform.core.secrets import decrypt_secret, encrypt_secret


def test_round_trip():
    original = "super-secret-auth-key"
    cipher = encrypt_secret(original)
    assert cipher is not None
    assert cipher.startswith("enc:v1:")
    assert original not in cipher
    assert decrypt_secret(cipher) == original


def test_plaintext_passthrough():
    assert decrypt_secret("legacy-plaintext-community") == "legacy-plaintext-community"
    assert decrypt_secret("not-encrypted") == "not-encrypted"


def test_none_and_empty():
    assert encrypt_secret(None) is None
    assert decrypt_secret(None) is None
    assert encrypt_secret("") == ""
    assert decrypt_secret("") == ""


def test_idempotent_encrypt():
    once = encrypt_secret("abc12345")
    twice = encrypt_secret(once)
    assert once == twice
    assert decrypt_secret(twice) == "abc12345"


def test_community_round_trip():
    cipher = encrypt_secret("public")
    assert cipher.startswith("enc:v1:")
    assert decrypt_secret(cipher) == "public"
