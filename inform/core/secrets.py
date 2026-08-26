"""AES-256-GCM encryption for credential secrets at rest.

Wire format: enc:v1: + urlsafe-b64(nonce[12] || tag[16] || ciphertext).
Key is SHA-256(SECURITY__SECRET_KEY)[:32]. Never log secret values.
"""

from __future__ import annotations

import base64
import hashlib
import logging

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

from inform.core.config import settings

logger = logging.getLogger("inform.secrets")

_PREFIX = "enc:v1:"
_NONCE_LEN = 12
_TAG_LEN = 16


def _aes_key() -> bytes:
    return hashlib.sha256(settings.security.secret_key.encode()).digest()[:32]


def encrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if value == "":
        return ""
    if value.startswith(_PREFIX):
        return value
    nonce = get_random_bytes(_NONCE_LEN)
    cipher = AES.new(_aes_key(), AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(value.encode("utf-8"))
    blob = nonce + tag + ciphertext
    return _PREFIX + base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if not value.startswith(_PREFIX):
        return value
    try:
        blob = base64.urlsafe_b64decode(value[len(_PREFIX):].encode("ascii"))
        nonce = blob[:_NONCE_LEN]
        tag = blob[_NONCE_LEN:_NONCE_LEN + _TAG_LEN]
        ciphertext = blob[_NONCE_LEN + _TAG_LEN:]
        cipher = AES.new(_aes_key(), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
    except Exception:
        logger.error("Failed to decrypt a stored secret")
        return None


def encrypt_legacy_secrets() -> None:
    """Encrypt plaintext auth_key / priv_key / community rows. Skip enc:v1:."""
    from inform.core.database import SessionLocal
    from inform.core.models import CredentialProfile

    db = SessionLocal()
    try:
        updated = 0
        for profile in db.query(CredentialProfile).all():
            changed = False
            new_auth = encrypt_secret(profile.auth_key if profile.auth_key is not None else "")
            new_priv = encrypt_secret(profile.priv_key if profile.priv_key is not None else "")
            new_comm = encrypt_secret(profile.community)
            if new_auth != profile.auth_key:
                profile.auth_key = new_auth if new_auth is not None else ""
                changed = True
            if new_priv != profile.priv_key:
                profile.priv_key = new_priv if new_priv is not None else ""
                changed = True
            if new_comm != profile.community:
                profile.community = new_comm
                changed = True
            if changed:
                updated += 1
        if updated:
            db.commit()
            logger.info("Encrypted legacy secrets on %s credential profile(s)", updated)
        else:
            db.rollback()
    except Exception:
        db.rollback()
        logger.error("encrypt_legacy_secrets failed")
        raise
    finally:
        db.close()
