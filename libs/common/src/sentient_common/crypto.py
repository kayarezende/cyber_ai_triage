"""Fernet-based symmetric encryption for per-tenant secrets.

Key source: env var `TENANT_SECRET_KEY` (urlsafe-base64-encoded 32 bytes).
Generate once per deployment with:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Fernet (AES-128-CBC + HMAC-SHA256) is authenticated — tampering raises
`cryptography.fernet.InvalidToken`. See ADR 0012.
"""

from __future__ import annotations

import os
from functools import cache

from cryptography.fernet import Fernet

_ENV_VAR = "TENANT_SECRET_KEY"


@cache
def _fernet() -> Fernet:
    raw = os.environ.get(_ENV_VAR)
    if not raw:
        raise RuntimeError(
            f"{_ENV_VAR} is not set; refusing to start. "
            "Generate with: python -c 'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())'"
        )
    try:
        return Fernet(raw.encode() if isinstance(raw, str) else raw)
    except ValueError as exc:
        raise RuntimeError(
            f"{_ENV_VAR} is not a valid Fernet key (urlsafe-base64, 32 bytes)."
        ) from exc


def encrypt(plaintext: str) -> bytes:
    """Encrypt a UTF-8 string; returns Fernet token bytes."""
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes) -> str:
    """Decrypt a Fernet token; raises `InvalidToken` on tampering."""
    return _fernet().decrypt(ciphertext).decode("utf-8")


def reset_cache() -> None:
    """Test helper: clear cached Fernet so env changes take effect."""
    _fernet.cache_clear()
