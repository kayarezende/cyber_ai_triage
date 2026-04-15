"""Tests for sentient_common.crypto (Fernet wrapper)."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken
from sentient_common import crypto


@pytest.fixture(autouse=True)
def _reset_crypto_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test gets a fresh Fernet via the LRU reset + a controlled key."""
    monkeypatch.setenv("TENANT_SECRET_KEY", Fernet.generate_key().decode())
    crypto.reset_cache()


def test_encrypt_decrypt_roundtrip() -> None:
    token = crypto.encrypt("splunk-hec-s3cr3t")
    assert isinstance(token, bytes)
    assert crypto.decrypt(token) == "splunk-hec-s3cr3t"


def test_encrypt_unicode() -> None:
    plaintext = "naïve café 🍪"
    assert crypto.decrypt(crypto.encrypt(plaintext)) == plaintext


def test_tamper_rejection() -> None:
    token = crypto.encrypt("don't touch this")
    # Flip one byte in the middle of the ciphertext.
    mutated = bytearray(token)
    mutated[len(mutated) // 2] ^= 0x01
    with pytest.raises(InvalidToken):
        crypto.decrypt(bytes(mutated))


def test_missing_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TENANT_SECRET_KEY", raising=False)
    crypto.reset_cache()
    with pytest.raises(RuntimeError, match="TENANT_SECRET_KEY is not set"):
        crypto.encrypt("anything")


def test_invalid_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TENANT_SECRET_KEY", "not-a-valid-fernet-key")
    crypto.reset_cache()
    with pytest.raises(RuntimeError, match="not a valid Fernet key"):
        crypto.encrypt("anything")
