"""
totp.py — RFC 6238 TOTP (Authy / Google Authenticator compatible), sovereign.

A TOTP code is a VERIFIER (proof you hold the seed on your phone), NOT a key — it
can't reconstruct a secret alone. So it's used here as a SECOND FACTOR / gate on
sensitive actions (vault recovery, unlock-word), not as the secret itself.

The seed lives 0600 on your own box (config.TOTP_SECRET_FILE). Its compromise alone
reveals no passphrase — it only lets someone pass the 2nd-factor gate, which still
requires the primary factor (k Shamir shares, or the passphrase).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
import urllib.parse

from skvault.config import TOTP_SECRET_FILE

SECRET_FILE = TOTP_SECRET_FILE


def gen_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def provisioning_uri(secret: str, account: str = "chef@skworld.io", issuer: str = "SKWorld-Vault") -> str:
    q = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                "digits": "6", "period": "30"})
    return f"otpauth://totp/{urllib.parse.quote(issuer)}:{urllib.parse.quote(account)}?{q}"


def _code_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    v = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{v:06d}"


def now_code(secret: str, t: float | None = None) -> str:
    return _code_at(secret, int((t if t is not None else time.time()) // 30))


def verify(secret: str, code: str, window: int = 1, t: float | None = None) -> bool:
    counter = int((t if t is not None else time.time()) // 30)
    target = str(code).strip().zfill(6)
    return any(_code_at(secret, counter + w) == target for w in range(-window, window + 1))


# --- stored seed (the configured factor) -------------------------------------
def init() -> str:
    """Generate + store a new TOTP seed (0600). Returns the secret (show as QR/URI)."""
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    secret = gen_secret()
    SECRET_FILE.write_text(secret)
    SECRET_FILE.chmod(0o600)
    return secret


def configured() -> bool:
    return SECRET_FILE.exists()


def verify_stored(code: str) -> bool:
    if not SECRET_FILE.exists():
        return False
    return verify(SECRET_FILE.read_text().strip(), code)
