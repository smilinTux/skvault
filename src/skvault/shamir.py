"""
shamir.py — Shamir's Secret Sharing over GF(256) (the ssss / HashiCorp-Vault model).

Information-theoretic k-of-n threshold sharing: split a secret into n shares such
that ANY k reconstruct it and any k-1 reveal NOTHING. Pure-Python, no deps,
auditable. Byte-wise over GF(2^8) with the AES polynomial (0x11b).

Used for sovereign social recovery of the vault passphrase: each share is then
PGP-sealed to one holder's key (see vault_recovery.py). No single holder — not
even the agent — can recover alone.
"""

from __future__ import annotations

import os

# --- GF(256) tables (generator 0x03, AES reduction poly 0x11b) ---------------
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= (_x << 1) ^ (0x11B if _x & 0x80 else 0)
    _x &= 0xFF
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval(poly: list[int], x: int) -> int:
    """Evaluate polynomial (coeffs low→high) at x in GF(256) via Horner."""
    y = 0
    for coeff in reversed(poly):
        y = _mul(y, x) ^ coeff
    return y


def split(secret: bytes, n: int, k: int) -> list[tuple[int, bytes]]:
    """Split `secret` into n shares, threshold k. Returns [(x, y_bytes), …], x in 1..n."""
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    if not secret:
        raise ValueError("empty secret")
    shares: list[bytearray] = [bytearray() for _ in range(n)]
    for byte in secret:
        # random polynomial of degree k-1, constant term = the secret byte
        poly = [byte] + [b for b in os.urandom(k - 1)]
        for i in range(n):
            shares[i].append(_eval(poly, i + 1))
    return [(i + 1, bytes(shares[i])) for i in range(n)]


def combine(shares: list[tuple[int, bytes]]) -> bytes:
    """Reconstruct the secret from >= k shares via Lagrange interpolation at x=0."""
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    length = len(shares[0][1])
    if any(len(y) != length for _, y in shares):
        raise ValueError("shares differ in length")
    out = bytearray()
    for pos in range(length):
        acc = 0
        for j, (xj, yj) in enumerate(shares):
            num = den = 1
            for m, (xm, _) in enumerate(shares):
                if m == j:
                    continue
                num = _mul(num, xm)  # product of x_m
                den = _mul(den, xj ^ xm)  # product of (x_j - x_m) == xor in GF(2^8)
            lagrange = _div(num, den)  # basis poly evaluated at 0
            acc ^= _mul(yj[pos], lagrange)
        out.append(acc)
    return bytes(out)


# --- serialization: a share as a portable hex string "k.x.yhex" --------------
def share_to_str(x: int, y: bytes, k: int) -> str:
    return f"{k:02x}.{x:02x}.{y.hex()}"


def share_from_str(s: str) -> tuple[int, int, bytes]:
    k_hex, x_hex, y_hex = s.strip().split(".")
    return int(k_hex, 16), int(x_hex, 16), bytes.fromhex(y_hex)
