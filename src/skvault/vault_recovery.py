"""
vault_recovery.py — sovereign social recovery of the vault passphrase.

Split the passphrase k-of-n (Shamir/GF256), seal each share to ONE holder's PGP
public key, and store the sealed shares. Recovery: any k holders decrypt THEIR
share (with their own key) → combine → passphrase → optionally rotate it. No
single holder (not even the agent) can recover alone. HashiCorp-Vault unseal model.

Layout: config.RECOVERY_DIR (default ~/.config/skmemory/recovery/)
    manifest.json                 {holders, threshold k, n, created}
    <holder-slug>.share.asc       PGP message: the Shamir share, sealed to <holder>
"""
from __future__ import annotations

import json
import re
import subprocess

from skvault import config, shamir

REC_DIR = config.RECOVERY_DIR
MANIFEST = REC_DIR / "manifest.json"


def _slug(uid: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", uid.lower()).strip("-")


def _have_pubkey(uid: str) -> bool:
    return subprocess.run(["gpg", "--list-keys", uid], capture_output=True).returncode == 0


def _encrypt_to(uid: str, text: str) -> str | None:
    r = subprocess.run(
        ["gpg", "--batch", "--yes", "--armor", "--trust-model", "always", "--recipient", uid, "--encrypt"],
        input=text.encode(), capture_output=True)
    return r.stdout.decode() if r.returncode == 0 else None


def share_init(passphrase: str, holders: list[str], k: int) -> dict:
    """Split passphrase k-of-n and seal one share to each holder's key."""
    n = len(holders)
    if not (2 <= k <= n <= 255):
        raise ValueError("require 2 <= threshold <= #holders")
    missing = [h for h in holders if not _have_pubkey(h)]
    if missing:
        raise ValueError(f"no public key in keyring for: {', '.join(missing)}")
    shares = shamir.split(passphrase.encode(), n, k)
    REC_DIR.mkdir(parents=True, exist_ok=True)
    sealed = []
    for (x, y), holder in zip(shares, holders):
        blob = _encrypt_to(holder, shamir.share_to_str(x, y, k))
        if blob is None:
            raise RuntimeError(f"failed to seal share to {holder}")
        path = REC_DIR / f"{_slug(holder)}.share.asc"
        path.write_text(blob)
        path.chmod(0o600)
        sealed.append(str(path))
    manifest = {"holders": holders, "threshold": k, "n": n,
                "shares": {h: f"{_slug(h)}.share.asc" for h in holders}}
    MANIFEST.write_text(json.dumps(manifest, indent=2))
    return {"sealed": sealed, "threshold": k, "n": n}


def provide_share(holder: str) -> tuple[int, int, bytes] | None:
    """A holder contributes by decrypting THEIR sealed share with their own key."""
    path = REC_DIR / f"{_slug(holder)}.share.asc"
    if not path.exists():
        return None
    r = subprocess.run(["gpg", "--batch", "--quiet", "--decrypt", str(path)],
                       capture_output=True)
    if r.returncode != 0:
        return None  # that holder's key isn't available/unlocked
    return shamir.share_from_str(r.stdout.decode())


def recover(providers: list[str]) -> str | None:
    """Collect shares from the given holders (each decrypts their own) → passphrase."""
    parts = [p for p in (provide_share(h) for h in providers) if p]
    if not parts:
        return None
    ks = {k for k, _, _ in parts}
    threshold = min(ks)
    if len(parts) < threshold:
        return None  # not enough shares to meet the embedded threshold
    shares = [(x, y) for _, x, y in parts]
    try:
        return shamir.combine(shares).decode()
    except Exception:
        return None


def status() -> dict:
    if not MANIFEST.exists():
        return {"configured": False}
    m = json.loads(MANIFEST.read_text())
    present = [h for h in m["holders"] if (REC_DIR / f"{_slug(h)}.share.asc").exists()]
    return {"configured": True, "threshold": m["threshold"], "n": m["n"],
            "holders": m["holders"], "shares_present": present}
