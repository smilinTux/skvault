"""
vault_creds.py — agent-accessible KeePass, without the agent holding the master key.

Your .kdbx stays yours. Its MASTER PASSWORD is PGP-sealed to your key
(chef@skworld.io) via capauth.seal. The agent can open the DB ONLY while the vault
is UNLOCKED (your gpg-agent has your passphrase cached / chat-word / TOTP) —
locked == no access. Lookups are per-entry, never a dump, and every access is
audit-logged.

Honest limit: at use-time the specific retrieved password passes through the
agent (it must, to use it). The guarantees are: no master password held, no
persistent storage, access only while you've authorized, full audit trail.

Config: SKVAULT_KEEPASS_DB (fallback SKINGEST_KEEPASS_DB), SKVAULT_KEEPASS_KEYFILE.
Sealed master: ~/.config/skvault/keepass-master.asc (fallback ~/.config/skmemory/).
Audit: ~/clawd/logs/keepass-access.log
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from capauth import seal as capseal

from skvault import config, vault

AUDIT_LOG = config.AUDIT_LOG


def _db_path() -> str | None:
    return config.keepass_db()


def _keyfile() -> str | None:
    return config.keepass_keyfile()


def _audit(action: str, detail: str) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {action}  {detail}\n")


def init(db_path: str, master_pw: str, keyfile: str | None = None) -> bool:
    """Seal the KeePass master password to your PGP key + record the db path."""
    if not capseal.recipients():
        raise RuntimeError(
            "no PGP recipient (CAPAUTH_PGP_RECIPIENT / SKINGEST_PGP_RECIPIENT) — set up your key first"
        )
    blob = capseal.seal(master_pw, sign_by="")  # sealed to chef@; no signature needed
    master_blob = config.master_blob_write()
    master_blob.parent.mkdir(parents=True, exist_ok=True)
    master_blob.write_text(blob)
    master_blob.chmod(0o600)
    # persist db path (+ keyfile) to skvault.env
    env = config.SKVAULT_ENV_PATH
    lines: dict[str, str] = {}
    if env.exists():
        for ln in env.read_text().splitlines():
            if "=" in ln and not ln.strip().startswith("#"):
                k, _, v = ln.partition("=")
                lines[k.strip()] = v.strip()
    abs_db = os.path.abspath(os.path.expanduser(db_path))
    lines["SKVAULT_KEEPASS_DB"] = abs_db
    os.environ["SKVAULT_KEEPASS_DB"] = abs_db  # live for this process too
    if keyfile:
        abs_kf = os.path.abspath(os.path.expanduser(keyfile))
        lines["SKVAULT_KEEPASS_KEYFILE"] = abs_kf
        os.environ["SKVAULT_KEEPASS_KEYFILE"] = abs_kf
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text(
        "# skvault local config (written by creds-init)\n"
        + "\n".join(f"{k}={v}" for k, v in lines.items())
        + "\n"
    )
    _audit("init", f"db={abs_db}")
    return True


def _master() -> str | None:
    """The master password — only available when the vault is UNLOCKED."""
    blob = config.master_blob_read()
    if not blob.exists():
        return None
    return capseal.unseal(blob.read_text())  # None when locked


def _open():
    """Open the kdbx; returns (kp, error_str). kp is None on locked/missing/fail."""
    db = _db_path()
    if not db or not Path(db).exists():
        return None, "no KeePass DB configured (run `skvault creds-init`)"
    master = _master()
    if master is None:
        return (
            None,
            "vault LOCKED — run `skvault unlock` first (agent can't open the DB while locked)",
        )
    try:
        from pykeepass import PyKeePass

        return PyKeePass(db, password=master, keyfile=_keyfile()), None
    except ImportError:
        return None, "pykeepass not installed (pip install pykeepass)"
    except Exception as e:  # noqa: BLE001 - KeePass exposes backend-specific failures
        return None, f"open failed (wrong master?): {str(e)[:80]}"
    finally:
        master = None  # forget


def get(query: str) -> tuple[list[dict], str | None]:
    kp, err = _open()
    if err:
        return [], err
    q = query.lower()
    matches = []
    for e in kp.entries:
        hay = " ".join(filter(None, [e.title, e.username, e.url])).lower()
        if q in hay:
            matches.append(
                {
                    "title": e.title,
                    "username": e.username,
                    "password": e.password,
                    "url": e.url,
                }
            )
    _audit("get", f"query={query!r} matched={[m['title'] for m in matches]}")
    return matches, None


def list_titles() -> tuple[list[str], str | None]:
    kp, err = _open()
    if err:
        return [], err
    titles = sorted(e.title for e in kp.entries if e.title)
    _audit("list", f"count={len(titles)}")
    return titles, None


def status() -> dict:
    return {
        "db_configured": bool(_db_path()),
        "db_exists": bool(_db_path() and Path(_db_path()).exists()),
        "master_sealed": config.master_blob_read().exists(),
        "vault_unlocked": vault.vault_unlocked() is True,
    }
