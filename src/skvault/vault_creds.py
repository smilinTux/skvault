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
import shutil
import time
from pathlib import Path

from capauth import seal as capseal

from skvault import config, vault

AUDIT_LOG = config.AUDIT_LOG

# How many pre-write copies of the kdbx to keep. The live DB is ~1.8 MB with
# over 1,500 entries, so unbounded backups are real disk, but a write to a
# credential store has no undo and losing the only copy of a secret is worse.
BACKUP_KEEP = 5
# Distinct from any hand-made backup name, so pruning can never reach one.
BACKUP_PREFIX = ".bak-autowrite-"


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


def _ensure_group(kp, path: str):
    """Resolve a `a/b/c` group path, creating any missing level. Returns the group."""
    grp = kp.root_group
    for name in [part for part in path.split("/") if part]:
        child = next((g for g in grp.subgroups if g.name == name), None)
        if child is None:
            child = kp.add_group(grp, name)
        grp = child
    return grp


def _backup_db(db: str) -> str | None:
    """Copy the kdbx aside BEFORE a write, then prune to BACKUP_KEEP newest.

    pykeepass saves in place, so a failed or bad write lands on top of the only
    copy. The backup is the pre-write bytes, mode 0600 like the DB it mirrors.
    """
    src = Path(db)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "%06dZ" % (
        time.time_ns() // 1000 % 1000000
    )
    bak = src.with_name(src.name + BACKUP_PREFIX + stamp)
    try:
        shutil.copy2(src, bak)
        os.chmod(bak, 0o600)
    except OSError as e:
        return f"backup failed: {str(e)[:80]}"
    # Prune ONLY our own copies. The live DB sits beside hand-made backups with
    # their own names (bak-rot-20261018, bak-pre-laptop-secrets-...). A glob of
    # `.bak-*` would see those too, and pruning by lexicographic name across two
    # naming schemes is how an automated writer deletes a human's only snapshot.
    old = sorted(src.parent.glob(src.name + BACKUP_PREFIX + "*"))
    for stale in old[:-BACKUP_KEEP]:
        try:
            stale.unlink()
        except OSError:
            pass  # a backup we cannot prune is not a reason to block the write
    return None


def add(
    title: str,
    username: str,
    password: str,
    url: str = "",
    notes: str = "",
    group: str | None = None,
    overwrite: bool = False,
) -> tuple[bool, str | None]:
    """Write one credential into the kdbx. Returns (ok, error_str).

    The vault was read-only until now, so every write had to be done by hand in
    a GUI. That is fine for a human adding one password and useless for anything
    automated: a generated service secret could be produced but not stored, which
    is how secrets end up pasted into terminals and transcripts instead.

    Refuses to clobber by default. An existing title is a refusal, not a silent
    replace, because overwriting the wrong entry destroys the only copy of a
    secret and there is no undo. `overwrite=True` updates in place rather than
    adding a second entry with the same title, since duplicate titles make
    `get()` ambiguous and the caller cannot tell which one is live.

    `group` is a `a/b` path, created if missing. The live vault files related
    secrets together (the skflow Windmill keys live under `skworld`), so an
    automated write needs to be able to land beside the entries a human filed
    by hand instead of piling up in the root group.
    """
    if not title or not password:
        return False, "title and password are both required"
    kp, err = _open()
    if err:
        return False, err
    existing = [e for e in kp.entries if e.title == title]
    if existing and not overwrite:
        return False, f"entry {title!r} already exists (pass overwrite to replace it)"
    if existing:
        entry = existing[0]
        entry.password = password
        if username:
            entry.username = username
        if url:
            entry.url = url
        if notes:
            entry.notes = notes
        action = "updated"
    else:
        kp.add_entry(
            _ensure_group(kp, group) if group else kp.root_group,
            title=title,
            username=username or "",
            password=password,
            url=url or "",
            notes=notes or "",
        )
        action = "added"
    bak_err = _backup_db(_db_path())
    if bak_err:
        return False, bak_err + " (refusing to write without a backup)"
    try:
        kp.save()
    except Exception as e:  # noqa: BLE001 - KeePass exposes backend-specific failures
        return False, f"save failed: {str(e)[:80]}"
    # The value never reaches the audit log; only that a write happened.
    _audit("add", f"title={title!r} action={action} group={group or '/'}")
    return True, None


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
