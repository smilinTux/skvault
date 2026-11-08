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


def _custom_fields(e) -> dict:
    try:
        return {k: v for k, v in (e.custom_properties or {}).items() if v is not None}
    except Exception:  # noqa: BLE001 - older pykeepass / odd entries
        return {}


def get(query: str, deep: bool = False) -> tuple[list[dict], str | None]:
    """Match entries on title/user/url; with deep=True also on notes and custom fields.

    Every match carries its notes and custom fields: tokens and recovery codes
    often live there, not in the password field.
    """
    kp, err = _open()
    if err:
        return [], err
    q = query.lower()
    matches = []
    for e in kp.entries:
        fields = _custom_fields(e)
        parts = [e.title, e.username, e.url]
        if deep:
            parts += [e.notes, *fields.keys(), *fields.values()]
        hay = " ".join(str(x) for x in parts if x).lower()
        if q in hay:
            matches.append(
                {
                    "title": e.title,
                    "username": e.username,
                    "password": e.password,
                    "url": e.url,
                    "notes": e.notes or "",
                    "fields": fields,
                }
            )
    _audit("get", f"query={query!r} deep={deep} matched={[m['title'] for m in matches]}")
    return matches, None


BACKUP_KEEP = 10
_BUILTIN = ("title", "username", "password", "url", "notes", "tags", "otp")


def _backup_db(db: str) -> Path:
    """Copy the .kdbx aside (0600) before a write; keep the newest BACKUP_KEEP."""
    d = config.STATE_DIR / "kdbx-backups"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    dst = d / f"{Path(db).name}.{time.strftime('%Y%m%dT%H%M%S')}.{os.getpid()}"
    shutil.copy2(db, dst)
    os.chmod(dst, 0o600)
    olds = sorted(d.glob(f"{Path(db).name}.*"))
    for old in olds[:-BACKUP_KEEP]:
        old.unlink(missing_ok=True)
    return dst


def put(
    title: str,
    *,
    username: str | None = None,
    url: str | None = None,
    password: str | None = None,
    notes: str | None = None,
    append_notes: str | None = None,
    fields: dict | None = None,
    remove_fields: list | None = None,
    protect: set | None = None,
    group: str | None = None,
    mode: str = "upsert",
) -> tuple[str | None, str | None]:
    """Create or update ONE entry, matched by exact title (case-insensitive).

    mode: "upsert" (default), "create" (fail if it exists), "update" (fail if missing).
    Only the arguments given are changed; everything else on the entry is kept.
    Returns (action, error) where action is "created", "updated" or "unchanged".
    """
    if not title or not title.strip():
        return None, "title is required"
    fields = dict(fields or {})
    for name in list(fields) + list(remove_fields or []):
        if name.lower() in _BUILTIN:
            return None, f"{name!r} is a built-in field, use its own option"
    kp, err = _open()
    if err:
        return None, err
    same = [e for e in kp.entries if (e.title or "").lower() == title.lower()]
    if len(same) > 1:
        return None, f"{len(same)} entries are titled {title!r}; rename one first"
    entry = same[0] if same else None
    if entry is not None and mode == "create":
        return None, f"entry {title!r} already exists (drop --create-only to update it)"
    if entry is None and mode == "update":
        return None, f"no entry titled {title!r} (drop --update-only to create it)"

    changed: list[str] = []
    if entry is None:
        dest = kp.root_group
        if group:
            dest = kp.find_groups(path=group.split("/"), first=True) or kp.add_group(
                kp.root_group, group
            )
        entry = kp.add_entry(
            dest, title, username or "", password or "", url=url or None, notes=notes
        )
        action = "created"
        changed.append("entry")
    else:
        action = "updated"
        for attr, val in (("username", username), ("url", url), ("password", password)):
            if val is not None and getattr(entry, attr) != val:
                setattr(entry, attr, val)
                changed.append(attr)
        if notes is not None and (entry.notes or "") != notes:
            entry.notes = notes
            changed.append("notes")
    if append_notes:
        cur = entry.notes or ""
        entry.notes = (cur.rstrip("\n") + "\n" if cur else "") + append_notes
        changed.append("notes+")
    for name, val in fields.items():
        if _custom_fields(entry).get(name) != val:
            entry.set_custom_property(name, val, protect=name in (protect or set()))
            changed.append(f"field:{name}")
    for name in remove_fields or []:
        if name in _custom_fields(entry):
            entry.delete_custom_property(name)
            changed.append(f"-field:{name}")

    if not changed:
        _audit("put", f"title={title!r} unchanged")
        return "unchanged", None
    _backup_db(kp.filename)
    entry.touch(modify=True)
    kp.save()
    # names only, never values
    _audit("put", f"title={title!r} {action} changed={changed}")
    return action, None


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
