"""
config.py — skvault configuration + transition-safe path resolution.

The live vault was set up under skingest; skvault keeps it working unchanged by
falling back to every legacy location:

  • KeePass DB:      SKVAULT_KEEPASS_DB        → fallback SKINGEST_KEEPASS_DB
  • KeePass keyfile: SKVAULT_KEEPASS_KEYFILE   → fallback SKINGEST_KEEPASS_KEYFILE
  • Sealed master:   ~/.config/skvault/keepass-master.asc
                       → fallback ~/.config/skmemory/keepass-master.asc
  • PGP recipients:  resolved via capauth.seal.recipients()
                     (CAPAUTH_PGP_RECIPIENT → SKINGEST_PGP_RECIPIENT)

On import we softly load the legacy skingest.env and a skvault.env (setdefault —
never clobbering a value already exported in the real shell environment) so that
SKINGEST_KEEPASS_DB written there by the existing `creds-init` is still honored.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Env-file bootstrap (transition continuity)
# ---------------------------------------------------------------------------

SKVAULT_ENV_PATH = Path(
    os.environ.get("SKVAULT_ENV", Path.home() / ".config" / "skvault" / "skvault.env")
)
_LEGACY_ENV_PATH = Path(
    os.environ.get(
        "SKINGEST_ENV", Path.home() / ".config" / "skmemory" / "skingest.env"
    )
)


def _load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines via setdefault (real shell env wins; we fill gaps)."""
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


# skvault.env first (its keys win over legacy among the files), then legacy.
_load_env_file(SKVAULT_ENV_PATH)
_load_env_file(_LEGACY_ENV_PATH)

# ---------------------------------------------------------------------------
# Sealed-master blob locations
# ---------------------------------------------------------------------------

MASTER_BLOB_SKVAULT = Path.home() / ".config" / "skvault" / "keepass-master.asc"
MASTER_BLOB_LEGACY = Path.home() / ".config" / "skmemory" / "keepass-master.asc"


def master_blob_read() -> Path:
    """Where to READ the sealed master from: skvault path if present, else legacy.

    During the transition the live blob still lives under skmemory/, so reads keep
    working; once `creds-init` runs under skvault it migrates to the skvault path.
    """
    return MASTER_BLOB_SKVAULT if MASTER_BLOB_SKVAULT.exists() else MASTER_BLOB_LEGACY


def master_blob_write() -> Path:
    """Where to WRITE a freshly sealed master (the sovereign skvault location)."""
    return MASTER_BLOB_SKVAULT


# ---------------------------------------------------------------------------
# KeePass DB / keyfile resolution
# ---------------------------------------------------------------------------


def keepass_db() -> str | None:
    return (
        os.environ.get("SKVAULT_KEEPASS_DB")
        or os.environ.get("SKINGEST_KEEPASS_DB")
        or None
    )


def keepass_keyfile() -> str | None:
    return (
        os.environ.get("SKVAULT_KEEPASS_KEYFILE")
        or os.environ.get("SKINGEST_KEEPASS_KEYFILE")
        or None
    )


# ---------------------------------------------------------------------------
# Misc paths
# ---------------------------------------------------------------------------

_DATA_DIR = Path(os.environ.get("SKVAULT_DATA_DIR", Path.home() / ".skingest"))
STATE_DIR = _DATA_DIR / "state"

# Social-recovery + TOTP keep their legacy homes for live continuity.
RECOVERY_DIR = Path.home() / ".config" / "skmemory" / "recovery"
TOTP_SECRET_FILE = Path.home() / ".config" / "skmemory" / "totp.secret"

AUDIT_LOG = Path.home() / "clawd" / "logs" / "keepass-access.log"
