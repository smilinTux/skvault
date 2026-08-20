"""Resolve non-secret SSH metadata for scoped vault consumers.

The metadata record contains paths to already-protected key and known-hosts
files, never key bytes or passwords. References use ``skvault://ssh/NAME`` and
resolve below a single operator-controlled directory.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MAX_RECORD_BYTES = 16 * 1024


def _metadata_root() -> Path:
    configured = os.environ.get("SKVAULT_SSH_METADATA_DIR")
    return (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".config" / "skvault" / "ssh"
    )


def resolve_ssh(reference: str) -> dict[str, Any]:
    """Resolve ``skvault://ssh/NAME`` to validated, non-secret file metadata."""
    prefix = "skvault://ssh/"
    if not reference.startswith(prefix):
        raise ValueError("SSH metadata reference must use skvault://ssh/NAME")
    name = reference[len(prefix) :]
    if not _NAME.fullmatch(name):
        raise ValueError("invalid SSH metadata name")
    root = _metadata_root().resolve()
    record_path = root / f"{name}.json"
    if record_path.is_symlink() or not record_path.is_file():
        raise ValueError("SSH metadata record must be a regular non-symlink file")
    stat = record_path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise PermissionError("SSH metadata record must be owned by this user and mode 0600")
    if stat.st_size > _MAX_RECORD_BYTES:
        raise ValueError("SSH metadata record is too large")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid SSH metadata JSON") from exc
    if not isinstance(record, dict):
        raise ValueError("SSH metadata must be a JSON object")
    allowed = {"username", "identity_file", "known_hosts_file"}
    if set(record) != allowed:
        raise ValueError("SSH metadata contains missing or unsupported fields")
    if any(key in record for key in ("password", "private_key", "token", "secret")):
        raise ValueError("SSH metadata must never contain inline secrets")
    return {key: str(record[key]) for key in sorted(allowed)}
