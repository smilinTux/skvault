"""Resolve non-secret SSH metadata for scoped vault consumers.

The metadata record contains paths to already-protected key and known-hosts
files, never key bytes or passwords. References use ``skvault://ssh/NAME`` and
resolve below a single operator-controlled directory.
"""

from __future__ import annotations

import json
import os
import re
import stat
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
    try:
        root_stat = root.stat()
    except OSError as exc:
        raise ValueError("SSH metadata root is unavailable") from exc
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or root_stat.st_mode & 0o022
    ):
        raise PermissionError(
            "SSH metadata root must be owned by this user and not group/world writable"
        )
    record_path = root / f"{name}.json"
    try:
        fd = os.open(
            record_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ValueError(
            "SSH metadata record must be a regular non-symlink file"
        ) from exc
    try:
        record_stat = os.fstat(fd)
        if not stat.S_ISREG(record_stat.st_mode):
            raise ValueError("SSH metadata record must be a regular file")
        if record_stat.st_uid != os.getuid() or record_stat.st_mode & 0o077:
            raise PermissionError(
                "SSH metadata record must be owned by this user and mode 0600"
            )
        if record_stat.st_size > _MAX_RECORD_BYTES:
            raise ValueError("SSH metadata record is too large")
        chunks = []
        remaining = _MAX_RECORD_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_RECORD_BYTES:
            raise ValueError("SSH metadata record is too large")
    finally:
        os.close(fd)
    try:
        record = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid SSH metadata JSON") from exc
    if not isinstance(record, dict):
        # The caller supplied bytes; this rejects decoded content, not argument type.
        raise ValueError("SSH metadata must be a JSON object")  # noqa: TRY004
    allowed = {"username", "identity_file", "known_hosts_file"}
    if set(record) != allowed:
        raise ValueError("SSH metadata contains missing or unsupported fields")
    if any(key in record for key in ("password", "private_key", "token", "secret")):
        raise ValueError("SSH metadata must never contain inline secrets")
    return {key: str(record[key]) for key in sorted(allowed)}
