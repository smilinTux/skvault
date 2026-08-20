import json
from pathlib import Path

import pytest

from skvault.ssh_metadata import resolve_ssh


def _record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str = "node") -> Path:
    monkeypatch.setenv("SKVAULT_SSH_METADATA_DIR", str(tmp_path))
    path = tmp_path / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "username": "operator",
                "identity_file": "/secure/id_ed25519",
                "known_hosts_file": "/secure/known_hosts",
            }
        )
    )
    path.chmod(0o600)
    return path


def test_resolve_ssh_returns_metadata_only(tmp_path: Path, monkeypatch) -> None:
    _record(tmp_path, monkeypatch)
    assert resolve_ssh("skvault://ssh/node") == {
        "identity_file": "/secure/id_ed25519",
        "known_hosts_file": "/secure/known_hosts",
        "username": "operator",
    }


@pytest.mark.parametrize("reference", ["ssh/node", "skvault://ssh/../node", "skvault://x"])
def test_resolve_ssh_rejects_unscoped_reference(tmp_path, monkeypatch, reference) -> None:
    _record(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        resolve_ssh(reference)


def test_resolve_ssh_rejects_unsafe_record(tmp_path: Path, monkeypatch) -> None:
    path = _record(tmp_path, monkeypatch)
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        resolve_ssh("skvault://ssh/node")


def test_resolve_ssh_rejects_symlink(tmp_path: Path, monkeypatch) -> None:
    real = _record(tmp_path, monkeypatch, "real")
    link = tmp_path / "node.json"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        resolve_ssh("skvault://ssh/node")
