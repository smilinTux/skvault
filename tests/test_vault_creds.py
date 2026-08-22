"""
TDD for skvault — credential vault (KeePass) + CLI, WITHOUT touching the live vault.

Safety: we NEVER read the live .kdbx or the real keepass-master.asc, and we never
touch the running gpg-agent. We:
  • create a THROWAWAY .kdbx with a known test password via pykeepass,
  • point SKVAULT_KEEPASS_DB at it,
  • monkeypatch capauth.seal.unseal to return the test master (so the "vault unlocked"
    path is exercised without gpg-agent), and capauth.seal.recipients to a fake uid,
  • monkeypatch skvault.config.master_blob_read/write to a tmp blob.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from pykeepass import create_database

TEST_MASTER = "throwaway-master-pw-123"


@pytest.fixture()
def test_kdbx(tmp_path: Path) -> Path:
    """A throwaway KeePass DB with two entries, opened by TEST_MASTER."""
    db = tmp_path / "test.kdbx"
    kp = create_database(str(db), password=TEST_MASTER)
    g = kp.root_group
    kp.add_entry(
        g,
        title="GitHub",
        username="octocat",
        password="ghsecret",
        url="https://github.com",
    )
    kp.add_entry(
        g,
        title="Email Account",
        username="me@example.com",
        password="mailsecret",
        url="https://mail.example.com",
    )
    kp.save()
    return db


@pytest.fixture()
def vc(monkeypatch, tmp_path, test_kdbx):
    """Import skvault.vault_creds with the live vault fully mocked out."""
    from capauth import seal

    from skvault import config

    # Point at the throwaway DB; clear any legacy fallback.
    monkeypatch.setenv("SKVAULT_KEEPASS_DB", str(test_kdbx))
    monkeypatch.delenv("SKINGEST_KEEPASS_DB", raising=False)
    monkeypatch.delenv("SKVAULT_KEEPASS_KEYFILE", raising=False)
    monkeypatch.delenv("SKINGEST_KEEPASS_KEYFILE", raising=False)

    # Sealed-master blob lives in tmp; pretend the vault is UNLOCKED by having
    # unseal() return the test master (mirrors gpg-agent cache hit).
    blob = tmp_path / "keepass-master.asc"
    blob.write_text("-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n")
    monkeypatch.setattr(config, "master_blob_read", lambda: blob)
    monkeypatch.setattr(config, "master_blob_write", lambda: blob)

    monkeypatch.setattr(seal, "unseal", lambda ct: TEST_MASTER)
    monkeypatch.setattr(seal, "recipients", lambda: ["chef@test.local"])

    from skvault import vault_creds

    importlib.reload(vault_creds)
    # re-apply patches that the reload may have re-bound
    monkeypatch.setattr(config, "master_blob_read", lambda: blob)
    monkeypatch.setattr(seal, "unseal", lambda ct: TEST_MASTER)
    return vault_creds


def test_list_titles_unlocked(vc):
    titles, err = vc.list_titles()
    assert err is None
    assert "GitHub" in titles
    assert "Email Account" in titles


def test_get_match(vc):
    matches, err = vc.get("github")
    assert err is None
    assert len(matches) == 1
    assert matches[0]["title"] == "GitHub"
    assert matches[0]["password"] == "ghsecret"


def test_get_no_match(vc):
    matches, err = vc.get("nonexistent-xyz")
    assert err is None
    assert matches == []


def test_locked_blocks_open(vc, monkeypatch):
    from capauth import seal

    # vault LOCKED: unseal returns None (gpg-agent cache miss / pinentry cancel)
    monkeypatch.setattr(seal, "unseal", lambda ct: None)
    matches, err = vc.get("github")
    assert matches == []
    assert err is not None and "LOCK" in err.upper()


def test_status_shape(vc):
    s = vc.status()
    assert s["db_configured"] is True
    assert s["db_exists"] is True
    assert s["master_sealed"] is True


def test_shamir_roundtrip():
    from skvault import shamir

    secret = b"correct horse battery staple"
    shares = shamir.split(secret, n=5, k=3)
    assert shamir.combine(shares[:3]) == secret
    assert shamir.combine([shares[0], shares[2], shares[4]]) == secret


def test_shamir_serialization():
    from skvault import shamir

    shares = shamir.split(b"hello", n=3, k=2)
    x, y = shares[0]
    s = shamir.share_to_str(x, y, 2)
    k2, x2, y2 = shamir.share_from_str(s)
    assert (k2, x2, y2) == (2, x, y)


def test_totp_verify():
    from skvault import totp

    secret = totp.gen_secret()
    code = totp.now_code(secret)
    assert totp.verify(secret, code) is True
    assert totp.verify(secret, "000000") in (True, False)  # just must not raise


def test_cli_help_lists_commands():
    from skvault.cli import build_cli

    cli = build_cli()
    names = set(cli.commands.keys())
    for expected in [
        "unlock",
        "lock",
        "vault-status",
        "seal-word",
        "creds-init",
        "creds-get",
        "creds-list",
        "creds-status",
        "vault-share-init",
        "vault-recover",
        "vault-recovery-status",
        "vault-totp-init",
        "vault-totp-verify",
    ]:
        assert expected in names, f"missing command {expected}"


def test_cli_creds_list_runs(vc, monkeypatch, test_kdbx, tmp_path):
    """End-to-end: `creds-list` against the throwaway DB via the click runner."""
    from capauth import seal
    from click.testing import CliRunner

    from skvault import config

    monkeypatch.setenv("SKVAULT_KEEPASS_DB", str(test_kdbx))
    blob = tmp_path / "keepass-master.asc"
    if not blob.exists():
        blob.write_text(
            "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n"
        )
    monkeypatch.setattr(config, "master_blob_read", lambda: blob)
    monkeypatch.setattr(seal, "unseal", lambda ct: TEST_MASTER)

    from skvault.cli import build_cli

    runner = CliRunner()
    result = runner.invoke(build_cli(), ["creds-list"])
    assert result.exit_code == 0, result.output
    assert "GitHub" in result.output
