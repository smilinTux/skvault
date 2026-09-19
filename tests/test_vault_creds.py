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


# ---------------------------------------------------------------------------
# creds-add: the vault could only ever be READ from, so every write to the
# kdbx had to happen by hand in a GUI. That is the gap this closes.
# ---------------------------------------------------------------------------


def test_add_creates_a_new_entry(vc):
    ok, err = vc.add("skgit LFS_JWT_SECRET", "skgit", "s3cr3t-value")
    assert err is None, err
    assert ok is True
    matches, err = vc.get("skgit LFS_JWT_SECRET")
    assert err is None
    assert len(matches) == 1
    assert matches[0]["password"] == "s3cr3t-value"


def test_add_refuses_to_clobber_an_existing_entry(vc):
    ok, err = vc.add("GitHub", "someone-else", "different")
    assert ok is False
    assert "already exists" in (err or "")
    matches, _ = vc.get("GitHub")
    assert (
        matches[0]["password"] == "ghsecret"
    ), "the original must survive a refused add"


def test_add_overwrite_updates_in_place(vc):
    ok, err = vc.add("GitHub", "octocat", "rotated", overwrite=True)
    assert err is None and ok is True
    matches, _ = vc.get("GitHub")
    assert len(matches) == 1, "overwrite must update, never duplicate"
    assert matches[0]["password"] == "rotated"


def test_add_refuses_when_the_vault_is_locked(vc, monkeypatch):
    from capauth import seal

    monkeypatch.setattr(seal, "unseal", lambda ct: None)
    ok, err = vc.add("Should Not Land", "u", "p")
    assert ok is False
    assert "LOCK" in (err or "").upper()


def test_add_persists_across_a_reopen(vc):
    vc.add("Durable Entry", "svc", "written-once")
    titles, err = vc.list_titles()
    assert err is None
    assert (
        "Durable Entry" in titles
    ), "add() must save the kdbx, not just mutate in memory"


# ---------------------------------------------------------------------------
# creds-update / creds-delete (ea911b09): create closed only the create case;
# every other write still needed a GUI. That is the gap THESE close.
# ---------------------------------------------------------------------------


def test_update_changes_a_field_in_place_without_duplicating(vc):
    ok, err = vc.update("GitHub", password="rotated-gh")
    assert err is None and ok is True
    matches, _ = vc.get("GitHub")
    assert len(matches) == 1, "update must never create a duplicate title"
    assert matches[0]["password"] == "rotated-gh"
    assert matches[0]["username"] == "octocat", "untouched fields must not change"


def test_update_username_url_notes(vc):
    ok, err = vc.update(
        "GitHub", username="newcat", url="https://github.example", notes="rotate me"
    )
    assert err is None and ok is True
    matches, _ = vc.get("github.example")
    assert len(matches) == 1
    assert matches[0]["username"] == "newcat"
    assert matches[0]["url"] == "https://github.example"
    assert matches[0]["password"] == "ghsecret", "password untouched when not passed"


def test_update_refuses_when_the_entry_does_not_exist(vc):
    ok, err = vc.update("NoSuch Service", password="x")
    assert ok is False
    assert err is not None
    titles, _ = vc.list_titles()
    assert "NoSuch Service" not in titles, "refused update must not create an entry"


def test_update_refuses_with_no_fields(vc):
    ok, err = vc.update("GitHub")
    assert ok is False and err is not None


def test_update_refuses_ambiguous_duplicate_titles(vc, test_kdbx):
    from pykeepass import PyKeePass

    kp = PyKeePass(str(test_kdbx), password=TEST_MASTER)
    kp.add_entry(kp.root_group, title="GitHub", username="dupe", password="dupe")
    kp.save()
    ok, err = vc.update("GitHub", password="x")
    assert ok is False
    assert "ambiguous" in (err or "")


def test_update_persists_across_a_reopen(vc):
    vc.update("GitHub", notes="written by test")
    from pykeepass import PyKeePass

    kp = PyKeePass(str(Path(get_kdbx_path(vc))), password=TEST_MASTER)
    entry = next(e for e in kp.entries if e.title == "GitHub")
    assert entry.notes == "written by test"


def test_update_refuses_when_the_vault_is_locked(vc, monkeypatch):
    from capauth import seal

    monkeypatch.setattr(seal, "unseal", lambda ct: None)
    ok, err = vc.update("GitHub", password="x")
    assert ok is False
    assert "LOCK" in (err or "").upper()


def test_delete_removes_the_entry(vc):
    ok, err = vc.delete("Email Account")
    assert err is None and ok is True
    titles, _ = vc.list_titles()
    assert "Email Account" not in titles
    ok, err = vc.delete("Email Account")
    assert ok is False, "second delete must refuse: entry is gone"


def test_delete_refuses_when_the_entry_does_not_exist(vc):
    ok, err = vc.delete("Never Existed")
    assert ok is False and err is not None


def test_delete_refuses_ambiguous_duplicate_titles(vc, test_kdbx):
    from pykeepass import PyKeePass

    kp = PyKeePass(str(test_kdbx), password=TEST_MASTER)
    kp.add_entry(kp.root_group, title="GitHub", username="dupe", password="dupe")
    kp.save()
    ok, err = vc.delete("GitHub")
    assert ok is False
    assert "ambiguous" in (err or "")


def test_delete_refuses_when_the_vault_is_locked(vc, monkeypatch):
    from capauth import seal

    monkeypatch.setattr(seal, "unseal", lambda ct: None)
    ok, err = vc.delete("GitHub")
    assert ok is False
    assert "LOCK" in (err or "").upper()


def test_writes_are_audit_logged_without_secret_values(vc, tmp_path, monkeypatch):
    """AC2 + AC3: the audit log records titles/fields, never values."""
    import skvault.vault_creds as vc_mod

    log = tmp_path / "keepass-access.log"
    monkeypatch.setattr(vc_mod, "AUDIT_LOG", log)
    vc.update("GitHub", password="audit-me-not")
    vc.delete("Email Account")
    text = log.read_text()
    assert "audit-me-not" not in text, "password value must never be audit-logged"
    assert "update" in text and "delete" in text
    assert "GitHub" in text and "Email Account" in text, "AC2: title-only record"


def get_kdbx_path(vc):
    import os

    return os.environ["SKVAULT_KEEPASS_DB"]


# --- CLI layer: same throwaway harness, driven through the click runner ---


def _cli_env(monkeypatch, test_kdbx, tmp_path, unseal_ret=TEST_MASTER):
    """Point the CLI at the throwaway DB; audit log to tmp; optional locked."""
    from capauth import seal
    from click.testing import CliRunner

    import skvault.vault_creds as vc_mod
    from skvault import config

    monkeypatch.setenv("SKVAULT_KEEPASS_DB", str(test_kdbx))
    blob = tmp_path / "keepass-master.asc"
    if not blob.exists():
        blob.write_text(
            "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n"
        )
    monkeypatch.setattr(config, "master_blob_read", lambda: blob)
    monkeypatch.setattr(seal, "unseal", lambda ct: unseal_ret)
    log = tmp_path / "keepass-access.log"
    monkeypatch.setattr(vc_mod, "AUDIT_LOG", log)
    import importlib

    importlib.reload(vc_mod)
    monkeypatch.setattr(config, "master_blob_read", lambda: blob)
    monkeypatch.setattr(seal, "unseal", lambda ct: unseal_ret)
    monkeypatch.setattr(vc_mod, "AUDIT_LOG", log)
    return CliRunner(), log


def test_cli_creds_update_username_via_runner(monkeypatch, test_kdbx, tmp_path):
    runner, _ = _cli_env(monkeypatch, test_kdbx, tmp_path)
    from skvault.cli import build_cli

    result = runner.invoke(build_cli(), ["creds-update", "GitHub", "--username", "newcat"])
    assert result.exit_code == 0, result.output
    assert "updated" in result.output


def test_cli_creds_update_password_stdin_via_runner(monkeypatch, test_kdbx, tmp_path):
    runner, _ = _cli_env(monkeypatch, test_kdbx, tmp_path)
    from skvault.cli import build_cli

    result = runner.invoke(
        build_cli(), ["creds-update", "GitHub", "--password-stdin"], input="piped-new-pw\n"
    )
    assert result.exit_code == 0, result.output
    matches, _ = vc_get("GitHub")
    assert matches[0]["password"] == "piped-new-pw"


def test_cli_creds_update_refuses_argv_password(monkeypatch, test_kdbx, tmp_path):
    """AC3: a secret on the command line is a hard error, not a fallback."""
    runner, _ = _cli_env(monkeypatch, test_kdbx, tmp_path)
    from skvault.cli import build_cli

    result = runner.invoke(
        build_cli(), ["creds-update", "GitHub", "--password", "argv-secret"]
    )
    assert result.exit_code != 0
    assert "argv-secret" not in result.output, "refusal must not echo the secret back"


def test_cli_creds_update_missing_entry_refuses(monkeypatch, test_kdbx, tmp_path):
    runner, _ = _cli_env(monkeypatch, test_kdbx, tmp_path)
    from skvault.cli import build_cli

    result = runner.invoke(build_cli(), ["creds-update", "Ghost", "--url", "https://x"])
    assert result.exit_code != 0
    assert "Ghost" not in [t for t in []]  # placeholder, real check below
    titles, _ = _list_titles_via_lib()
    assert "Ghost" not in titles


def test_cli_creds_delete_requires_yes(monkeypatch, test_kdbx, tmp_path):
    """AC2: bare creds-delete refuses by default and changes nothing."""
    runner, _ = _cli_env(monkeypatch, test_kdbx, tmp_path)
    from skvault.cli import build_cli

    result = runner.invoke(build_cli(), ["creds-delete", "GitHub"])
    assert result.exit_code != 0
    assert "--yes" in result.output
    titles, _ = _list_titles_via_lib()
    assert "GitHub" in titles, "refused delete must not remove the entry"


def test_cli_creds_delete_with_yes_removes(monkeypatch, test_kdbx, tmp_path):
    runner, log = _cli_env(monkeypatch, test_kdbx, tmp_path)
    from skvault.cli import build_cli

    result = runner.invoke(build_cli(), ["creds-delete", "GitHub", "--yes"])
    assert result.exit_code == 0, result.output
    titles, _ = _list_titles_via_lib()
    assert "GitHub" not in titles
    log_text = log.read_text()
    assert "GitHub" in log_text and "delete" in log_text


def test_cli_creds_delete_missing_entry_refuses(monkeypatch, test_kdbx, tmp_path):
    runner, _ = _cli_env(monkeypatch, test_kdbx, tmp_path)
    from skvault.cli import build_cli

    result = runner.invoke(build_cli(), ["creds-delete", "Ghost", "--yes"])
    assert result.exit_code != 0


def test_cli_write_refuses_when_locked(monkeypatch, test_kdbx, tmp_path):
    """AC4: both verbs refuse and say so when the vault is locked."""
    runner, _ = _cli_env(monkeypatch, test_kdbx, tmp_path, unseal_ret=None)
    from skvault.cli import build_cli

    r1 = runner.invoke(build_cli(), ["creds-update", "GitHub", "--url", "https://x"])
    r2 = runner.invoke(build_cli(), ["creds-delete", "GitHub", "--yes"])
    for r in (r1, r2):
        assert r.exit_code != 0
        assert "LOCK" in r.output.upper()


def test_cli_commands_registered():
    from skvault.cli import build_cli

    names = set(build_cli().commands.keys())
    assert "creds-update" in names
    assert "creds-delete" in names


def vc_get(q):
    from skvault import vault_creds

    return vault_creds.get(q)


def _list_titles_via_lib():
    from skvault import vault_creds

    return vault_creds.list_titles()
