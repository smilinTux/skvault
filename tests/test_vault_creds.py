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


# ---- notes, custom fields, creds-put ---------------------------------------

def _cli(vc, monkeypatch, tmp_path, args, stdin=None):
    from click.testing import CliRunner

    from skvault import config
    from skvault.cli import build_cli

    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    return CliRunner().invoke(build_cli(), args, input=stdin)


def test_put_creates_then_get_returns_notes_and_fields(vc, monkeypatch, tmp_path):
    from skvault import config

    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    action, err = vc.put(
        "Forge API",
        username="bot",
        url="https://forge.example",
        password="pw1",
        notes="line one\nPAT: tok_abc123",
        fields={"region": "nor"},
    )
    assert (action, err) == ("created", None)
    m, err = vc.get("forge api")
    assert err is None and len(m) == 1
    assert m[0]["notes"] == "line one\nPAT: tok_abc123"
    assert m[0]["fields"] == {"region": "nor"}
    assert m[0]["password"] == "pw1"
    # backup written before the save, 0600
    backups = list((tmp_path / "state" / "kdbx-backups").iterdir())
    assert len(backups) == 1 and (backups[0].stat().st_mode & 0o777) == 0o600


def test_get_deep_matches_notes_only_when_asked(vc, monkeypatch, tmp_path):
    from skvault import config

    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    vc.put("Plain Site", notes="the token is hidden-needle-42")
    assert vc.get("hidden-needle-42")[0] == []
    hits, _ = vc.get("hidden-needle-42", deep=True)
    assert [h["title"] for h in hits] == ["Plain Site"]


def test_put_updates_only_given_fields_and_reports_unchanged(vc, monkeypatch, tmp_path):
    from skvault import config

    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    assert vc.put("GitHub", append_notes="PAT: ghp_x") == ("updated", None)
    m = vc.get("github")[0][0]
    assert m["password"] == "ghsecret" and m["username"] == "octocat"
    assert m["notes"] == "PAT: ghp_x"
    assert vc.put("GitHub", username="octocat") == ("unchanged", None)
    assert vc.put("GitHub", fields={"scope": "repo"}, remove_fields=[]) == ("updated", None)
    assert vc.put("GitHub", remove_fields=["scope"]) == ("updated", None)
    assert vc.get("github")[0][0]["fields"] == {}


def test_put_modes_and_guards(vc, monkeypatch, tmp_path):
    from skvault import config

    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    assert vc.put("GitHub", mode="create")[1].startswith("entry 'GitHub' already exists")
    assert vc.put("Nope", mode="update")[1].startswith("no entry titled")
    assert "built-in" in vc.put("GitHub", fields={"Password": "x"})[1]
    assert vc.put("  ")[1] == "title is required"


def test_cli_get_hides_notes_and_fields_unless_show(vc, monkeypatch, tmp_path):
    vc.put("Notes Site", notes="secret-note-value", fields={"apikey": "k-123"})
    r = _cli(vc, monkeypatch, tmp_path, ["creds-get", "notes site"])
    assert r.exit_code == 0, r.output
    assert "secret-note-value" not in r.output and "k-123" not in r.output
    assert "notes: 1 line(s) (hidden" in r.output and "field apikey: (hidden)" in r.output
    r = _cli(vc, monkeypatch, tmp_path, ["creds-get", "notes site", "--show"])
    assert "secret-note-value" in r.output and "k-123" in r.output


def test_cli_get_field_prints_one_raw_value(vc, monkeypatch, tmp_path):
    vc.put("Notes Site", notes="a\nb", fields={"apikey": "k-123"})
    r = _cli(vc, monkeypatch, tmp_path, ["creds-get", "notes site", "--field", "notes"])
    assert r.exit_code == 0 and r.output == "a\nb\n"
    r = _cli(vc, monkeypatch, tmp_path, ["creds-get", "notes site", "--field", "apikey"])
    assert r.output == "k-123\n"
    r = _cli(vc, monkeypatch, tmp_path, ["creds-get", "notes site", "--field", "missing"])
    assert r.exit_code == 2
    r = _cli(vc, monkeypatch, tmp_path, ["creds-get", "e", "--field", "password"])
    assert r.exit_code == 2  # several matches


def test_cli_put_reads_secrets_from_stdin_only(vc, monkeypatch, tmp_path):
    r = _cli(vc, monkeypatch, tmp_path,
             ["creds-put", "New Svc", "--user", "svc", "--stdin", "field:token"], stdin="tok-999\n")
    assert r.exit_code == 0, r.output
    assert "tok-999" not in r.output
    assert vc.get("new svc")[0][0]["fields"]["token"] == "tok-999"
    r = _cli(vc, monkeypatch, tmp_path,
             ["creds-put", "New Svc", "--stdin", "append-notes"], stdin="first\nsecond\n")
    assert vc.get("new svc")[0][0]["notes"] == "first\nsecond"
    r = _cli(vc, monkeypatch, tmp_path, ["creds-put", "New Svc", "--generate", "24"])
    assert r.exit_code == 0 and "pass:" not in r.output
    assert len(vc.get("new svc")[0][0]["password"]) == 24
    r = _cli(vc, monkeypatch, tmp_path, ["creds-put", "New Svc", "--set", "noequals"])
    assert r.exit_code == 2
