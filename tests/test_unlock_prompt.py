"""The interactive `skvault unlock` prompt accepts EITHER the GPG key passphrase OR the unlock-word.

Chef typed his unlock-word at the passphrase prompt and it failed with "mistyped passphrase"; the
word only worked via `--word`. The prompt now tries the input as the passphrase first, then as the
word. Never touches gpg-agent: vault.unlock / vault.unlock_with_word are monkeypatched.
"""

from __future__ import annotations

from click.testing import CliRunner

from skvault import cli, vault

PASS = "long-real-gpg-passphrase-xyz"
WORD = "memorableword"


def _patch(monkeypatch, calls):
    state = {"unlocked": False}

    def fake_unlock(pw):
        calls.append(("pass", pw))
        state["unlocked"] = pw == PASS
        return state["unlocked"]

    def fake_word(w):
        calls.append(("word", w))
        state["unlocked"] = w == WORD
        return state["unlocked"]

    monkeypatch.setattr(vault, "unlock", fake_unlock)
    monkeypatch.setattr(vault, "unlock_with_word", fake_word)
    monkeypatch.setattr(vault, "vault_unlocked", lambda: False)
    monkeypatch.setattr(vault, "status_line", lambda: "STATUS")
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": prompt_input["value"])


prompt_input = {"value": ""}


def test_prompt_accepts_passphrase(monkeypatch):
    calls = []
    _patch(monkeypatch, calls)
    prompt_input["value"] = PASS
    r = CliRunner().invoke(cli.build_cli(), ["unlock"])
    assert r.exit_code == 0, r.output
    assert calls == [("pass", PASS)]  # word path not needed


def test_prompt_falls_back_to_word(monkeypatch):
    calls = []
    _patch(monkeypatch, calls)
    prompt_input["value"] = WORD
    r = CliRunner().invoke(cli.build_cli(), ["unlock"])
    assert r.exit_code == 0, r.output
    assert calls == [("pass", WORD), ("word", WORD)]


def test_prompt_wrong_input_fails_and_mentions_both(monkeypatch):
    calls = []
    _patch(monkeypatch, calls)
    prompt_input["value"] = "nope"
    r = CliRunner().invoke(cli.build_cli(), ["unlock"])
    assert r.exit_code != 0
    assert calls == [("pass", "nope"), ("word", "nope")]
    assert "unlock-word" in r.output.lower() or "word" in r.output.lower()


def test_word_flag_unchanged(monkeypatch):
    calls = []
    _patch(monkeypatch, calls)
    r = CliRunner().invoke(cli.build_cli(), ["unlock", "--word", WORD])
    assert r.exit_code == 0, r.output
    assert calls == [("word", WORD)]
