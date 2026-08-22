"""
vault.py — the gpg-agent SEAL LIFECYCLE (lock / unlock / status), skvault-owned.

capauth.seal owns the seal/unseal primitives (encrypt-at-rest to your PGP key).
This module owns everything ABOVE that primitive that makes the vault a vault:

  • vault_unlocked()      — probe (without prompting) whether the passphrase is
                            cached in gpg-agent → sacred content is decryptable now
  • unlock() / lock()     — preset the private-key passphrase into gpg-agent / flush it
  • verify_passphrase()   — confirm a passphrase is the real key passphrase
  • seal_word() / unlock_with_word()
                          — opt-in memorable chat unlock-word (Hermes path)
  • status_line() / notify_if_changed()
                          — one-line lock status + sk-alert on state change

All seal/unseal goes through capauth.seal so there is ONE encryption implementation.
"""

from __future__ import annotations

import glob
import os
import subprocess
from pathlib import Path

from capauth import seal as capseal

from skvault import config


def gpg_available() -> bool:
    return capseal.gpg_available()


def recipients() -> list[str]:
    return capseal.recipients()


def seal(plaintext: str, *, to=None, sign_by=None) -> str:
    return capseal.seal(plaintext, to=to, sign_by=sign_by)


CIPHER_PREFIX = "-----BEGIN PGP MESSAGE-----"

# Memorable chat unlock-word blob — legacy home, kept for live continuity.
_WORD_BLOB = Path(os.path.expanduser("~/.config/skmemory/vault-word.blob"))


def _has_secret_key(uid: str) -> bool:
    return (
        subprocess.run(
            ["gpg", "--list-secret-keys", uid], capture_output=True, check=False
        ).returncode
        == 0
    )


def vault_unlocked() -> bool | None:
    """
    Is the sacred vault readable right now? Probe WITHOUT prompting: seal a token to a
    recipient we hold the private key for, then try to decrypt with pinentry cancelled.
    Success → passphrase is cached in gpg-agent (UNLOCKED). Returns None if no recipient/
    secret key is available to probe.
    """
    if not (gpg_available() and recipients()):
        return None
    target = next((r for r in recipients() if _has_secret_key(r)), None)
    if not target:
        return None  # we don't even hold a private key for any recipient
    try:
        ct = seal("probe", to=[target], sign_by="")
    except Exception:  # noqa: BLE001 - unavailable SEAL backends mean an unknown lock state
        return None
    r = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "cancel", "--decrypt"],
        input=ct.encode(),
        capture_output=True,
        check=False,
    )
    return r.returncode == 0


def _preset_bin() -> str | None:
    for pat in (
        "/usr/lib*/gnupg*/gpg-preset-passphrase",
        "/usr/libexec/gpg-preset-passphrase",
    ):
        hits = glob.glob(pat)
        if hits:
            return hits[0]
    return None


def _encryption_keygrips(uid: str) -> list[str]:
    """Keygrips of encryption-capable (sub)keys for uid we hold the secret of."""
    out = subprocess.run(
        ["gpg", "--batch", "--with-keygrip", "--list-secret-keys", uid],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    grips, in_enc = [], False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith(("ssb", "sec")):
            in_enc = "e" in (s.split("[")[-1].split("]")[0].lower() if "[" in s else "")
        elif s.startswith("Keygrip") and in_enc:
            grips.append(s.split("=")[-1].strip())
    return grips


def unlock(passphrase: str) -> bool:
    """Preset the recipient's private-key passphrase into gpg-agent (cache TTL from gpg-agent.conf)."""
    preset = _preset_bin()
    if not preset:
        return False
    did = False
    for r in recipients():
        if not _has_secret_key(r):
            continue
        for grip in _encryption_keygrips(r):
            rc = subprocess.run(
                [preset, "--preset", "--passphrase", passphrase, grip],
                capture_output=True,
                check=False,
            ).returncode
            did = did or rc == 0
    return did and vault_unlocked() is True


def lock() -> None:
    """Flush gpg-agent's cached passphrases (reliable — restarts the agent)."""
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], capture_output=True, check=False)


def verify_passphrase(passphrase: str) -> bool:
    """
    True if `passphrase` is the correct key passphrase. NOTE: clears the gpg-agent
    cache first (gpgconf --kill) so the *provided* passphrase is actually tested
    rather than a cached one — i.e. this LOCKS the vault as a side effect.
    """
    if not recipients():
        return False
    try:
        ct = seal("verify", to=recipients()[:1], sign_by="")
    except Exception:  # noqa: BLE001 - any SEAL failure rejects the passphrase probe
        return False
    subprocess.run(
        ["gpgconf", "--kill", "gpg-agent"], capture_output=True, check=False
    )  # clear cache → test the real input
    r = subprocess.run(
        [
            "gpg",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            passphrase,
            "--decrypt",
        ],
        input=ct.encode(),
        capture_output=True,
        check=False,
    )
    return r.returncode == 0 and r.stdout.decode().strip() == "verify"


# --- chat unlock-word (opt-in, "sus"): a memorable word unseals the passphrase ---
# The real passphrase is symmetrically sealed in a blob that ONLY the word opens.
# Typing the word (e.g. via Hermes DM) unseals it → loads gpg-agent → forgets it.
# The agent/chat layer never persistently holds the real passphrase. CAVEAT: the
# word itself is a credential and travels through chat transport/logs.


def seal_word(word: str, passphrase: str) -> bool:
    """One-time: seal the real passphrase under a memorable unlock-word (AES256)."""
    _WORD_BLOB.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--symmetric",
            "--cipher-algo",
            "AES256",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            word,
            "--armor",
            "-o",
            str(_WORD_BLOB),
        ],
        input=passphrase.encode(),
        capture_output=True,
        check=False,
    )
    if r.returncode == 0:
        os.chmod(_WORD_BLOB, 0o600)
        return True
    return False


def unlock_with_word(word: str) -> bool:
    """Unseal the passphrase using the word, load it into gpg-agent, then forget it."""
    if not _WORD_BLOB.exists():
        return False
    r = subprocess.run(
        [
            "gpg",
            "--batch",
            "--quiet",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            word,
            "--decrypt",
            str(_WORD_BLOB),
        ],
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        return False
    passphrase = r.stdout.decode()
    try:
        return unlock(passphrase)
    finally:
        del passphrase  # forget


def notify_if_changed(line: str | None = None) -> bool:
    """Fire a Telegram sk-alert ONLY when the vault lock state changes. Returns True if alerted."""
    line = line or status_line()
    cur = (
        "unlocked"
        if line.startswith("🔓")
        else ("locked" if line.startswith("🔒") else "n/a")
    )
    state_dir = config.STATE_DIR
    state_dir.mkdir(parents=True, exist_ok=True)
    f = state_dir / "vault_lock_state"
    last = f.read_text().strip() if f.exists() else ""
    if cur == last:
        return False
    f.write_text(cur)
    if last and cur in ("locked", "unlocked"):  # don't alert on first-ever observation
        skalert = os.path.expanduser("~/.skenv/bin/sk-alert")
        if os.path.exists(skalert):
            level = "warn" if cur == "unlocked" else "info"
            subprocess.run(
                [skalert, "-l", level, "-k", "skvault-vault", "--", line],
                check=False,
            )
            return True
    return False


def status_line() -> str:
    """One-line vault lock status — for `skvault status` and the session hook."""
    if not recipients():
        return "⚪ SACRED VAULT — no PGP recipient configured (labels-only; run `skvault seal-word`)"
    state = vault_unlocked()
    rcpts = ", ".join(recipients())
    if state is True:
        return f"🔓 SACRED VAULT UNLOCKED — sacred/@chef-only content is DECRYPTABLE now (recipient: {rcpts})"
    if state is False:
        return f"🔒 SACRED VAULT LOCKED — sacred content is sealed; `skvault unlock` to read it (recipient: {rcpts})"
    return f"🔑 SACRED VAULT — encrypted to {rcpts}, but no local private key to read it here"
