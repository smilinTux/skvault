"""
cli.py — `skvault` command-line interface (click).

The stable `skvault` shim delegates here. Command names match what the shim and
hooks expect:

  skvault unlock [--word W]    skvault lock              skvault vault-status [--notify]
  skvault seal-word           skvault creds-init ...    skvault creds-get <q> [--show]
  skvault creds-list [filter] skvault creds-status
  skvault creds-add <title> [--generate] [--overwrite]
  skvault vault-share-init --holders a,b,c [--threshold k]
  skvault vault-recover --providers a,b [--totp CODE]   skvault vault-recovery-status
  skvault vault-totp-init [--force]                     skvault vault-totp-verify CODE
"""

from __future__ import annotations

import getpass
from pathlib import Path

import click

# ---------------------------------------------------------------------------
# Sacred-vault lock lifecycle
# ---------------------------------------------------------------------------


@click.command(
    "unlock",
    help="Unlock the sacred vault (passphrase → gpg-agent) so creds/search can decrypt",
)
@click.option(
    "--word",
    default=None,
    help="Unlock via the sealed chat unlock-word (Hermes path) instead of the passphrase",
)
def cmd_unlock(word: str | None) -> None:
    from skvault import vault

    if vault.vault_unlocked() is True:
        click.echo("🔓 already unlocked.")
        raise SystemExit(0)
    if word:  # chat unlock-word path (Hermes can call this)
        ok = vault.unlock_with_word(word)
    else:
        try:
            pw = getpass.getpass(
                "  Chef GPG key passphrase — the vault key, NOT your KeePass master (hidden): "
            )
        except (EOFError, KeyboardInterrupt):
            click.echo("\n  cancelled.")
            raise SystemExit(1)
        if not pw:
            click.echo("  no passphrase given.")
            raise SystemExit(1)
        ok = vault.unlock(pw)
        del pw
    line = vault.status_line()
    if ok:
        click.echo(line)
    else:
        click.echo(
            "✗ unlock failed — almost always a mistyped passphrase (paste it from your"
        )
        click.echo(
            "  password manager; it's a long string). The passphrase ALONE unlocks —"
        )
        click.echo(
            "  a seal-word is optional (only for memorable-word / Hermes unlock)."
        )
    vault.notify_if_changed(line)
    raise SystemExit(0 if ok else 1)


@click.command("lock", help="Lock the sacred vault (flush gpg-agent cache)")
def cmd_lock() -> None:
    from skvault import vault

    vault.lock()
    line = vault.status_line()
    click.echo(line)
    vault.notify_if_changed(line)
    raise SystemExit(0)


@click.command(
    "vault-status",
    help="Show whether the sacred (encrypted) vault is unlocked or locked",
)
@click.option(
    "--notify", is_flag=True, help="Also fire an sk-alert if the lock state changed"
)
def cmd_vault_status(notify: bool) -> None:
    from skvault import vault

    line = vault.status_line()
    click.echo(line)
    if notify:
        vault.notify_if_changed(line)
    raise SystemExit(0)


@click.command(
    "seal-word",
    help="One-time: seal your passphrase under a memorable unlock-word (for chat/Hermes unlock)",
)
def cmd_seal_word() -> None:
    from skvault import vault

    click.echo(
        "  Seal your passphrase under a memorable unlock-word (for chat/Hermes unlock)."
    )
    click.echo(
        "  ⚠ The word becomes a credential and travels through chat/logs. Rotate freely."
    )
    try:
        word = getpass.getpass("  Unlock-word (hidden): ")
        pw = getpass.getpass(
            "  Chef GPG key passphrase — the vault key, NOT your KeePass master (hidden): "
        )
    except (EOFError, KeyboardInterrupt):
        click.echo("\n  cancelled.")
        raise SystemExit(1)
    if not word or not pw:
        click.echo("  both required.")
        raise SystemExit(1)
    if not vault.verify_passphrase(pw):
        del word, pw
        click.echo(
            "  ✗ that passphrase is INCORRECT (it wouldn't unlock) — not sealing. Re-run and paste it."
        )
        raise SystemExit(1)
    ok = vault.seal_word(word, pw)
    del word, pw
    click.echo("  ✓ passphrase verified + sealed under your word.")
    click.echo('  Unlock anytime with:  skvault unlock --word "<your word>"')
    raise SystemExit(0 if ok else 1)


# ---------------------------------------------------------------------------
# KeePass credential vault
# ---------------------------------------------------------------------------


@click.command("creds-init", help="Seal a KeePass .kdbx master password to your key")
@click.argument("db")
@click.option("--keyfile", default=None, help="Optional KeePass keyfile path")
def cmd_creds_init(db: str, keyfile: str | None) -> None:
    from skvault import vault_creds as vc

    if not Path(db).expanduser().exists():
        click.echo(f"  ✗ no such .kdbx: {db}")
        raise SystemExit(1)
    try:
        master = getpass.getpass("  KeePass master password (hidden): ")
    except (EOFError, KeyboardInterrupt):
        click.echo("\n  cancelled.")
        raise SystemExit(1)
    if not master:
        click.echo("  no password.")
        raise SystemExit(1)
    try:
        vc.init(db, master, keyfile=keyfile)
    except Exception as e:  # noqa: BLE001 - CLI boundary reports backend failures
        click.echo(f"  ✗ {e}")
        raise SystemExit(1)
    finally:
        del master
    click.echo(
        "  ✓ KeePass master sealed to your key. Agent can open it ONLY while the vault is unlocked."
    )
    click.echo("  Use: skvault unlock → skvault creds-get <site>")
    raise SystemExit(0)


@click.command(
    "creds-get", help="Look up a credential by site/title/user (needs vault unlocked)"
)
@click.argument("query")
@click.option("--show", is_flag=True, help="Reveal the password (otherwise hidden)")
def cmd_creds_get(query: str, show: bool) -> None:
    from skvault import vault_creds as vc

    matches, err = vc.get(query)
    if err:
        click.echo(f"  ✗ {err}")
        raise SystemExit(1)
    if not matches:
        click.echo(f"  (no entry matching {query!r})")
        raise SystemExit(0)
    for m in matches:
        click.echo(f"  • {m['title']}  ({m.get('url') or '—'})")
        click.echo(f"      user: {m['username']}")
        if show:
            click.echo(f"      pass: {m['password']}")
        else:
            click.echo("      pass: (hidden — add --show to reveal)")
    raise SystemExit(0)


@click.command(
    "creds-list",
    help="List KeePass entry titles (optional filter; needs vault unlocked)",
)
@click.argument("filter_text", required=False, default=None)
def cmd_creds_list(filter_text: str | None) -> None:
    from skvault import vault_creds as vc

    titles, err = vc.list_titles()
    if err:
        click.echo(f"  ✗ {err}")
        raise SystemExit(1)
    if filter_text:
        titles = [t for t in titles if filter_text.lower() in (t or "").lower()]
    click.echo(
        f"  {len(titles)} entries{f' matching {filter_text!r}' if filter_text else ''}:"
    )
    for t in titles:
        click.echo(f"    • {t}")
    if not filter_text and len(titles) > 50:
        click.echo(
            "  (tip: `creds-list <text>` to filter, or `creds-get <site> --show` to fetch one)"
        )
    raise SystemExit(0)


@click.command(
    "creds-add",
    help="Write a credential into the KeePass vault (needs vault unlocked)",
)
@click.argument("title")
@click.option("--username", default="", help="Username / account for the entry.")
@click.option("--url", default="", help="Site or service URL.")
@click.option("--notes", default="", help="Free-text notes.")
@click.option(
    "--generate",
    is_flag=True,
    help="Generate a strong random secret instead of prompting. Never echoed.",
)
@click.option(
    "--length", default=44, show_default=True, help="Bytes of entropy when generating."
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Replace an existing entry with this title instead of refusing.",
)
def cmd_creds_add(
    title: str,
    username: str,
    url: str,
    notes: str,
    generate: bool,
    length: int,
    overwrite: bool,
) -> None:
    """Add or update one entry.

    The secret is never taken as a command-line argument: that would put it in
    shell history and in the process list, where anything on the box can read
    it. It is either generated here or prompted for without echo.
    """
    import secrets

    from skvault import vault_creds as vc

    if generate:
        password = secrets.token_urlsafe(length)
    else:
        password = getpass.getpass("  secret (hidden): ")
        if not password:
            click.echo("  ✗ empty secret, nothing written")
            raise SystemExit(1)
        confirm = getpass.getpass("  confirm: ")
        if password != confirm:
            click.echo("  ✗ secrets do not match, nothing written")
            raise SystemExit(1)

    _ok, err = vc.add(
        title, username, password, url=url, notes=notes, overwrite=overwrite
    )
    password = None  # forget
    if err:
        click.echo(f"  ✗ {err}")
        raise SystemExit(1)
    click.echo(f"  ✓ stored {title!r}" + (" (generated)" if generate else ""))
    click.echo("  Read it back with: skvault creds-get <title> --show")
    raise SystemExit(0)


@click.command(
    "creds-update",
    help="Change fields on ONE existing entry (needs vault unlocked). Never creates.",
)
@click.argument("title")
@click.option(
    "--username", default=None, help="New username (not a secret; argument is fine)."
)
@click.option("--url", default=None, help="New url (not a secret; argument is fine).")
@click.option(
    "--notes", default=None, help="New notes (not a secret; argument is fine)."
)
@click.option(
    "--password",
    "password_opt",
    default=None,
    hidden=True,  # deliberately undocumented: AC3 makes an argv secret a hard error
)
@click.option(
    "--generate",
    is_flag=True,
    help="Generate a strong random password. Never echoed.",
)
@click.option(
    "--length", default=44, show_default=True, help="Bytes of entropy when generating."
)
@click.option(
    "--password-stdin",
    "password_stdin",
    is_flag=True,
    help="Read the new password from stdin (no echo, no argv).",
)
def cmd_creds_update(
    title: str,
    username: str | None,
    url: str | None,
    notes: str | None,
    password_opt: str | None,
    generate: bool,
    length: int,
    password_stdin: bool,
) -> None:
    """Update fields on one existing entry, in place.

    Same secret discipline as creds-add: the password is generated in-process,
    prompted for without echo, or read from stdin, never taken as a
    command-line argument. A missing title is a refusal, not a silent create;
    use creds-add for that.
    """
    import secrets
    import sys

    from skvault import vault_creds as vc

    # AC3 is a hard error, not a fallback: an argv-secret has already leaked to
    # shell history and the process list, so 'it still works' is not good enough.
    if password_opt is not None:
        click.echo(
            "  ✗ --password would put the secret in shell history and the process list;"
            " generate it (--generate) or pipe it in (--password-stdin)"
        )
        raise SystemExit(2)
    if generate and password_stdin:
        click.echo("  ✗ pass either --generate or --password-stdin, not both")
        raise SystemExit(2)

    password: str | None = None
    if generate:
        password = secrets.token_urlsafe(length)
    elif password_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            click.echo("  ✗ empty password on stdin, nothing written")
            raise SystemExit(1)

    if password is None and username is None and url is None and notes is None:
        click.echo(
            "  ✗ nothing to update (pass username/url/notes or a password source)"
        )
        raise SystemExit(2)

    _ok, err = vc.update(
        title, password=password, username=username, url=url, notes=notes
    )
    password = None  # forget
    if err:
        click.echo(f"  ✗ {err}")
        raise SystemExit(1)
    click.echo(
        f"  ✓ updated {title!r}"
        + (" (password generated, never echoed)" if generate else "")
    )
    raise SystemExit(0)


@click.command(
    "creds-delete",
    help="Remove ONE existing entry (needs vault unlocked; needs --yes).",
)
@click.argument("title")
@click.option(
    "--yes",
    "-y",
    "yes",
    is_flag=True,
    help="Actually delete. Without this flag the command refuses and changes nothing.",
)
def cmd_creds_delete(title: str, yes: bool) -> None:
    """Delete one existing entry.

    Deletion is irreversible and the kdbx keeps no trash, so a bare
    `creds-delete <title>` refuses on purpose: the default must be the safe
    outcome, especially for automation. The audit line records the title only.
    """
    from skvault import vault_creds as vc

    if not yes:
        click.echo(
            f"  ✗ refusing to delete {title!r} without an explicit confirmation flag (--yes)"
        )
        raise SystemExit(1)
    _ok, err = vc.delete(title)
    if err:
        click.echo(f"  ✗ {err}")
        raise SystemExit(1)
    click.echo(f"  ✓ deleted {title!r}")
    raise SystemExit(0)


@click.command("creds-status", help="Show KeePass vault config + lock state")
def cmd_creds_status() -> None:
    from skvault import vault_creds as vc

    s = vc.status()
    click.echo(
        f"  KeePass: db_configured={s['db_configured']} db_exists={s['db_exists']} "
        f"master_sealed={s['master_sealed']} vault_unlocked={s['vault_unlocked']}"
    )
    raise SystemExit(0)


# ---------------------------------------------------------------------------
# Social recovery (Shamir k-of-n) + TOTP 2nd factor
# ---------------------------------------------------------------------------


@click.command(
    "vault-share-init",
    help="Split your passphrase k-of-n across holders' PGP keys (social recovery)",
)
@click.option(
    "--holders", required=True, help="Comma-separated PGP uids of share holders"
)
@click.option(
    "--threshold",
    type=int,
    default=None,
    help="k shares required to recover (default: majority)",
)
def cmd_vault_share_init(holders: str, threshold: int | None) -> None:
    from skvault import vault_recovery as vr

    hs = [h.strip() for h in holders.split(",") if h.strip()]
    if len(hs) < 2:
        click.echo("  need >= 2 --holders (comma-separated PGP uids)")
        raise SystemExit(1)
    k = threshold or (len(hs) // 2 + 1)
    click.echo(f"  Split your passphrase {k}-of-{len(hs)} across: {', '.join(hs)}")
    click.echo(
        f"  Each share is sealed to that holder's PGP key. Any {k} can reconstruct; fewer reveal nothing."
    )
    try:
        pw = getpass.getpass("  Passphrase to protect (hidden): ")
    except (EOFError, KeyboardInterrupt):
        click.echo("\n  cancelled.")
        raise SystemExit(1)
    if not pw:
        click.echo("  no passphrase.")
        raise SystemExit(1)
    try:
        r = vr.share_init(pw, hs, k)
    except Exception as e:  # noqa: BLE001 - CLI boundary reports recovery failures
        click.echo(f"  ✗ {e}")
        raise SystemExit(1)
    finally:
        del pw
    click.echo(
        f"  ✓ sealed {len(r['sealed'])} shares (threshold {r['threshold']}-of-{r['n']})."
    )
    click.echo("  Recover anytime with: skvault vault-recover --providers <k holders>")
    raise SystemExit(0)


@click.command(
    "vault-recover",
    help="Recover the passphrase from k holders (each decrypts their sealed share)",
)
@click.option(
    "--providers",
    required=True,
    help="Comma-separated holders contributing their shares",
)
@click.option(
    "--totp",
    "totp_code",
    default=None,
    help="Current TOTP code (required if a TOTP 2nd factor is configured)",
)
def cmd_vault_recover(providers: str, totp_code: str | None) -> None:
    from skvault import totp
    from skvault import vault_recovery as vr

    ps = [h.strip() for h in providers.split(",") if h.strip()]
    st = vr.status()
    if not st.get("configured"):
        click.echo("  no recovery configured — run `skvault vault-share-init` first.")
        raise SystemExit(1)
    if totp.configured():
        if not totp_code or not totp.verify_stored(totp_code):
            click.echo(
                "  ✗ TOTP required: pass a current code with --totp <6 digits> (2nd factor is configured)."
            )
            raise SystemExit(1)
        click.echo("  ✓ TOTP 2nd factor verified.")
    pw = vr.recover(ps)
    if pw is None:
        click.echo(
            f"  ✗ recovery failed — need >= {st['threshold']} holders, each with their key "
            "available/unlocked to decrypt their share."
        )
        raise SystemExit(1)
    click.echo("  ✓ passphrase recovered (handle carefully — shown once):")
    click.echo(f"      {pw}")
    click.echo("  Rotate it now if desired:  gpg --change-passphrase chef@skworld.io")
    raise SystemExit(0)


@click.command(
    "vault-recovery-status", help="Show social-recovery configuration (k-of-n, holders)"
)
def cmd_vault_recovery_status() -> None:
    from skvault import vault_recovery as vr

    st = vr.status()
    if not st.get("configured"):
        click.echo("  social recovery: NOT configured (`skvault vault-share-init`)")
        raise SystemExit(0)
    click.echo(
        f"  social recovery: {st['threshold']}-of-{st['n']}  holders={', '.join(st['holders'])}"
    )
    click.echo(f"  sealed shares present: {len(st['shares_present'])}/{st['n']}")
    raise SystemExit(0)


@click.command("vault-totp-init", help="Create an Authy/TOTP 2nd-factor for recovery")
@click.option("--force", is_flag=True, help="Replace an existing TOTP factor")
def cmd_vault_totp_init(force: bool) -> None:
    import shutil
    import subprocess

    from skvault import totp

    if totp.configured() and not force:
        click.echo("  TOTP already configured (use --force to replace).")
        raise SystemExit(1)
    secret = totp.init()
    uri = totp.provisioning_uri(secret)
    click.echo("  ✓ TOTP factor created. Add it to Authy / Google Authenticator:")
    click.echo(f"      secret: {secret}")
    click.echo(f"      uri:    {uri}")
    if shutil.which("qrencode"):
        click.echo("\n  Scan this QR:")
        subprocess.run(["qrencode", "-t", "ANSIUTF8", uri], check=False)
    else:
        click.echo(
            "  (install qrencode for a scannable QR, or paste the secret/uri manually)"
        )
    click.echo("  Verify with: skvault vault-totp-verify <6-digit code>")
    raise SystemExit(0)


@click.command("vault-totp-verify", help="Verify a TOTP code")
@click.argument("code")
def cmd_vault_totp_verify(code: str) -> None:
    from skvault import totp

    if not totp.configured():
        click.echo("  no TOTP configured — run `skvault vault-totp-init`.")
        raise SystemExit(1)
    ok = totp.verify_stored(code)
    click.echo("  ✓ valid code" if ok else "  ✗ invalid/expired code")
    raise SystemExit(0 if ok else 1)


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

_COMMANDS = [
    cmd_unlock,
    cmd_lock,
    cmd_vault_status,
    cmd_seal_word,
    cmd_creds_init,
    cmd_creds_get,
    cmd_creds_add,
    cmd_creds_update,
    cmd_creds_delete,
    cmd_creds_list,
    cmd_creds_status,
    cmd_vault_share_init,
    cmd_vault_recover,
    cmd_vault_recovery_status,
    cmd_vault_totp_init,
    cmd_vault_totp_verify,
]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="skvault", message="%(version)s")
def cli() -> None:
    """skvault — sovereign secrets vault (gpg-agent SEAL + KeePass + Shamir + TOTP)."""


for _c in _COMMANDS:
    cli.add_command(_c)


def build_cli() -> click.Group:
    """Return the assembled click Group (used by tests + the console entry point)."""
    return cli


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
