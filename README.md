# skvault — sovereign secrets vault

> **What it is:** the SKWorld secrets **vault** — a KeePass-backed credential store with
> sovereign social recovery (Shamir k-of-n) and a TOTP second factor, built on top of
> `capauth`'s seal/unseal primitive. The agent **never holds your KeePass master**: it is
> PGP-sealed to your sovereign identity and only unsealable while the vault is unlocked
> (your passphrase cached in `gpg-agent`).
>
> **Maturity tier:** **T0 — Classical** (delegates all seal/unseal to `capauth`; rides
> `capauth`'s PQC migration — see [SOP §9](SOP.md#9-maturity-tier--version-reference)).
> **Status:** experimental · pre-1.0 (`0.1.0`) · NOT independently audited.

**This repo is the fleet's single home for the credential vault.** If you are looking for
KeePass `.kdbx` access, Shamir k-of-n social recovery, or TOTP, they are here and nowhere
else. They were stripped out of `skingest` in commit
[`7a0cf6f`](https://github.com/smilinTux/skingest/commit/7a0cf6f) on **2026-06-29**
(EPIC `11eeac9e`); `skingest`'s own README and SOP were corrected in August 2026 to point
here, including a troubleshooting row for anyone still hunting `creds-get` / `unlock` /
`vault-recover` in that repo.

The ownership split: **`capauth` is the crypto home** (identity + sign/verify +
seal/unseal); **`skvault` is the vault** (KeePass creds + recovery + Shamir + TOTP + lock
lifecycle) that *depends on* `capauth.seal` and implements no encryption of its own;
**`skingest` is pure ingestion** (also seals via `capauth.seal`) and holds no vault.

---

## The picture — capauth ← skvault → consumers

```
   ┌───────────┐  seal/unseal   ┌──────────────────────────┐   shim    ┌──────────────────┐
   │  capauth  │◀──primitive────│         skvault          │◀──verb────│  consumers       │
   │ (crypto   │   capauth.seal │  vault · vault_creds      │  skvault  │  skos.secrets    │
   │  home:    │───────────────▶│  vault_recovery · shamir  │──────────▶│  skguide         │
   │  identity │   gpg-agent    │  totp · config            │  unlock/  │  .claude hooks   │
   │  + SEAL)  │                │                           │  get/list │  Hermes DM       │
   └───────────┘                └────────────┬──────────────┘           └──────────────────┘
                                             │ PyKeePass (master = PGP-sealed blob)
                                             ▼
                                  ┌──────────────────────┐
                                  │  your KeePass .kdbx  │  (your DB stays yours)
                                  └──────────────────────┘
```

`capauth` owns the **one** encryption implementation (`capauth.seal` — encrypt-at-rest to
your PGP key, gated by `gpg-agent`). `skvault` owns everything *above* that primitive that
makes a pile of sealed blobs into a vault: the lock lifecycle, agent-accessible KeePass,
social recovery, and the 2nd factor. Downstream consumers never import `skvault` directly —
they call the **stable `skvault` shim**, so the backend can move without touching a single
hook.

---

## Quickstart

```bash
# install into the shared venv
~/.skenv/bin/pip install -e /home/cbrd21/clawd/skcapstone-repos/skvault
# the console script lands as `skvault-backend`; the stable verb is the shim:
#   ~/.skenv/bin/skvault  →  skvault-backend

# one-time: seal your KeePass master to your PGP key
skvault creds-init ~/secrets.kdbx            # prompts for the KeePass master (then forgets it)

# day-to-day
skvault unlock                               # passphrase → gpg-agent (the vault key, NOT the KeePass master)
skvault status                               # 🔓 unlocked / 🔒 locked / 🔑 no local secret key
skvault get github --show                    # look up a credential by site/title/user
skvault list aws                             # list entry titles (optional filter)
skvault lock                                 # flush gpg-agent → vault sealed again
```

Optional sovereign hardening:

```bash
skvault vault-share-init --holders chef,lumina,jarvis --threshold 2   # Shamir 2-of-3 social recovery
skvault vault-totp-init                                                # Authy/Google-Authenticator 2nd factor
skvault seal-word                                                      # memorable chat unlock-word (Hermes path)
```

### ⚠️ `skvault` is not in this repository

Every command above says `skvault`, but **`pip install` gives you `skvault-backend`.**
The `skvault` verb is a thin bash shim at `~/.skenv/bin/skvault` that **this package does
not ship and that does not exist anywhere in this git tree** (grep for it and you find
nothing). That is deliberate: shipping a `skvault` console script would make every
`pip install` clobber the shim, and the shim is the seam that lets the backend move
without touching a single consumer.

It maps `status` → `vault-status`, `get` → `creds-get`, `list` → `creds-list`, defaults to
`status` when given no arguments, and passes everything else through unchanged. So a
missing `status` command in `cli.py` is not a bug. The shim is **host state, not repo
state**: it is not versioned, installed, or tested here, and on a node that lacks it every
consumer fails with `skvault: command not found` while `skvault-backend` works fine.
Details and how to recreate it: [SOP §3](SOP.md#3-build) and
[SOP §7](SOP.md#7-api--reference).

---

## What it owns / does NOT do

- ✅ **Owns:** the gpg-agent **lock lifecycle**, agent-accessible **KeePass** (per-entry,
  audit-logged, master never held), **Shamir** k-of-n social recovery, **TOTP** 2nd
  factor, and transition-safe path/config resolution.
- ❌ **Does NOT** implement encryption itself — every seal/unseal goes through
  `capauth.seal` (one implementation). It is **not** a network service, **not** a KEM or
  transport, and **not** an identity authority (that's `capauth`).

The non-secret SSH metadata adapter accepts `username`, absolute protected
`identity_file` and `known_hosts_file` paths, plus optional validated transport
`hostname` and bounded `port` values.
It never returns key bytes, passwords, tokens, or inline SSH options.

---

## Docs

| Doc | What's in it |
|---|---|
| [SOP.md](SOP.md) | Operational source of truth — architecture (mermaid), build/test/release, config, full CLI reference, troubleshooting, maturity tier. |
| [SECURITY.md](SECURITY.md) | Threat model, the never-holds-master guarantee, audit log, reporting channel. |
| [docs/crypto-architecture.md](docs/crypto-architecture.md) | Per-surface crypto inventory (seal / word-blob / Shamir / TOTP / KeePass) with FIPS cites + hybrid-vs-classical. |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Branch/commit/test path · release log · conduct. |

---

## Related projects / See also

- ⬆️ **Depends on:** [capauth](https://github.com/smilinTux/capauth) — the crypto home;
  `skvault` delegates **all** seal/unseal to `capauth.seal` and resolves PGP recipients
  through it. skvault holds **no** encryption code of its own.
- ↔️ **Sibling:** [skingest](https://github.com/smilinTux/skingest) — pure ingestion; the
  vault's old home (this repo was split out of it, EPIC `11eeac9e`). skingest also seals
  via `capauth.seal`. Legacy `SKINGEST_*` env keys + `~/.config/skmemory/` blob paths stay
  honored for live continuity.
- ⬇️ **Used by:** `skos.secrets`, `skguide`, the `.claude` session hooks, and the Hermes
  DM unlock path — all via the stable `skvault` shim, never by importing this package.
- ↔️ **Sibling:** [skcomms](https://github.com/smilinTux/skcomms) — a `capauth.seal`
  consumer on the comms side; peer in the same crypto-delegation pattern.
- 📐 **Standards:** [sk-standards](https://github.com/smilinTux/sk-standards) — the
  doc/SOP standard, `CRYPTOGRAPHY_STANDARD`, `UNIFIED_INGRESS_STANDARD`, and the project
  graph this README links into.

---

🐧 **SK = staycuriousANDkeepsmilin** · sovereign infrastructure, honest claims.
