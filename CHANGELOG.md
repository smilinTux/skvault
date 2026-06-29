# Changelog

All notable changes to `skvault` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **sk-standards doc set** — `SOP.md` (9 sections + mermaid architecture diagram & the
  unlock→seal→KeePass sequence diagram), `SECURITY.md` (threat model + the
  never-holds-master guarantee + audit log), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, this
  `CHANGELOG.md`, `LICENSE`, and `docs/crypto-architecture.md` (per-surface inventory +
  FIPS cites). README rebuilt as a hub with the `capauth ← skvault → consumers` picture, a
  quickstart, and a `Related projects / See also` cross-link block. Stated maturity tier
  **T0 — Classical** + `CRYPTOGRAPHY_STANDARD` compliance line (delegates seal/unseal to
  `capauth`; holds no master). Per the sk-standards `SK_REPO_DOC_STANDARD`.

## [0.1.0] — 2026-06-29

### Added

- **Initial release — split out of `skingest`** (EPIC `11eeac9e`) so secrets management is
  its own component. Depends on `capauth.seal` (the one seal/unseal implementation).
  - `vault` — gpg-agent **lock lifecycle**: `unlock` (preset passphrase via
    `gpg-preset-passphrase`), `lock` (`gpgconf --kill gpg-agent`), no-prompt
    `vault_unlocked()` probe, `status_line()`, `notify_if_changed()` (sk-alert on state
    change), and the opt-in memorable **unlock-word** (AES-256 symmetric blob) for the
    Hermes path.
  - `vault_creds` — **agent-accessible KeePass** without holding the master: the `.kdbx`
    master is PGP-sealed to your key via `capauth.seal`, openable only while unlocked;
    per-entry `get` / `list` (never bulk), every access audit-logged to
    `~/clawd/logs/keepass-access.log`.
  - `vault_recovery` + `shamir` — **sovereign social recovery**: passphrase split k-of-n
    over GF(256) (information-theoretic), each share PGP-sealed to one holder's key
    (HashiCorp-Vault unseal model).
  - `totp` — **RFC 6238** 2nd-factor gate on recovery / sensitive actions.
  - `config` — **transition-safe** resolution: `SKVAULT_*` env with `SKINGEST_*` fallbacks
    and legacy `~/.config/skmemory/` blob paths, so the live vault keeps working post-split.
  - `cli` — click command group exposed as the **`skvault-backend`** console script; driven
    by the stable `skvault` shim (`~/.skenv/bin/skvault`):
    `unlock | lock | status | get | list | creds-* | vault-*`.

[Unreleased]: https://github.com/smilinTux/skvault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/smilinTux/skvault/releases/tag/v0.1.0
