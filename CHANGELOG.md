# Changelog

All notable changes to `skvault` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Cleared the legacy Ruff formatting and lint debt across `src/` and `tests/`,
  made the CI lint job blocking, and updated the operator SOP to reflect the
  enforced release gate. Broad exception catches remain only at intentional
  fail-closed CLI/backend boundaries and subprocess calls now state their
  non-raising behavior explicitly.

### Added

- **`docs-evidence` block + `docs-check` CI gate.** `SOP.md` now ends with an executable
  evidence block of 9 hermetic, repo-local, offline checks: the `skvault-backend` entry
  point (and the *absence* of a bare `skvault` script that would clobber the shim), the
  *absence* of the shim from this tree, the seven documented modules, version lockstep
  between `pyproject.toml` and `__version__`, the GPL-3.0-or-later licence in both places,
  crypto-by-custody (`capauth.seal` imported, no crypto library imported anywhere in the
  package), the Shamir `split`/`combine` public API, the five self-report functions, and
  the error strings SOP section 8 quotes verbatim. Every check was negative-tested.
  `.github/workflows/docs-check.yml` runs tiers 1 and 2 on push and pull_request.
  No CI workflow is cited as evidence: `ci.yml` is not hermetic (see below).

### Documentation

- **Stated ownership explicitly: skvault is the fleet's single credential vault.** KeePass
  `.kdbx` access, Shamir k-of-n social recovery and TOTP live here and nowhere else. They
  were stripped out of `skingest` in commit `7a0cf6f` on 2026-06-29 (EPIC `11eeac9e`), and
  `skingest`'s own README and SOP were corrected in August 2026 to point here. SOP section
  1 and the README now say so with the commit and the date, so a reader arriving from a
  stale reference lands in the right place.
- **Documented that the `skvault` command is not in this repository.** `pip install`
  produces `skvault-backend`; the `skvault` verb is a bash shim at `~/.skenv/bin/skvault`
  that this package deliberately does not ship (shipping it would make every install
  clobber the shim). It is invisible from the git tree, it renames verbs
  (`status` to `vault-status`, `get` to `creds-get`, `list` to `creds-list`), it defaults
  to `status` with no arguments, and it is host state rather than repo state. Covered in
  SOP section 3 and the README, and pinned by an evidence check on its absence.
- **Documented what CI does and does not gate.** The `test`, `build`, and `lint` jobs are
  real gates. More importantly `ci.yml` is **not hermetic**: it installs
  `capauth @ git+https://github.com/smilinTux/capauth.git@main` over the network, so a
  green run depends on GitHub reachability and on whatever `capauth@main` currently is.
  Recorded in SOP section 4 as the reason no CI workflow appears in the evidence block.
- **Corrected the versioning story.** The version is **not** tag-derived: it is hardcoded
  in two places that must be edited together (`pyproject.toml` and
  `src/skvault/__init__.py`), the repo has **zero git tags**, and it has never been
  published to PyPI. SOP sections 5 and 9 now say that plainly instead of implying a
  release flow that has never run, and an evidence check pins the two versions in lockstep.

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
