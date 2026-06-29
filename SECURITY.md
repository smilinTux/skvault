# Security Policy — skvault

`skvault` is **secrets-handling** software: it brokers *use-time* access to your real
credentials and the recovery of your vault passphrase. Read the **threat model** and the
**never-holds-master guarantee** before relying on it.

> ⚠️ **Experimental · pre-1.0 (`0.1.0`) · NOT independently security-audited.** No
> third-party audit, fuzzing, or formal review has been performed. skvault contains **no
> encryption code of its own** — it binds `capauth.seal` (the one seal/unseal
> implementation), GnuPG, and `pykeepass`; the original code here is the vault lifecycle,
> the agent-accessible KeePass layer, the Shamir split/combine, and the TOTP gate. **Review
> it yourself before production use.**

---

## CRYPTOGRAPHY_STANDARD compliance (the honest crypto posture)

Per the sk-standards
[CRYPTOGRAPHY_STANDARD](https://github.com/smilinTux/sk-standards), every claim is scoped to
**surface + FIPS/RFC number + hybrid-vs-classical**, backed by a self-report command.

- ✅ **Delegated crypto — one implementation.** skvault performs **no** asymmetric
  encryption itself. Every seal/unseal routes through **`capauth.seal`**; skvault owns only
  the vault *above* the primitive. Its asymmetric/at-rest tier **is** `capauth`'s.
- ✅ **The master is never held.** The KeePass master is **PGP-sealed to your sovereign
  identity** (`capauth.seal`) and is unsealable **only while `gpg-agent` has your passphrase
  cached** (`skvault unlock`). `skvault lock` (`gpgconf --kill gpg-agent`) revokes access.
  No master is stored in plaintext, cached, or written to disk by skvault.
- ✅ **Quantum-acceptable symmetric surfaces.** The optional unlock-word blob is **AES-256**
  symmetric (Grover-only → acceptable per the standard's floor; never AES-128). Social
  recovery is **Shamir k-of-n over GF(256)** — *information-theoretic*: any `k-1` shares
  reveal **nothing**. TOTP is **RFC 6238 HMAC-SHA1**, used as a *verifier* (2nd-factor
  gate), never as a key.
- ❌ **The seal surface is classical today.** Because seal/unseal delegates to `capauth`,
  whose live root is **Ed25519 / RSA-4096** (RFC 8032/4880), the sealed master and sealed
  Shamir shares are protected by **classical** OpenPGP and are **Shor-breakable** once a
  CRQC exists. This is **not** quantum-resistant on the seal surface — do not claim it. It
  rides `capauth`'s additive, reversible PQC migration; nothing changes in skvault.
- ❌ **Never** "quantum-proof," "quantum-safe," "unbreakable," or "CNSA 2.0 compliant." Say
  **"quantum-resistant" / "post-quantum"** and cite the surface + FIPS number.
- ❌ **Not transport / not a KEM / not an identity authority.** skvault establishes no
  session secrets and authenticates no peers — that is `capauth`.

**Maturity tier: T0 — Classical** (delegates seal/unseal to `capauth`). See
[SOP §9](SOP.md#9-maturity-tier--version-reference) and
[docs/crypto-architecture.md](docs/crypto-architecture.md).

---

## Threat model

### The never-holds-master guarantee (the core invariant)

skvault's central promise is precise — and so are its limits:

- **Held:** *nothing.* skvault never stores the KeePass master in plaintext, never caches
  it, and never persists it. The sealed blob (`keepass-master.asc`) is ciphertext only.
- **At rest:** the master is decryptable **only** by your PGP private key, **only** while
  `gpg-agent` holds the passphrase. Locked = mathematically no access.
- **Honest limit (stated, not hidden):** at **use-time**, the one specific retrieved
  password — and, transiently, the unsealed master while `pykeepass` opens the DB — passes
  **through the process memory** of whoever runs the command (it must, to be used). The
  guarantees are: **no master held**, **no persistent storage**, **access only while you
  authorized it (unlocked)**, and a **full audit trail**. skvault does not defend against a
  compromised host that is reading process memory *while the vault is unlocked*.

### In scope

- The seal/unseal gating (locked ⇒ unsealable), the no-prompt `vault_unlocked()` probe, and
  `lock` actually flushing `gpg-agent`.
- Per-entry (never bulk-dump) KeePass access + the append-only audit log
  (`~/clawd/logs/keepass-access.log`) recording every `init` / `get` / `list`.
- The Shamir split/combine correctness and threshold (`k-1` shares reveal nothing; only the
  embedded threshold reconstructs).
- The TOTP 2nd-factor gate on recovery.
- File-permission hygiene: sealed blobs, TOTP seed, word-blob, and Shamir shares written
  `0600`.

### Out of scope (you MUST handle these elsewhere)

- **A compromised host while unlocked** — root/another process reading memory or
  `gpg-agent` while the passphrase is cached. Mitigate with `skvault lock` when idle and a
  short `gpg-agent` cache TTL.
- **The strength of your KeePass DB itself** (KDF / keyfile) and of your **PGP passphrase**
  — skvault inherits, it does not improve, these.
- **The unlock-word channel.** `seal-word` is opt-in and explicitly "sus": the word is a
  **credential that travels through chat transport/logs** (Hermes path). Rotate freely;
  prefer the passphrase path where possible.
- **Holder key custody** for social recovery — each holder is responsible for their own PGP
  private key; a quorum of compromised holders can reconstruct.
- **The seal surface's quantum exposure** — that is `capauth`'s migration to own.

### Trust roots / dependencies

- **`capauth.seal`** — the seal/unseal primitive and PGP-recipient resolution. skvault's
  confidentiality at rest is exactly as strong as this.
- **GnuPG** (`gpg`, `gpgconf`, `gpg-preset-passphrase`) — the agent, cache, AES-256
  symmetric op, and per-holder share encryption.
- **`pykeepass`** — opens the `.kdbx`.
- **Your PGP keyring + passphrase** — the ultimate root of trust.

---

## Supported versions

Until 1.0, only the latest published `0.x` line receives security fixes.

| Version | Supported |
|---|---|
| `0.1.x` | ✅ |
| `< 0.1` | ❌ |

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

- Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the
  Security tab of [`smilinTux/skvault`](https://github.com/smilinTux/skvault)), or
- email the maintainers (smilinTux / SKWorld) at the address on the GitHub org.

Please include: affected version, Python version, GnuPG version, and a minimal
reproduction. We aim to acknowledge within **72 hours** and to ship a fix or mitigation
within **90 days**, coordinating a disclosure date. Credit is given unless you ask
otherwise.

### What we especially want to hear about

- Any path where the **KeePass master** or the **vault passphrase** is written to disk,
  logged, or persisted by skvault.
- `creds-get` / `creds-list` returning entries while the vault reports **locked**, or
  `lock` failing to actually flush `gpg-agent`.
- A Shamir flaw where **fewer than the threshold** of shares reconstructs the secret, or
  `k-1` shares leak information.
- A recovery path that bypasses a **configured** TOTP gate.
- A blob/seed/share written **world-readable** (not `0600`).
- A crypto-label overclaim — e.g. the classical seal surface described as
  "quantum-resistant," or AES-256 implied to be quantum-broken.

---

**License:** GPL-3.0-or-later. **Standards:** RFC 4880 / 9580 (OpenPGP); RFC 8032
(Ed25519); RFC 6238 (TOTP); FIPS 197 (AES); FIPS 203/204 (ML-KEM / ML-DSA — inherited via
`capauth`); NIST CSWP 39 (crypto-agility). Threat-model lineage: HashiCorp-Vault unseal
(Shamir social recovery).
