# skvault — Crypto Architecture (per-surface inventory)

Per the sk-standards
[CRYPTOGRAPHY_STANDARD](https://github.com/smilinTux/sk-standards). skvault writes **no
asymmetric crypto of its own** — it **delegates every seal/unseal to `capauth.seal`** (the
one implementation) and owns only symmetric/threshold surfaces above it. Every claim below
is scoped to **surface + FIPS/RFC number + hybrid-vs-classical**.

> **Maturity tier: T0 — Classical.** The asymmetric/at-rest surface is exactly `capauth`'s
> (classical OpenPGP today). skvault inherits `capauth`'s PQC migration; no suite
> negotiation happens here.

---

## Per-surface crypto inventory

| Surface | Where | Primitive | Standard | Hybrid-vs-classical | Quantum posture |
|---|---|---|---|---|---|
| **Sealed KeePass master** | `vault_creds.init` / `_master` → `capauth.seal` → `~/.config/skvault/keepass-master.asc` | OpenPGP public-key encryption to your identity | RFC 4880 / 9580 | **Classical** (Ed25519 / RSA-4096, delegated to `capauth`) | ❌ Shor-breakable; **HNDL-exposed**. Rides `capauth`'s additive PQC migration. |
| **Sealed Shamir shares** | `vault_recovery._encrypt_to` → `gpg --encrypt --recipient <holder>` | OpenPGP public-key encryption, one share per holder key | RFC 4880 / 9580 | **Classical** (per-holder keys) | ❌ Shor-breakable per holder key. |
| **Shamir split itself** | `shamir.split` / `combine` (GF(256), AES poly `0x11b`, Lagrange @ x=0) | Shamir's Secret Sharing, k-of-n | Shamir 1979 (HashiCorp-Vault model) | N/A (information-theoretic) | ✅ **Information-theoretic** — `k-1` shares reveal nothing, independent of any quantum advance. |
| **Unlock-word blob** | `vault.seal_word` / `unlock_with_word` → `~/.config/skmemory/vault-word.blob` | `gpg --symmetric --cipher-algo AES256` | FIPS 197 (AES-256) | Symmetric | ✅ Grover-only → **quantum-acceptable** (never AES-128). |
| **gpg-agent passphrase cache** | `vault.unlock` (`gpg-preset-passphrase`) / `lock` (`gpgconf --kill`) | local key-passphrase presetting into the agent | GnuPG | Classical (local) | N/A — cache gating, not at-rest crypto. |
| **TOTP 2nd factor** | `totp.*` → `~/.config/skmemory/totp.secret` (0600) | HMAC-SHA1, 6-digit, 30 s period, ±1 window | RFC 6238 / 4226 | Symmetric MAC | ✅ A **verifier**, not a key — cannot reconstruct a secret; quantum-irrelevant as used. |
| **KeePass DB at rest** | the `.kdbx` itself (opened by `pykeepass`) | AES / ChaCha20 + Argon2 (KDBX4, DB's own settings) | — (KeePass format) | Symmetric + KDF | ✅ Symmetric/Grover-only — but **owned by your DB settings**, not skvault. |

---

## What this means (honest summary)

- **The HNDL-exposed surfaces are the OpenPGP-sealed ones** (master + Shamir shares),
  because they delegate to `capauth`'s **classical** root. That is the *only* place an
  adversary recording ciphertext today could harvest-now-decrypt-later — and it is
  `capauth`'s migration to close, not skvault's.
- **Everything skvault implements itself is already quantum-acceptable:** AES-256
  (Grover-only), Shamir over GF(256) (information-theoretic), TOTP (a verifier).
- **No suite-ids / no KEM / no negotiation** live in skvault by design — it negotiates no
  crypto. The suite registry, backend ABC, and downgrade protection are `capauth`'s; skvault
  inherits the tier it is given.

## Self-report (claim evidence)

These commands make every claim above reproducible, not asserted:

```bash
skvault status                 # 🔓/🔒/🔑 — is the seal surface decryptable right now?
skvault creds-status           # db_configured / db_exists / master_sealed / vault_unlocked
skvault vault-recovery-status  # k-of-n, holders, sealed shares present
skvault vault-totp-verify <c>  # confirm the 2nd-factor seed
```

The seal/unseal tier (classical-vs-hybrid) is reported by **`capauth`** — see
`capauth`'s `docs/CRYPTO_SPEC.md` and its self-report; skvault's posture is, by delegation,
whatever `capauth` reports.

---

**FIPS/RFC anchors:** FIPS 197 (AES-256); RFC 6238 / 4226 (TOTP / HOTP); RFC 4880 / 9580
(OpenPGP, via `capauth`); FIPS 203 / 204 (ML-KEM / ML-DSA — the inherited PQC target);
NIST CSWP 39 (crypto-agility). Shamir's Secret Sharing (1979), HashiCorp-Vault unseal model.
