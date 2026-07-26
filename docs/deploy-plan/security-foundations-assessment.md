# Security Foundations: Bulletproof Deployment Plan (skvault + PQC family)

Date: 2026-07-09. Scope: skvault plus the root-rotation and PQC toolchain it depends on. This is a light assessment note, not a full audit.

## 1. Current State

skvault 0.1.0 (2 commits on master, freshly split from skingest) is a small, honest, well-documented local CLI vault: KeePass master PGP-sealed via capauth.seal, gpg-agent lock lifecycle, pure-Python GF(256) Shamir k-of-n recovery, RFC 6238 TOTP gate. About 1.1k LOC. Tests pass locally (10/10) but there is no .github directory at all: nothing gates a commit or tag. Git hygiene is clean (no tracked secrets; .gitignore covers *.kdbx, *.asc, .env).

The wider family is in better shape than stale memory suggests: the sk_pgp "static OpenSSL-PQC" blocker was resolved 2026-06-25 (self-contained wheel, brew OpenSSL under a private SONAME), and all five PQC repos have CI with cross-impl KAT gates. Root PGP rotation is properly ceremonialized (526-line runbook with STOP gates, dry-run harness, default-closed T3 composite gate) but the live run is blocked on one unproven capability: protected-key subkey-add in the custom sq 1.4.0-pqc.1 build. That sq binary and its build script exist only on .158, outside git.

## 2. Target: what bulletproof means for this repo

- A cold machine can stand up skvault from the repo alone: install, config, join an existing vault, or recover one, following in-repo runbooks (including the shim currently living only in ~/.skenv/bin).
- Loss of any single disk, box, or key does not lose the vault. That means: the PGP secret key and the .kdbx have documented, tested backup/escrow; Shamir shares live on at least two independent custody domains, not one filesystem.
- CI gates every commit: pytest on push and PR, since SOP §4 already calls pytest "the release gate".
- The recovery ceremony is a drilled runbook, not troubleshooting rows plus an out-of-repo memory note.
- The PQC toolchain the root rotation depends on is reproducible: build script in git, binary rebuilt and verified on a second box.
- No secret values ever in git; secret paths documented as metadata only.

## 3. Gap Analysis (severity-ordered)

| # | Severity | Area | Gap |
|---|----------|------|-----|
| 1 | critical | Key custody | Shamir recovery (vault_recovery.py) recovers only the passphrase. No documented backup/escrow of the PGP secret key or the .kdbx (1471 entries). Losing either is total loss regardless of k-of-n. SOP §8 itself documents the no-local-secret-key dead end. |
| 2 | high | Share custody SPOF | All sealed shares + manifest.json live in one directory on one box (~/.config/skmemory/recovery/), and holder keys plausibly live on the same hosts. Co-located shares defeat the k-of-n model. |
| 3 | high | CI | No .github/ at all. The most security-critical Tier-2 component is the only repo in the family without CI. |
| 4 | high | Recovery/join runbook | No step-by-step recovery ceremony or multi-node join doc in-repo. The ~/.skenv/bin/skvault shim is "not shipped by this package" and its source is not in git. A cold machine cannot stand this up from the repo alone. |
| 5 | high | sq toolchain custody | sq 1.4.0-pqc.1 binary and ~/pqc-build/build-sq.sh exist only on .158, outside version control. One disk failure loses the exact toolchain mid-migration. |
| 6 | high | Rotation Phase-1 gate | Protected-key subkey-add with the custom sq build is unproven (ceremony doc Phase 1 STOP: exact flags TBD; sk_pgp Key.add_pqc_subkeys is a stub). This is THE technical blocker before the additive live run. |
| 7 | medium | Legacy paths | Recovery shares, TOTP seed, word-blob still primary under ~/.config/skmemory/; lock memo under ~/.skingest/state/. A fresh machine following skvault naming will not find them. |
| 8 | medium | Word-blob entropy | seal-word blobs are offline-brute-forceable at word-list speed with gpg default s2k; the word travels through chat transport/logs (acknowledged in vault.py comments). Needs a documented never-leaves-the-box constraint and a slow KDF. |
| 9 | medium | sk_pgp build pinning | The SONAME fix bundles a shared brew openssl@3 with no pinned version or checksum; a brew upgrade silently changes the bundled crypto provider. |
| 10 | low | recover() threshold | vault_recovery.recover() derives threshold as min(ks) across provided shares (line 83) instead of reading manifest.json (integrity-of-error impact only, but the manifest is the authority). |

## 4. Remediation Roadmap

Phase 0, stop-the-bleeding (parallelizable, no dependencies):
- Add CI to skvault (gap 3).
- Commit build-sq.sh to capauth (or a tools dir), rebuild and verify sq on .41 (gap 5). Redundancy mantra: if you need one, get two.
- Document and execute PGP secret key + .kdbx backup/escrow (gap 1). This is the single highest-value item; every other recovery layer is false confidence without it.

Phase 1, make recovery real (after Phase 0 backup lands):
- Write the recovery ceremony + multi-node join runbook in docs/, bring the shim into git (gap 4).
- Distribute Shamir shares off-box per the runbook and drill a recovery (gap 2). Depends on gaps 1 and 4.

Phase 2, unblock the root rotation (parallel to Phase 1):
- Prove protected-key subkey-add on a throwaway key with the sq PQC build (gap 6). Benefits from gap 5 (second verified binary) but is not strictly blocked by it.

Phase 3, polish (parallelizable, medium/low):
- Migrate legacy state paths to skvault-native homes with fallbacks (gap 7).
- Hardening batch: manifest-authoritative threshold in recover(), word-blob slow KDF + documented constraint (gaps 8, 10).
- Pin openssl version/checksum in sk_pgp build.sh (gap 9).

## 5. Task List

1. security-foundations: add CI workflow to skvault (critical, no deps)
2. security-foundations: PGP secret key and .kdbx backup/escrow procedure (critical, no deps). Procedure documented in [../PGP_AND_KDBX_BACKUP_ESCROW.md](../PGP_AND_KDBX_BACKUP_ESCROW.md); first real backup is a Chef-gated ceremony (STOP §7).
3. security-foundations: commit sq PQC build script and rebuild on .41 (high, no deps)
4. security-foundations: recovery ceremony and multi-node join runbook, shim into git (high, no deps)
5. security-foundations: distribute Shamir shares off-box and drill recovery (high, depends on 2 and 4)
6. security-foundations: prove protected-key subkey-add on throwaway key (high, no hard deps)
7. security-foundations: migrate legacy skmemory/skingest state paths (medium, no deps)
8. security-foundations: skvault hardening batch, manifest threshold + word-blob KDF (medium, no deps)
9. security-foundations: pin OpenSSL version and checksum in sk_pgp build (medium, no deps)
