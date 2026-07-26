# skvault: PGP Secret Key + `.kdbx` Backup / Escrow Procedure

Closes gap 1 (critical, key custody) in
[security-foundations-assessment.md](deploy-plan/security-foundations-assessment.md):
Shamir social recovery (`src/skvault/vault_recovery.py`) recovers **only the vault
passphrase**. If the PGP **secret key** or the KeePass **`.kdbx`** is lost, recovery is
impossible regardless of k-of-n. SOP.md §8 documents that dead end ("`status` shows 🔑
(no local secret key) ... you can't read it here"). This doc designs and documents a
tested backup/escrow for **both** so that loss of any single disk, box, or key does not
lose the vault.

> **This is a DESIGN + PROCEDURE document. It does NOT execute the first real backup.**
> Running the actual export of the live secret key and snapshotting the real 1471-entry
> `.kdbx` is a Chef-gated ceremony (see §7 STOP-REQUIRES-CHEF). Nothing here prints,
> echoes, or commits any secret value.

---

## 1. The recovery chain, and where the gap is

Opening one real credential requires **four** things in series. Losing any one of them
breaks the chain, and today only one of the four has a sovereign recovery path.

| # | Link | Where it lives | Recovery today |
|---|---|---|---|
| 1 | The `.kdbx` file (the credential DB itself) | `/home/cbrd21/etc-sync/KeePassDatabase.kdbx` | **NONE** (this doc, Part B) |
| 2 | The KeePass master password | never held; PGP-sealed in `keepass-master.asc`, unsealed by `capauth.seal` | rides links 3+4 (blob is ciphertext; back it up with Part B) |
| 3 | The PGP **secret key** (`chef@skworld.io`) that unseals the master | your GnuPG keyring | **NONE** (this doc, Part A) |
| 4 | The PGP **key passphrase** (the "vault key") that unlocks the secret key | in your head / password manager | **Shamir k-of-n** (`vault_recovery.py`, SOP §2/§7) ✅ |

**The gap in one line:** Shamir recovers link 4. Links 1 and 3 have no backup, so the
existing recovery is false confidence without this procedure. The three layers **compose**:

```
full recovery  =  passphrase (Shamir k-of-n)      [link 4, already built]
               +  PGP secret key (Part A escrow)   [link 3, this doc]
               +  .kdbx + sealed master (Part B)   [links 1 and 2, this doc]
```

You need all three. This doc supplies the two missing legs; `vault_recovery.py` supplies
the third.

---

## 2. Verified environment (metadata only: no secret values were read)

Everything below was confirmed on the primary box by public tooling (key listings, file
`stat`, format magic). **No private key bytes, `.kdbx` contents, or passphrases were read
or printed.**

| Fact | Value | Status |
|---|---|---|
| Vault PGP recipient | `chef@skworld.io` | **verified** (`SKINGEST_PGP_RECIPIENT`, `capauth.seal.recipients()`) |
| Recipient fingerprint | `BD7EEECA23D90A594400751CFDB582D9CB7272A6` | **verified** (`gpg --list-keys`) |
| Key type / usage / expiry | RSA-4096, primary `[SCEAR]` + encryption subkey `[SEA]`, expires **2028-06-09** | **verified** |
| Secret key present locally | yes (`sec` + `ssb` shown by `gpg --list-secret-keys`) | **verified**, so Part A export is runnable on this box |
| `.kdbx` path | `/home/cbrd21/etc-sync/KeePassDatabase.kdbx` | **verified** (`config.keepass_db()`) |
| `.kdbx` size / format | 1,575,515 bytes, **KDBX4** (magic `03d9a29a`, sig2 `0xb54bfb67`, v4) | **verified** (`ls`, format magic) |
| Expected entry count | **1471** (integrity target for restore-test) | **assumed** (from assessment §3 gap 1; not re-counted here, counting needs an unlock) |
| `.kdbx` custody today | inside `~/etc-sync/` which is **Syncthing-managed** (`.stfolder` present) | **verified**, this is **replication, not backup** (see §4) |
| Sealed master blob | `~/.config/skmemory/keepass-master.asc`, 1004 B, mode `0600` | **verified** (skvault path `~/.config/skvault/keepass-master.asc` not yet migrated) |
| No keyfile | `config.keepass_keyfile()` = `None` (passphrase-only DB) | **verified** |
| Shamir recovery dir | `~/.config/skmemory/recovery/` does **not** yet exist (Shamir not initialized) | **verified**, Part A composes with this once `vault-share-init` is run |
| `gpg` / `gpgconf` | GnuPG 2.4.4 | **verified** (`/usr/bin/gpg`) |
| `qrencode` | present | **verified** (`/usr/bin/qrencode`) |
| `sq` | present at `~/.cargo/bin/sq` (generic build) | **verified**, usable for classical RSA export; the PQC `sq 1.4.0-pqc.1` lives on .158 |
| `paperkey` | **not installed**; available via `apt` (`paperkey 1.6-1build1`) | **assumed-after-install** (Option A2) |
| `keepassxc-cli` | not installed | **verified**, restore-test uses `pykeepass` (already a skvault dep) instead |

---

## 3. Part A: PGP secret key escrow (encrypted offline export)

**Threat closed:** the daily box dies or its keyring is wiped. With no secret key,
`keepass-master.asc` can never be unsealed, so the passphrase (even Shamir-recovered) and
the `.kdbx` are both useless. SOP §8's "🔑 no local secret key" dead end.

**What to protect:** the secret key for `chef@skworld.io` (fpr
`BD7EEECA23D90A594400751CFDB582D9CB7272A6`). Note both an export and a paperkey copy stay
**S2K-encrypted under the PGP passphrase** (gpg does not strip the passphrase on export),
so the backup medium holds ciphertext, not a bare key. Treat it as sensitive regardless,
and **never store the passphrase with it** (the passphrase is itself Shamir-recoverable,
which is the intended separation).

### Option A1: `gpg --export-secret-keys` to a second medium (recommended primary)

Exports the full secret key (primary + subkeys), still passphrase-encrypted. Written to
offline removable media on a second custody domain.

```bash
# CEREMONY ONLY: do not run outside the Chef-gated ceremony (§7). Illustrative flags.
umask 077
DEST=/media/USB-OFFLINE            # air-gapped removable medium, NOT ~/etc-sync (Syncthing)
gpg --armor --export-secret-keys BD7EEECA23D90A594400751CFDB582D9CB7272A6 \
    > "$DEST/chef-skworld-secret-$(date -u +%Y%m%dT%H%M%SZ).asc"
gpg --armor --export        BD7EEECA23D90A594400751CFDB582D9CB7272A6 \
    > "$DEST/chef-skworld-public.asc"     # public half, needed for a clean import/restore
sync
```

`sq` equivalent (generic build at `~/.cargo/bin/sq`, classical RSA key):
`sq key export --cert BD7EEECA23D90A594400751CFDB582D9CB7272A6 > "$DEST/…secret.pgp"`.

### Option A2: `paperkey` printed to paper (recommended second medium)

`paperkey` extracts only the **secret** portions (the public data is recomputed on
restore), producing a compact printable that survives disk rot and lives outside any
digital custody. Requires `sudo apt install paperkey` first (available, not yet installed).

```bash
# CEREMONY ONLY. paperkey preserves the S2K-encrypted secret; still passphrase-protected.
gpg --export-secret-keys BD7EEECA23D90A594400751CFDB582D9CB7272A6 \
    | paperkey --output-type raw > /media/USB-OFFLINE/chef-skworld.paperkey   # then print
```

Restore for A2 needs the **public key** (`chef-skworld-public.asc` from A1, or any
published copy) plus the paper: `paperkey --pubring public.asc --secrets scanned.paperkey
| gpg --import`.

### Verified-restore step (Part A): fail-closed

A backup is **not trusted** until it re-imports and unseals in a throwaway keyring. This
touches only a temp `GNUPGHOME`; it never prints key material and is destroyed after.

```bash
# CEREMONY ONLY. Prove the escrowed key round-trips without polluting the live keyring.
export GNUPGHOME=$(mktemp -d)
gpg --import "$DEST/chef-skworld-public.asc"
gpg --import "$DEST/chef-skworld-secret-…​.asc"          # (or paperkey restore, A2)
# 1. Fingerprint MUST match, else FAIL:
gpg --list-secret-keys --with-colons | grep -q BD7EEECA23D90A594400751CFDB582D9CB7272A6 \
    && echo "fingerprint OK" || echo "FAIL, wrong key"
# 2. Functional unseal test: decrypt the sealed master blob in the temp home.
#    Success (exit 0) proves the escrowed key can actually unseal the vault.
#    Pipe to a byte counter: the plaintext master is NEVER printed:
gpg --quiet --decrypt ~/.config/skmemory/keepass-master.asc | wc -c \
    && echo "unseal OK (master recovered, not shown)" || echo "FAIL, cannot unseal"
gpgconf --kill gpg-agent
rm -rf "$GNUPGHOME"; unset GNUPGHOME
```

If either check fails, the escrow copy is bad, redo the export before trusting it.

### Storage (second custody domain) and re-issue triggers

- **Second custody domain:** offline and physically separate from the daily machine and
  from the Syncthing mesh. Recommended: one air-gapped USB in a fireproof/locked box (A1)
  plus one printed paperkey in a **different** physical location, e.g. a bank deposit box
  (A2). The redundancy mantra: if you need one, get two. The passphrase does **not** travel
  with either copy.
- **Re-issue the escrow when:** the key is rotated (capauth root rotation / PQC migration),
  the PGP passphrase is changed, a subkey is added or expires, the **2028-06-09 expiry** is
  extended, or compromise is suspected. A stale export that predates a rotation restores the
  wrong key and silently fails the unseal test above.

---

## 4. Part B: `.kdbx` versioned encrypted backup

**Threat closed:** the `.kdbx` is corrupted or deleted. Its only home today is
`~/etc-sync/`, a **Syncthing folder** (`.stfolder` confirmed). Syncthing **replicates**: a
corruption or an accidental delete **propagates to every replica**. There is no version
history and no retention ladder. Replication is not backup.

**What to protect:** `/home/cbrd21/etc-sync/KeePassDatabase.kdbx` (1.5 MB, KDBX4, ~1471
entries), plus the small sealed master blob `keepass-master.asc` (ciphertext, safe to copy)
which should ride along so a restore has links 1 **and** 2 together.

### Snapshot procedure (defense-in-depth seal)

The `.kdbx` is already ciphertext (KDBX4: AES/ChaCha20 + Argon2 under its own master). We
additionally PGP-seal each snapshot to `chef@skworld.io` so an attacker needs **both** the
PGP secret key **and** the KeePass master. Route the seal through `capauth.seal` (the one
crypto impl in the stack, SOP §2) so there is no second encryption implementation; a plain
`gpg --encrypt -r chef@skworld.io` is the equivalent fallback.

```bash
# CEREMONY ONLY. Second custody domain = a box/disk NOT in the same Syncthing share.
TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/srv/vault-backups          # a DIFFERENT box's local disk, or offline USB
gpg --encrypt --recipient chef@skworld.io \
    --output "$BACKUP/KeePassDatabase.$TS.kdbx.gpg" \
    /home/cbrd21/etc-sync/KeePassDatabase.kdbx
gpg --encrypt --recipient chef@skworld.io \
    --output "$BACKUP/keepass-master.$TS.asc.gpg" \
    ~/.config/skmemory/keepass-master.asc
sync
```

### Versioning / retention

- **Versioned filenames:** UTC-timestamped, immutable (`KeePassDatabase.YYYYMMDDTHHMMSSZ.kdbx.gpg`).
  Never overwrite; append new snapshots.
- **Retention ladder (recommended, Chef ratifies exact counts):** keep last **7 daily**,
  **4 weekly**, **12 monthly**. Prune older than the ladder. Keep at least the two most
  recent **verified** snapshots at all times.
- **Custody:** the primary backup target is a **second box's local disk that is NOT a member
  of the `~/etc-sync` Syncthing folder** (else you have re-created the replication SPOF),
  plus a periodic offline USB copy. Two independent domains, per the mantra.

### Verified restore-test (Part B): fail-closed

Prove a snapshot decrypts and opens read-only with the expected entry count before trusting
it. Uses `pykeepass` (a skvault runtime dep) against a temp copy; entry **count** only is
compared, no entry values are printed.

```bash
# CEREMONY ONLY. Requires the vault UNLOCKED so the KeePass master can be unsealed.
TMP=$(mktemp -d)
gpg --quiet --decrypt "$BACKUP/KeePassDatabase.<TS>.kdbx.gpg" > "$TMP/restore.kdbx"
gpg --quiet --decrypt "$BACKUP/keepass-master.<TS>.asc.gpg"   > "$TMP/master.asc"
~/.skenv/bin/python - "$TMP/restore.kdbx" "$TMP/master.asc" <<'PY'
import sys, subprocess
from pykeepass import PyKeePass
db, blob = sys.argv[1], sys.argv[2]
master = subprocess.run(["gpg","--quiet","--decrypt",blob],
                        capture_output=True).stdout.decode().strip()
n = len(PyKeePass(db, password=master).entries)   # count only; no titles/passwords printed
print(f"restore OK: {n} entries" if n >= 1400 else f"FAIL: only {n} entries")
PY
shred -u "$TMP"/*; rm -rf "$TMP"
```

Expected: ~1471 entries. A count far below that (or an open failure) means the snapshot or
the master blob is stale/corrupt, **do not** rotate away the source until a snapshot
passes.

---

## 5. How this composes with Shamir passphrase recovery

Full sovereign recovery of the live vault, on a cold machine, is the three legs together:

1. **Passphrase**: `skvault vault-recover --providers a,b [--totp CODE]` reconstructs the
   PGP key passphrase from k-of-n holder shares (`vault_recovery.recover`, SOP §7).
2. **PGP secret key**: restore from the Part A escrow (§3), import, verify fingerprint
   `BD7E…72A6`. The passphrase from step 1 unlocks it.
3. **`.kdbx` + sealed master**: restore the newest **verified** snapshot from the Part B
   backup (§4). With the secret key (step 2) unlocked by the passphrase (step 1),
   `capauth.seal` unseals the master and `pykeepass` opens the DB.

Miss any leg and recovery fails: Shamir alone gives a passphrase with nothing to apply it
to. That is exactly the false-confidence gap this doc closes.

---

## 6. Fail-closed + secret-hygiene rules (always)

- **Verify before trust.** A backup that has not passed its restore-test (§3, §4) does not
  count as a backup. Never delete or rotate away a source until a replacement snapshot has
  restored cleanly.
- **Ciphertext only in transit/at rest.** Every artifact this procedure writes is
  passphrase-encrypted (Part A) or PGP-sealed (Part B). No plaintext key, no plaintext DB,
  no passphrase ever lands on disk, in a log, in chat, or in git.
- **Passphrase never co-located** with the key escrow; it is Shamir-recoverable instead.
- **Temp homes are destroyed** (`rm -rf`/`shred`) and `gpg-agent` killed after every
  restore-test.
- **Two custody domains minimum** for each artifact (redundancy mantra).

---

## 7. STOP: REQUIRES CHEF (first real backup ceremony)

Everything above is design and dry-run illustration. The **first real execution** is a
Chef-gated ceremony and is **out of scope for any agent**, because it touches the live
secret key and the real 1471-entry `.kdbx`, and it sets the offline media and its
passphrase. Do not run it autonomously.

The ceremony, when Chef schedules it, is:

1. `sudo apt install paperkey` (enables Option A2).
2. Part A: export the secret key (A1) to an air-gapped USB **and** print a paperkey (A2);
   run the §3 verified-restore in a throwaway `GNUPGHOME`; confirm fingerprint + unseal.
3. Part B: take the first PGP-sealed `.kdbx` + sealed-master snapshot to a second box's disk
   (not the Syncthing share) and an offline USB; run the §4 restore-test; confirm ~1471
   entries.
4. Record **only** the fact of completion, the timestamps, and the storage locations (never
   any secret) in the vault runbook / this repo's ops log.
5. Schedule recurring Part B snapshots and set a calendar reminder to re-issue Part A on the
   2028-06-09 expiry or any earlier rotation.

Until Chef runs this, the gap remains open by design: the procedure exists and is tested in
principle, but no live backup has been produced.
