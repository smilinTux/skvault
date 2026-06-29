# skvault — sovereign secrets vault

KeePass-backed sacred secrets vault. **Split out of skingest** (EPIC 11eeac9e) so secrets
management is its own service. Depends on **capauth.seal** (the gpg-agent seal/unseal
primitive — capauth is the crypto home); the KeePass master is PGP-sealed to your sovereign
identity, unlocked into the gpg-agent.

Stable entry point: the `skvault` shim (`~/.skenv/bin/skvault`) → `skvault-backend` (this package).
`skvault unlock | lock | status | get <q> | list [filter] | creds-* | vault-*`.

## Related
- 📐 **capauth** — identity + sign/verify + seal/unseal (the crypto home)
- 🗂️ **skingest** — ingestion (was the old vault home; now pure ingestion)
