# Mission

skvault exists to be the SKWorld secrets vault: a KeePass-backed credential store the agent can use without ever holding your master key.

The KeePass master is PGP-sealed to your sovereign identity and only unsealable while the vault is unlocked, with your passphrase cached in `gpg-agent`. It adds sovereign social recovery (Shamir k-of-n) and a TOTP second factor on top of `capauth`'s seal/unseal primitive.

## Scope

- The vault above the crypto primitive: KeePass credentials, lock lifecycle, social recovery, Shamir sharing, and TOTP 2FA.
- A stable `skvault` shim so consumers (skos.secrets, skguide, `.claude` hooks, Hermes DM) never import the backend directly and it can move without touching a hook.
- Split out of `skingest` so secrets management is its own component.

In the division of labor, `capauth` is the crypto home (identity plus the one seal/unseal implementation), skvault is the vault that depends on `capauth.seal`, and `skingest` is pure ingestion.

## Non-goals

- skvault owns no encryption of its own; all seal/unseal delegates to `capauth`.
- It is not an identity system and does not manage keys; that is `capauth`'s job.
- At T0 it is classical (rides capauth's PQC migration), experimental, pre-1.0, and not independently audited.
