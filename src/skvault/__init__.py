"""
skvault — the sovereign secrets VAULT.

CapAuth owns SEAL (gpg-agent encrypt/decrypt-at-rest, `capauth.seal`); skvault owns
the VAULT built on top of it:

  • vault         — gpg-agent lock lifecycle (unlock/lock/status, chat unlock-word)
  • vault_creds   — agent-accessible KeePass without holding the master key
  • vault_recovery + shamir — k-of-n sovereign social recovery (HashiCorp-Vault model)
  • totp          — RFC 6238 second-factor gate on sensitive actions

The agent never holds the KeePass master: it is PGP-sealed to YOUR key and only
unsealable while the vault is unlocked (gpg-agent has your passphrase cached).
"""

__version__ = "0.1.0"

from .ssh_metadata import resolve_ssh

__all__ = ["__version__", "resolve_ssh"]
