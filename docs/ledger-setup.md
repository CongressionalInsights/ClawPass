# Ledger Setup Guide

LedgerClaw supports two Ledger paths.

## 1) Ledger as WebAuthn security key

1. Open onboarding.
2. Click **Add Ledger as security key**.
3. Use Ledger Security Key / FIDO flow in browser prompt.
4. Credential is stored as `ledger_webauthn` method.

## 2) Ledger via Ethereum signer

1. Connect wallet stack with Ledger-backed account.
2. Click **Add Ledger Ethereum signer**.
3. Sign the typed challenge (`eth_signTypedData_v4`).
4. LedgerClaw verifies signer ownership and enrolls the address.

## Decision usage

For pending requests, approvers can approve via:
- `webauthn`
- `ledger_webauthn`
- `ethereum_signer`

All decision proofs are hash-bound to request id, action hash, nonce, and expiry.
