# Threat Model

## Protected assets

- Sensitive action execution rights
- Approval integrity (who approved, what was approved, when)
- Audit and webhook truth

## Main threats

- Replay of old signatures/assertions
- Hash substitution (approve one action, execute another)
- Unauthorized approver impersonation
- UI prompt confusion and unsafe fallback behavior
- Webhook tampering

## Controls

- Per-request nonce and expiry
- Action hash binding in decision envelope
- Method-specific cryptographic verification
- Fail-closed policy on verification errors
- Immutable audit records
- Optional webhook HMAC signature (`X-ClawPass-Signature`)

## Residual risks

- Wallet/browser extension compromise on approver endpoint
- Weak org identity governance outside ClawPass
- Social engineering around approval intent context
