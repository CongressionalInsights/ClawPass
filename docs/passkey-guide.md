# Create Your First Passkey (Mobile + Desktop)

## Mobile flow

1. Open LedgerClaw UI on your phone.
2. Enter your work email and display name.
3. Tap **Create passkey now**.
4. Accept the system passkey prompt (Face ID / biometrics / device PIN).
5. Confirm success in the Settings summary.

## Desktop flow

1. Open LedgerClaw UI on desktop.
2. Enter your work email and display name.
3. Click **Create passkey now** for local desktop passkey.
4. Or click **Use another device** to trigger cross-device passkey flow.
5. Confirm success in Settings summary.

## Retry-safe behavior

If the prompt is dismissed or fails:
- Click the same button again.
- LedgerClaw creates a fresh challenge and keeps your approver context.

## Why this matters

High-risk approvals are blocked when an approver has zero passkeys. Enrolling a passkey is required before high-risk actions can be approved.
