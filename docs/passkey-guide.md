# Create Your First Passkey (Mobile + Desktop)

ClawPass is an approval service for high-risk actions. If you were sent here, it means your account needs a passkey before you can safely approve high-risk requests. Passkey enrollment gives ClawPass a strong, phishing-resistant approval method and satisfies the non-ledger passkey floor required for high-risk approvals.

## Mobile flow

1. Open ClawPass UI on your phone.
2. Enter your work email and display name.
3. Tap **Create passkey now**.
4. Accept the system passkey prompt (Face ID / biometrics / device PIN).
5. Confirm success in the Settings summary.

## Desktop flow

1. Open ClawPass UI on desktop.
2. Enter your work email and display name.
3. Click **Create passkey now** for a local desktop passkey.
4. Or click **Use another device** to trigger the cross-device passkey flow.
5. Confirm success in the Settings summary.

## Retry-safe behavior

If the prompt is dismissed or fails:
- Click the same button again.
- ClawPass creates a fresh challenge and keeps your approver context.

## Why this matters

High-risk approvals are blocked when an approver has zero non-ledger passkeys. Enrolling a passkey is required before high-risk actions can be approved.

## Related docs

- [Recovery Model](./recovery-model.md)
- [Ledger Setup Guide](./ledger-setup.md)
