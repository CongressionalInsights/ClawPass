from __future__ import annotations

from dataclasses import dataclass

from clawpass_server.core.constants import RISK_HIGH


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    reason: str | None = None


class PolicyEngine:
    """Single-approver policy with passkey floor for high-risk approvals."""

    def can_start_decision(self, *, risk_level: str, passkey_count: int) -> PolicyDecision:
        if risk_level == RISK_HIGH and passkey_count <= 0:
            return PolicyDecision(
                allowed=False,
                reason="High-risk approvals require at least one enrolled passkey for the approver.",
            )
        return PolicyDecision(allowed=True)
