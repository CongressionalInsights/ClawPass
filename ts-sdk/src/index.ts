export type DecisionMethod = "webauthn" | "ledger_webauthn" | "ethereum_signer";
export type DecisionValue = "APPROVE" | "DENY";

export interface LedgerClawClientOptions {
  baseUrl: string;
  headers?: Record<string, string>;
}

export class LedgerClawClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor(options: LedgerClawClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.headers = options.headers || {};
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...this.headers,
        ...(init.headers || {}),
      },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.detail || `${response.status} ${response.statusText}`);
    }
    return payload as T;
  }

  createApprovalRequest(payload: Record<string, unknown>) {
    return this.request("/v1/approval-requests", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  getApprovalRequest(requestId: string) {
    return this.request(`/v1/approval-requests/${requestId}`);
  }

  startDecision(requestId: string, approverId: string, decision: DecisionValue, method: DecisionMethod) {
    return this.request(`/v1/approval-requests/${requestId}/decision/start`, {
      method: "POST",
      body: JSON.stringify({ approver_id: approverId, decision, method }),
    });
  }

  completeDecision(requestId: string, challengeId: string, proof: Record<string, unknown>) {
    return this.request(`/v1/approval-requests/${requestId}/decision/complete`, {
      method: "POST",
      body: JSON.stringify({ challenge_id: challengeId, proof }),
    });
  }
}
