export type DecisionMethod = "webauthn" | "ledger_webauthn" | "ethereum_signer";
export type DecisionValue = "APPROVE" | "DENY";

export interface CreateApprovalRequestPayload {
  request_id?: string;
  action_type: string;
  action_hash: string;
  risk_level?: string;
  requester_id?: string;
  action_ref?: string;
  metadata?: Record<string, unknown>;
  expires_at?: string;
  callback_url?: string;
}

export interface ClawPassClientOptions {
  baseUrl: string;
  headers?: Record<string, string>;
}

export type LedgerClawClientOptions = ClawPassClientOptions;

export class ClawPassClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor(options: ClawPassClientOptions) {
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

  createApprovalRequest(payload: CreateApprovalRequestPayload) {
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

export const LedgerClawClient = ClawPassClient;
