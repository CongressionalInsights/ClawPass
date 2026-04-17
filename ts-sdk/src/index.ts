export type DecisionMethod = "webauthn" | "ledger_webauthn" | "ethereum_signer";
export type DecisionValue = "APPROVE" | "DENY";
export type ApprovalRequestStatus = "PENDING" | "APPROVED" | "DENIED" | "EXPIRED" | "CANCELLED";
export type ApprovalRequestStatusQuery = ApprovalRequestStatus | Lowercase<ApprovalRequestStatus>;

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

export interface ApprovalRequest {
  id: string;
  action_type: string;
  action_ref: string | null;
  action_hash: string;
  requester_id: string | null;
  risk_level: string;
  metadata: Record<string, unknown>;
  status: ApprovalRequestStatus;
  decision: string | null;
  method: string | null;
  approver_id: string | null;
  nonce: string;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  callback_url: string | null;
}

export interface ApproverSummary {
  id: string;
  email: string;
  display_name: string | null;
  passkey_count: number;
  ledger_webauthn_count: number;
  ethereum_signer_count: number;
}

export interface WebhookEvent {
  id: string;
  request_id: string;
  event_type: string;
  status: string;
  last_error: string | null;
  attempt_count: number;
  available_at: string | null;
  lease_expires_at: string | null;
  retry_parent_id: string | null;
  retry_attempt: number;
  created_at: string;
  updated_at: string;
}

export type WebhookEventStatus = "queued" | "skipped" | "delivered" | "failed";

export interface WebhookDeliverySummary {
  total_events: number;
  backlog_count: number;
  leased_backlog_count: number;
  stalled_backlog_count: number;
  scheduled_retry_count: number;
  delivered_count: number;
  failed_count: number;
  skipped_count: number;
  attempted_count: number;
  failure_rate: number;
  redelivery_count: number;
  redelivery_backlog_count: number;
  redelivery_delivered_count: number;
  redelivery_failed_count: number;
  oldest_queued_at: string | null;
  oldest_stalled_at: string | null;
  last_event_at: string | null;
  health_state: string;
  alerts: string[];
}

export interface WebhookEventListFilters {
  requestId?: string;
  status?: WebhookEventStatus;
  eventType?: string;
  limit?: number;
  cursor?: string;
}

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
    return this.request<ApprovalRequest>("/v1/approval-requests", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  getApprovalRequest(requestId: string) {
    return this.request<ApprovalRequest>(`/v1/approval-requests/${requestId}`);
  }

  listApprovalRequests(status?: ApprovalRequestStatusQuery) {
    const search = status ? `?${new URLSearchParams({ status }).toString()}` : "";
    return this.request<ApprovalRequest[]>(`/v1/approval-requests${search}`);
  }

  cancelApprovalRequest(requestId: string, reason?: string) {
    return this.request<ApprovalRequest>(`/v1/approval-requests/${requestId}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  getApproverSummary(approverId: string) {
    return this.request<ApproverSummary>(`/v1/approvers/${approverId}/summary`);
  }

  listWebhookEvents(filters?: string | WebhookEventListFilters) {
    const normalized =
      typeof filters === "string"
        ? { requestId: filters }
        : (filters ?? {});
    const params = new URLSearchParams();
    if (normalized.requestId) {
      params.set("request_id", normalized.requestId);
    }
    if (normalized.status) {
      params.set("status", normalized.status);
    }
    if (normalized.eventType) {
      params.set("event_type", normalized.eventType);
    }
    if (normalized.limit !== undefined) {
      params.set("limit", String(normalized.limit));
    }
    if (normalized.cursor) {
      params.set("cursor", normalized.cursor);
    }
    const query = params.toString();
    const search = query ? `?${query}` : "";
    return this.request<WebhookEvent[]>(`/v1/webhook-events${search}`);
  }

  getWebhookSummary() {
    return this.request<WebhookDeliverySummary>("/v1/webhook-summary");
  }

  redeliverWebhookEvent(eventId: string) {
    return this.request<WebhookEvent>(`/v1/webhook-events/${eventId}/redeliver`, {
      method: "POST",
      body: JSON.stringify({}),
    });
  }

  retryWebhookEventNow(eventId: string) {
    return this.request<WebhookEvent>(`/v1/webhook-events/${eventId}/retry-now`, {
      method: "POST",
      body: JSON.stringify({}),
    });
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
