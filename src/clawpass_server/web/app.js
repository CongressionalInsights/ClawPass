import {
  $,
  api,
  assertionCredentialToJSON,
  normalizeCreationOptions,
  registrationCredentialToJSON,
  updateDeviceHint,
} from "./common.js";

const logEl = $("log");
const globalStatus = $("global-status");
let currentSession = null;

function log(message, data) {
  const line = `[${new Date().toISOString()}] ${message}`;
  logEl.textContent = `${line}${data ? `\n${JSON.stringify(data, null, 2)}` : ""}\n\n${logEl.textContent}`;
}

function setStatus(value) {
  globalStatus.textContent = value;
}

function metricCard(label, value, tone = "normal") {
  return `
    <div class="metric-card">
      <div class="metric-label">${label}</div>
      <div class="metric-value ${tone}">${value}</div>
    </div>
  `;
}

function formatPercent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

async function loadSession() {
  try {
    currentSession = await api("/v1/auth/session");
  } catch (error) {
    window.location.replace("/login");
    return;
  }
  if (!currentSession.is_admin) {
    window.location.replace("/login");
    return;
  }
  $("session-summary").textContent = `Signed in as ${currentSession.email}. ${currentSession.passkey_count} passkey(s), ${currentSession.ledger_webauthn_count} Ledger key(s), ${currentSession.ethereum_signer_count} Ethereum signer(s).`;
  $("security-summary").textContent = `Approver ${currentSession.email}: ${currentSession.passkey_count} passkey(s), ${currentSession.ledger_webauthn_count} Ledger security key(s), ${currentSession.ethereum_signer_count} Ethereum signer(s).`;
  setStatus("Ready");
}

async function createPasskey({ isLedger = false, useAnotherDevice = false }) {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support passkeys/WebAuthn.");
  }
  setStatus("Starting passkey enrollment…");
  const start = await api("/v1/webauthn/register/start", {
    method: "POST",
    body: JSON.stringify({ is_ledger: isLedger }),
  });
  const publicKey = normalizeCreationOptions(start.public_key_options);
  if (useAnotherDevice) {
    publicKey.authenticatorSelection = { ...(publicKey.authenticatorSelection || {}) };
    delete publicKey.authenticatorSelection.authenticatorAttachment;
    publicKey.hints = Array.from(new Set([...(publicKey.hints || []), "hybrid"]));
  }
  const credential = await navigator.credentials.create({ publicKey });
  const complete = await api("/v1/webauthn/register/complete", {
    method: "POST",
    body: JSON.stringify({
      session_id: start.session_id,
      credential: registrationCredentialToJSON(credential),
      label: isLedger ? "Ledger security key" : "Passkey",
    }),
  });
  log("Passkey enrollment complete.", complete);
  await loadSession();
}

async function addEthereumSigner() {
  if (!window.ethereum) {
    throw new Error("No injected Ethereum wallet found.");
  }
  const [address] = await window.ethereum.request({ method: "eth_requestAccounts" });
  const challenge = await api("/v1/signers/ethereum/challenge", {
    method: "POST",
    body: JSON.stringify({ address, chain_id: 1 }),
  });
  const signature = await window.ethereum.request({
    method: "eth_signTypedData_v4",
    params: [address, JSON.stringify(challenge.typed_data)],
  });
  const verified = await api("/v1/signers/ethereum/verify", {
    method: "POST",
    body: JSON.stringify({ session_id: challenge.session_id, signature }),
  });
  log("Ethereum signer enrolled.", verified);
  await loadSession();
}

function renderProducer(producer) {
  const card = document.createElement("div");
  card.className = "request-card";
  card.innerHTML = `
    <strong>${producer.name}</strong>
    <div class="request-meta">${producer.id}</div>
    <div class="request-meta">${producer.description || "No description"}</div>
    <div class="actions"></div>
  `;
  const actions = card.querySelector(".actions");

  const issueButton = document.createElement("button");
  issueButton.className = "btn";
  issueButton.textContent = "Issue API key";
  issueButton.onclick = async () => {
    try {
      setStatus("Issuing producer API key…");
      const key = await api(`/v1/operator/producers/${producer.id}/keys`, {
        method: "POST",
        body: JSON.stringify({ label: "primary" }),
      });
      $("key-output").textContent = `Issued key for ${producer.name}: ${key.api_key}`;
      log("Producer API key issued.", key);
      setStatus("Ready");
    } catch (error) {
      alert(String(error));
      setStatus("Error");
    }
  };
  actions.appendChild(issueButton);
  return card;
}

async function refreshProducers() {
  const producers = await api("/v1/operator/producers");
  const container = $("producer-list");
  container.innerHTML = "";
  if (!producers.length) {
    const empty = document.createElement("div");
    empty.className = "request-card";
    empty.textContent = "No producers created yet.";
    container.appendChild(empty);
    return;
  }
  producers.forEach((producer) => container.appendChild(renderProducer(producer)));
}

async function createProducer() {
  const name = $("producer-name").value.trim();
  const description = $("producer-description").value.trim();
  if (!name) {
    throw new Error("Producer name is required.");
  }
  const producer = await api("/v1/operator/producers", {
    method: "POST",
    body: JSON.stringify({ name, description: description || null }),
  });
  log("Producer created.", producer);
  $("producer-name").value = "";
  $("producer-description").value = "";
  await refreshProducers();
}

function renderApprover(approver) {
  const card = document.createElement("div");
  card.className = "request-card";
  card.innerHTML = `
    <strong>${approver.email}</strong>
    <div class="request-meta">${approver.display_name || "No display name"}</div>
    <div class="request-meta">passkeys=${approver.passkey_count} · ledger keys=${approver.ledger_webauthn_count} · ethereum signers=${approver.ethereum_signer_count}</div>
  `;
  return card;
}

async function refreshApprovers() {
  const approvers = await api("/v1/operator/approvers");
  const invites = await api("/v1/operator/approver-invites");
  const container = $("approver-list");
  container.innerHTML = "";
  if (!approvers.length) {
    const empty = document.createElement("div");
    empty.className = "request-card";
    empty.textContent = "No approvers found.";
    container.appendChild(empty);
  } else {
    approvers.forEach((approver) => container.appendChild(renderApprover(approver)));
  }
  if (invites.length) {
    $("invite-output").textContent = `Latest invite: ${invites[0].invite_url}`;
  }
}

async function createInvite() {
  const email = $("invite-email").value.trim().toLowerCase();
  const displayName = $("invite-display-name").value.trim();
  if (!email) {
    throw new Error("Invite email is required.");
  }
  const invite = await api("/v1/operator/approver-invites", {
    method: "POST",
    body: JSON.stringify({
      email,
      display_name: displayName || null,
      expires_in_minutes: 1440,
    }),
  });
  $("invite-output").textContent = `Invite created: ${invite.invite_url}`;
  $("invite-email").value = "";
  $("invite-display-name").value = "";
  log("Approver invite created.", invite);
  await refreshApprovers();
}

function renderWebhookEndpoint(summary) {
  const card = document.createElement("div");
  card.className = "request-card";
  const muted = Boolean(summary.muted_until);
  card.innerHTML = `
    <strong>${summary.callback_url}</strong>
    <div class="request-meta">state=${summary.health_state} · queued=${summary.queued_count} · failed=${summary.failed_count} · dead-lettered=${summary.dead_lettered_count}</div>
    <div class="request-meta">failure-rate=${formatPercent(summary.failure_rate)} · consecutive-failures=${summary.consecutive_failure_count}</div>
    <div class="request-meta">muted=${summary.muted_until || "not muted"} · last-event=${summary.last_event_at || "n/a"}</div>
    ${summary.latest_error ? `<div class="request-meta">latest-error=${summary.latest_error}</div>` : ""}
    <div class="actions"></div>
  `;
  const actions = card.querySelector(".actions");
  const toggleButton = document.createElement("button");
  toggleButton.className = "btn";
  toggleButton.textContent = muted ? "Resume endpoint" : "Mute endpoint";
  toggleButton.onclick = async () => {
    setStatus(muted ? "Resuming endpoint…" : "Muting endpoint…");
    await api(muted ? "/v1/webhook-endpoints/unmute" : "/v1/webhook-endpoints/mute", {
      method: "POST",
      body: JSON.stringify(
        muted
          ? { callback_url: summary.callback_url }
          : { callback_url: summary.callback_url, reason: "operator pause" },
      ),
    });
    await refreshWebhookOps();
    setStatus("Ready");
  };
  actions.appendChild(toggleButton);
  return card;
}

async function refreshWebhookOps() {
  const summary = await api("/v1/webhook-summary");
  $("webhook-health").textContent = `Health: ${summary.health_state}`;
  $("webhook-summary-meta").textContent = `Backlog ${summary.backlog_count}, scheduled retries ${summary.scheduled_retry_count}, dead-lettered ${summary.dead_lettered_count}`;
  $("webhook-alerts").innerHTML = summary.alerts.length
    ? summary.alerts.map((message) => `<div class="alert-item warning">${message}</div>`).join("")
    : '<div class="alert-item ok">No active webhook alerts.</div>';
  $("webhook-stats").innerHTML = [
    metricCard("Backlog", summary.backlog_count, summary.stalled_backlog_count ? "warn" : "normal"),
    metricCard("Stalled", summary.stalled_backlog_count, summary.stalled_backlog_count ? "warn" : "normal"),
    metricCard("Failure rate", formatPercent(summary.failure_rate), summary.failed_count ? "danger" : "normal"),
    metricCard("Dead-lettered", summary.dead_lettered_count, summary.dead_lettered_count ? "danger" : "normal"),
  ].join("");

  const endpoints = await api("/v1/webhook-endpoints/summary?limit=20");
  const container = $("webhook-endpoint-list");
  container.innerHTML = "";
  if (!endpoints.length) {
    const empty = document.createElement("div");
    empty.className = "request-card";
    empty.textContent = "No callback endpoints recorded yet.";
    container.appendChild(empty);
    return;
  }
  endpoints.forEach((endpoint) => container.appendChild(renderWebhookEndpoint(endpoint)));
}

async function logout() {
  await api("/v1/auth/logout", { method: "POST", body: JSON.stringify({}) });
  window.location.replace("/login");
}

async function main() {
  updateDeviceHint($("device-hint"));
  await loadSession();
  await Promise.all([refreshProducers(), refreshApprovers(), refreshWebhookOps()]);

  $("btn-passkey").onclick = () => createPasskey({ isLedger: false }).catch((error) => alert(String(error)));
  $("btn-passkey-cross").onclick = () => createPasskey({ isLedger: false, useAnotherDevice: true }).catch((error) => alert(String(error)));
  $("btn-ledger-webauthn").onclick = () => createPasskey({ isLedger: true }).catch((error) => alert(String(error)));
  $("btn-ledger-eth").onclick = () => addEthereumSigner().catch((error) => alert(String(error)));
  $("btn-create-invite").onclick = () => createInvite().catch((error) => alert(String(error)));
  $("btn-refresh-approvers").onclick = () => refreshApprovers().catch((error) => alert(String(error)));
  $("btn-create-producer").onclick = () => createProducer().catch((error) => alert(String(error)));
  $("btn-refresh-producers").onclick = () => refreshProducers().catch((error) => alert(String(error)));
  $("btn-refresh-webhooks").onclick = () => refreshWebhookOps().catch((error) => alert(String(error)));
  $("btn-prune-webhooks").onclick = async () => {
    try {
      const result = await api("/v1/webhook-events/prune", { method: "POST", body: JSON.stringify({}) });
      log("Pruned webhook history.", result);
      await refreshWebhookOps();
    } catch (error) {
      alert(String(error));
    }
  };
  $("btn-logout").onclick = () => logout().catch((error) => alert(String(error)));
}

main().catch((error) => {
  setStatus("Error");
  log("Operator app failed to load.", { error: String(error) });
});
