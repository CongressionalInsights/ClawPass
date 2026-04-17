const state = {
  approverId: null,
};

const $ = (id) => document.getElementById(id);
const logEl = $("log");
const globalStatus = $("global-status");

function log(message, data) {
  const line = `[${new Date().toISOString()}] ${message}`;
  logEl.textContent = `${line}${data ? `\n${JSON.stringify(data, null, 2)}` : ""}\n\n${logEl.textContent}`;
}

function setStatus(value) {
  globalStatus.textContent = value;
}

function toBase64Url(bytes) {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function normalizeCreationOptions(publicKey) {
  return {
    ...publicKey,
    challenge: fromBase64Url(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: fromBase64Url(publicKey.user.id),
    },
    excludeCredentials: (publicKey.excludeCredentials || []).map((item) => ({
      ...item,
      id: fromBase64Url(item.id),
    })),
  };
}

function normalizeRequestOptions(publicKey) {
  return {
    ...publicKey,
    challenge: fromBase64Url(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map((item) => ({
      ...item,
      id: fromBase64Url(item.id),
    })),
  };
}

function registrationCredentialToJSON(credential) {
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: toBase64Url(credential.response.attestationObject),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}

function assertionCredentialToJSON(credential) {
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: toBase64Url(credential.response.authenticatorData),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      signature: toBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? toBase64Url(credential.response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `${response.status} ${response.statusText}`);
  }
  return payload;
}

function currentIdentity() {
  return {
    approver_id: state.approverId,
    email: $("email").value.trim() || undefined,
    display_name: $("display-name").value.trim() || undefined,
  };
}

function updateDeviceHint() {
  const isMobile = window.matchMedia("(max-width: 900px)").matches || /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent);
  $("device-hint").textContent = isMobile
    ? "Mobile flow: tap Create passkey to open your phone-native passkey prompt."
    : "Desktop flow: create a local passkey or choose Use another device for cross-device passkeys.";
}

async function createPasskey({ isLedger = false, useAnotherDevice = false }) {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support passkeys/WebAuthn.");
  }
  setStatus("Starting passkey enrollment...");
  const start = await api("/v1/webauthn/register/start", {
    method: "POST",
    body: JSON.stringify({ ...currentIdentity(), is_ledger: isLedger }),
  });
  state.approverId = start.approver_id;

  const publicKey = normalizeCreationOptions(start.public_key_options);
  if (useAnotherDevice) {
    publicKey.authenticatorSelection = { ...(publicKey.authenticatorSelection || {}) };
    delete publicKey.authenticatorSelection.authenticatorAttachment;
    publicKey.hints = Array.from(new Set([...(publicKey.hints || []), "hybrid"]));
  }

  const cred = await navigator.credentials.create({ publicKey });
  const complete = await api("/v1/webauthn/register/complete", {
    method: "POST",
    body: JSON.stringify({
      session_id: start.session_id,
      credential: registrationCredentialToJSON(cred),
      label: isLedger ? "Ledger security key" : "Primary passkey",
    }),
  });
  log("Passkey enrollment complete.", complete);
  await refreshSummary();
  setStatus("Passkey enrolled");
}

async function addEthereumSigner() {
  if (!window.ethereum) {
    throw new Error("No injected Ethereum wallet found (e.g. MetaMask + Ledger).\nUse passkey or Ledger security-key mode instead.");
  }
  const [address] = await window.ethereum.request({ method: "eth_requestAccounts" });
  const challenge = await api("/v1/signers/ethereum/challenge", {
    method: "POST",
    body: JSON.stringify({ ...currentIdentity(), address, chain_id: 1 }),
  });
  state.approverId = challenge.approver_id;

  const signature = await window.ethereum.request({
    method: "eth_signTypedData_v4",
    params: [address, JSON.stringify(challenge.typed_data)],
  });
  const verified = await api("/v1/signers/ethereum/verify", {
    method: "POST",
    body: JSON.stringify({ session_id: challenge.session_id, signature }),
  });
  log("Ethereum signer verified.", verified);
  await refreshSummary();
}

async function refreshSummary() {
  if (!state.approverId) {
    $("summary").textContent = "No approver selected yet.";
    return;
  }
  const summary = await api(`/v1/approvers/${state.approverId}/summary`);
  $("summary").textContent = `Approver ${summary.email}: ${summary.passkey_count} passkeys, ${summary.ledger_webauthn_count} Ledger security keys, ${summary.ethereum_signer_count} Ethereum signer(s).`;
}

async function createRequest() {
  const req = await api("/v1/approval-requests", {
    method: "POST",
    body: JSON.stringify({
      action_type: $("action-type").value.trim(),
      action_hash: $("action-hash").value.trim(),
      risk_level: $("risk-level").value,
      requester_id: state.approverId || "demo-requester",
      callback_url: $("callback-url").value.trim() || undefined,
      metadata: { source: "clawpass-web-demo" },
    }),
  });
  log("Approval request created.", req);
  await refreshRequests();
}

async function startAndComplete(requestId, decision, method) {
  if (!state.approverId) {
    throw new Error("Create or load an approver first.");
  }
  const start = await api(`/v1/approval-requests/${requestId}/decision/start`, {
    method: "POST",
    body: JSON.stringify({ approver_id: state.approverId, decision, method }),
  });

  if (method === "webauthn" || method === "ledger_webauthn") {
    const publicKey = normalizeRequestOptions(start.payload.public_key_options);
    const assertion = await navigator.credentials.get({ publicKey });
    const done = await api(`/v1/approval-requests/${requestId}/decision/complete`, {
      method: "POST",
      body: JSON.stringify({ challenge_id: start.challenge_id, proof: { credential: assertionCredentialToJSON(assertion) } }),
    });
    log(`Decision completed via ${method}.`, done);
  } else {
    if (!window.ethereum) throw new Error("Ethereum wallet not available.");
    const [address] = await window.ethereum.request({ method: "eth_requestAccounts" });
    const signature = await window.ethereum.request({
      method: "eth_signTypedData_v4",
      params: [address, JSON.stringify(start.payload.typed_data)],
    });
    const done = await api(`/v1/approval-requests/${requestId}/decision/complete`, {
      method: "POST",
      body: JSON.stringify({ challenge_id: start.challenge_id, proof: { signature } }),
    });
    log("Decision completed via ethereum_signer.", done);
  }
  await refreshRequests();
}

function renderRequestCard(request) {
  const card = document.createElement("div");
  card.className = "request-card";
  card.innerHTML = `
    <strong>${request.id}</strong>
    <div class="request-meta">${request.action_type} · ${request.risk_level} · status=${request.status}</div>
    <div class="request-meta">hash=${request.action_hash}</div>
    <div class="actions"></div>
  `;

  const actions = card.querySelector(".actions");
  if (request.status === "PENDING") {
    [
      ["Approve (Passkey)", "APPROVE", "webauthn"],
      ["Deny (Passkey)", "DENY", "webauthn"],
      ["Approve (Ledger key)", "APPROVE", "ledger_webauthn"],
      ["Approve (Ledger signer)", "APPROVE", "ethereum_signer"],
    ].forEach(([label, decision, method]) => {
      const btn = document.createElement("button");
      btn.className = "btn";
      btn.textContent = label;
      btn.onclick = async () => {
        try {
          setStatus(`Working: ${label}`);
          await startAndComplete(request.id, decision, method);
          setStatus("Ready");
        } catch (error) {
          setStatus("Error");
          log(`Decision failed for ${request.id}`, { method, error: String(error) });
          alert(String(error));
        }
      };
      actions.appendChild(btn);
    });
  }
  return card;
}

async function refreshRequests() {
  const requests = await api("/v1/approval-requests");
  const container = $("requests");
  container.innerHTML = "";
  requests.forEach((request) => container.appendChild(renderRequestCard(request)));
}

function bindButtons() {
  $("btn-passkey").onclick = async () => {
    try {
      await createPasskey({ isLedger: false, useAnotherDevice: false });
    } catch (error) {
      log("Passkey enrollment failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };

  $("btn-passkey-cross").onclick = async () => {
    try {
      await createPasskey({ isLedger: false, useAnotherDevice: true });
    } catch (error) {
      log("Cross-device passkey failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };

  $("btn-ledger-webauthn").onclick = async () => {
    try {
      await createPasskey({ isLedger: true, useAnotherDevice: false });
    } catch (error) {
      log("Ledger WebAuthn enrollment failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };

  $("btn-ledger-eth").onclick = async () => {
    try {
      setStatus("Registering Ethereum signer...");
      await addEthereumSigner();
      setStatus("Ethereum signer ready");
    } catch (error) {
      log("Ethereum signer enrollment failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };

  $("btn-recovery").onclick = () => {
    log("Recovery path confirmed by operator.");
    setStatus("Recovery confirmed");
    alert("Recovery path confirmed. Keep at least one backup passkey device.");
  };

  $("btn-create-request").onclick = async () => {
    try {
      setStatus("Creating request...");
      await createRequest();
      setStatus("Ready");
    } catch (error) {
      log("Create request failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };

  $("btn-refresh").onclick = async () => {
    try {
      await refreshRequests();
      setStatus("Ready");
    } catch (error) {
      log("Refresh failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };

  $("btn-settings-passkey").onclick = async () => {
    try {
      await createPasskey({ isLedger: false, useAnotherDevice: false });
    } catch (error) {
      log("Settings passkey action failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };

  $("btn-load-summary").onclick = async () => {
    try {
      await refreshSummary();
      setStatus("Ready");
    } catch (error) {
      log("Summary load failed", { error: String(error) });
      alert(String(error));
      setStatus("Error");
    }
  };
}

async function init() {
  updateDeviceHint();
  bindButtons();
  await refreshRequests().catch(() => null);
  setStatus("Ready");
}

window.addEventListener("resize", updateDeviceHint);
init();
