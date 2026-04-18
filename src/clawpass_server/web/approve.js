import {
  $,
  api,
  assertionCredentialToJSON,
  normalizeRequestOptions,
} from "./common.js";

const requestId = window.location.pathname.split("/").pop();
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

async function loadRequest() {
  const loginUrl = new URL("/login", window.location.origin);
  loginUrl.searchParams.set("next", window.location.pathname);
  try {
    const link = await api(`/v1/approval-links/${requestId}`);
    $("request-summary").textContent = `${link.action_type} · ${link.risk_level} risk · ${link.status} · requested by ${link.producer_id || "unknown producer"}`;
    $("btn-login").href = loginUrl.toString();
    currentSession = await api("/v1/auth/session");
    $("auth-summary").textContent = `Signed in as ${currentSession.email}.`;
    const request = await api(`/v1/approval-requests/${requestId}`);
    $("request-summary").textContent = `${request.action_type} · ${request.action_hash} · ${request.status} · requested by ${request.producer_id || "unknown producer"}`;
    $("btn-login").style.display = "none";
    log("Approval page loaded.", { session: currentSession, request });
  } catch (error) {
    $("auth-summary").textContent = "Sign in with your approver passkey before deciding.";
    $("btn-approve").disabled = true;
    $("btn-deny").disabled = true;
    log("Approval page requires login or the request link is unavailable.", { error: String(error) });
  }
}

async function decide(decision) {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support passkeys/WebAuthn.");
  }
  setStatus(`${decision === "APPROVE" ? "Approving" : "Denying"}…`);
  const start = await api(`/v1/approval-requests/${requestId}/decision/start`, {
    method: "POST",
    body: JSON.stringify({ decision, method: "webauthn" }),
  });
  const credential = await navigator.credentials.get({
    publicKey: normalizeRequestOptions(start.payload.public_key_options),
  });
  const complete = await api(`/v1/approval-requests/${requestId}/decision/complete`, {
    method: "POST",
    body: JSON.stringify({
      challenge_id: start.challenge_id,
      proof: { credential: assertionCredentialToJSON(credential) },
    }),
  });
  $("request-summary").textContent = `${complete.request.action_type} · ${complete.request.action_hash} · ${complete.request.status}`;
  log("Decision complete.", complete);
  setStatus(complete.request.status);
}

$("btn-login").onclick = (event) => {
  if ($("btn-login").getAttribute("href")) {
    return;
  }
  event.preventDefault();
};

$("btn-approve").onclick = () => decide("APPROVE").catch((error) => {
  setStatus("Error");
  log("Approval failed.", { error: String(error) });
  alert(String(error));
});

$("btn-deny").onclick = () => decide("DENY").catch((error) => {
  setStatus("Error");
  log("Denial failed.", { error: String(error) });
  alert(String(error));
});

loadRequest();
