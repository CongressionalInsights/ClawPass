import {
  $,
  api,
  assertionCredentialToJSON,
  normalizeRequestOptions,
  updateDeviceHint,
} from "./common.js";

const logEl = $("log");
const globalStatus = $("global-status");

function log(message, data) {
  const line = `[${new Date().toISOString()}] ${message}`;
  logEl.textContent = `${line}${data ? `\n${JSON.stringify(data, null, 2)}` : ""}\n\n${logEl.textContent}`;
}

function setStatus(value) {
  globalStatus.textContent = value;
}

async function login() {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support passkeys/WebAuthn.");
  }
  const email = $("email").value.trim().toLowerCase();
  if (!email) {
    throw new Error("Approver email is required.");
  }
  setStatus("Starting login…");
  const start = await api("/v1/auth/login/start", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  const credential = await navigator.credentials.get({
    publicKey: normalizeRequestOptions(start.public_key_options),
  });
  const complete = await api("/v1/auth/login/complete", {
    method: "POST",
    body: JSON.stringify({
      session_id: start.session_id,
      credential: assertionCredentialToJSON(credential),
    }),
  });
  log("Login complete.", complete);
  const nextPath = new URLSearchParams(window.location.search).get("next");
  window.location.replace(nextPath || (complete.is_admin ? "/app" : "/"));
}

updateDeviceHint($("device-hint"));
$("email").value = new URLSearchParams(window.location.search).get("email") || "";
$("btn-login").onclick = () => login().catch((error) => {
  setStatus("Error");
  log("Login failed.", { error: String(error) });
  alert(String(error));
});
