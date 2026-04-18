import {
  $,
  api,
  normalizeCreationOptions,
  registrationCredentialToJSON,
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

async function bootstrap() {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support passkeys/WebAuthn.");
  }
  setStatus("Starting bootstrap…");
  const start = await api("/v1/setup/bootstrap/start", {
    method: "POST",
    body: JSON.stringify({
      bootstrap_token: $("bootstrap-token").value.trim(),
      email: $("email").value.trim(),
      display_name: $("display-name").value.trim() || null,
    }),
  });
  const credential = await navigator.credentials.create({
    publicKey: normalizeCreationOptions(start.public_key_options),
  });
  const complete = await api("/v1/setup/bootstrap/complete", {
    method: "POST",
    body: JSON.stringify({
      session_id: start.session_id,
      credential: registrationCredentialToJSON(credential),
      label: "Primary passkey",
    }),
  });
  log("Bootstrap complete.", complete);
  window.location.replace("/app");
}

updateDeviceHint($("device-hint"));
$("btn-bootstrap").onclick = () => bootstrap().catch((error) => {
  setStatus("Error");
  log("Bootstrap failed.", { error: String(error) });
  alert(String(error));
});
