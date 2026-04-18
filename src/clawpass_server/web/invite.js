import {
  $,
  api,
  normalizeCreationOptions,
  registrationCredentialToJSON,
  updateDeviceHint,
} from "./common.js";

const token = window.location.pathname.split("/").pop();
const logEl = $("log");
const globalStatus = $("global-status");
let invite = null;

function log(message, data) {
  const line = `[${new Date().toISOString()}] ${message}`;
  logEl.textContent = `${line}${data ? `\n${JSON.stringify(data, null, 2)}` : ""}\n\n${logEl.textContent}`;
}

function setStatus(value) {
  globalStatus.textContent = value;
}

async function loadInvite() {
  invite = await api(`/v1/invites/${token}`);
  $("invite-summary").textContent = `Invite for ${invite.email}${invite.display_name ? ` (${invite.display_name})` : ""}. Expires ${invite.expires_at}.`;
  setStatus("Ready");
  log("Invite loaded.", invite);
}

async function acceptInvite() {
  if (!window.PublicKeyCredential) {
    throw new Error("This browser does not support passkeys/WebAuthn.");
  }
  setStatus("Starting passkey enrollment…");
  const start = await api(`/v1/invites/${token}/start`, {
    method: "POST",
    body: JSON.stringify({}),
  });
  const credential = await navigator.credentials.create({
    publicKey: normalizeCreationOptions(start.public_key_options),
  });
  const complete = await api(`/v1/invites/${token}/complete`, {
    method: "POST",
    body: JSON.stringify({
      session_id: start.session_id,
      credential: registrationCredentialToJSON(credential),
      label: "Primary passkey",
    }),
  });
  log("Invite accepted.", complete);
  const nextPath = new URLSearchParams(window.location.search).get("next");
  window.location.replace(nextPath || "/");
}

updateDeviceHint($("device-hint"));
$("btn-accept").onclick = () => acceptInvite().catch((error) => {
  setStatus("Error");
  log("Invite acceptance failed.", { error: String(error) });
  alert(String(error));
});

loadInvite().catch((error) => {
  setStatus("Error");
  log("Invite failed to load.", { error: String(error) });
  alert(String(error));
});
