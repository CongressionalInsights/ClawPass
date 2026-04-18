export const $ = (id) => document.getElementById(id);

export function getCookie(name) {
  const cookie = document.cookie
    .split(";")
    .map((value) => value.trim())
    .find((value) => value.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.slice(name.length + 1)) : "";
}

export async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = getCookie("clawpass_csrf");
    if (csrf) {
      headers["X-ClawPass-CSRF"] = csrf;
    }
  }
  const response = await fetch(path, { ...options, headers });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.detail || `${response.status} ${response.statusText}`);
  }
  return payload;
}

export function toBase64Url(bytes) {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function normalizeCreationOptions(publicKey) {
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

export function normalizeRequestOptions(publicKey) {
  return {
    ...publicKey,
    challenge: fromBase64Url(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map((item) => ({
      ...item,
      id: fromBase64Url(item.id),
    })),
  };
}

export function registrationCredentialToJSON(credential) {
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

export function assertionCredentialToJSON(credential) {
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

export function updateDeviceHint(element) {
  const isMobile = window.matchMedia("(max-width: 900px)").matches || /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent);
  element.textContent = isMobile
    ? "Mobile flow: use your device passkey prompt or another trusted device."
    : "Desktop flow: create a local passkey or choose another device for cross-device sign-in.";
}
