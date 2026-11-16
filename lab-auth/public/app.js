const form = document.querySelector("#login-form");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const mfaCodeInput = document.querySelector("#mfa-code");
const mfaCodeGroup = document.querySelector("#mfa-code-group");
const mfaSetup = document.querySelector("#mfa-setup");
const setupSecret = document.querySelector("#setup-secret");
const submitButton = document.querySelector("#submit-button");
const cancelMfaButton = document.querySelector("#cancel-mfa");
const resultBox = document.querySelector("#result");

let pendingUsername = null;
let pendingPassword = null;

function showResult(kind, message, eventId) {
  resultBox.hidden = false;
  resultBox.className = "result " + kind;
  resultBox.replaceChildren();

  const title = document.createElement("strong");
  const titles = {
    success: "Autenticación correcta",
    failure: "Autenticación fallida",
    locked: "Cuenta bloqueada temporalmente",
    info: "Verificación en dos pasos",
    error: "No se pudo confirmar el registro"
  };
  title.textContent = titles[kind] || "Resultado";
  const detail = document.createElement("span");
  detail.textContent = message;
  resultBox.append(title, detail);

  if (eventId) {
    const id = document.createElement("code");
    id.textContent = "Evento: " + eventId;
    resultBox.append(id);
  }
}

function resetMfaStep() {
  pendingUsername = null;
  pendingPassword = null;
  usernameInput.disabled = false;
  passwordInput.disabled = false;
  passwordInput.value = "";
  mfaCodeInput.value = "";
  mfaCodeGroup.hidden = true;
  mfaSetup.hidden = true;
  cancelMfaButton.hidden = true;
  submitButton.querySelector("span").textContent = "Iniciar sesión";
}

cancelMfaButton.addEventListener("click", () => {
  resetMfaStep();
  resultBox.hidden = true;
  usernameInput.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resultBox.hidden = true;

  const username = pendingUsername || usernameInput.value.trim();
  const password = pendingPassword || passwordInput.value;
  const totpCode = pendingPassword ? mfaCodeInput.value.trim() : "";

  if (!username || !password) {
    showResult("error", "Completa el identificador y la contraseña.");
    return;
  }
  if (pendingPassword && !/^[0-9]{6}$/.test(totpCode)) {
    showResult("error", "Introduce el código de seis dígitos de tu aplicación autenticadora.");
    return;
  }

  submitButton.disabled = true;
  submitButton.querySelector("span").textContent = pendingPassword ? "Verificando…" : "Procesando…";

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ username, password, totp_code: totpCode }),
      cache: "no-store",
      credentials: "same-origin"
    });

    const payload = await response.json().catch(() => ({}));

    if (response.status === 202 && payload.mfa_required) {
      pendingUsername = username;
      pendingPassword = password;
      usernameInput.disabled = true;
      passwordInput.value = "";
      passwordInput.disabled = true;
      setupSecret.textContent = payload.setup_secret || "";
      mfaSetup.hidden = false;
      mfaCodeGroup.hidden = false;
      cancelMfaButton.hidden = false;
      mfaCodeInput.value = "";
      mfaCodeInput.focus();
      showResult("info", payload.message || "Configura tu aplicación autenticadora y escribe el código actual.");
      return;
    }

    if (response.ok && payload.authenticated && payload.event_recorded) {
      resetMfaStep();
      showResult("success", payload.message, payload.event_id);
    } else if (response.status === 401 && payload.event_recorded) {
      if (pendingPassword) {
        mfaCodeInput.value = "";
        mfaCodeInput.focus();
      } else {
        resetMfaStep();
      }
      showResult("failure", payload.message, payload.event_id);
    } else if (response.status === 423 && payload.event_recorded) {
      resetMfaStep();
      showResult("locked", payload.message + " Tiempo restante: " + payload.retry_after_seconds + " segundos.", payload.event_id);
    } else {
      showResult("error", payload.error || "No se pudo confirmar el resultado. Revisa Centinela antes de repetir el intento.");
    }
  } catch {
    showResult("error", "No se pudo conectar con el laboratorio. Comprueba la conexión e inténtalo más tarde.");
  } finally {
    submitButton.disabled = false;
    if (!pendingPassword) submitButton.querySelector("span").textContent = "Iniciar sesión";
    else submitButton.querySelector("span").textContent = "Verificar código";
  }
});
