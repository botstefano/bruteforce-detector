const form = document.querySelector("#login-form");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const submitButton = document.querySelector("#submit-button");
const resultBox = document.querySelector("#result");

function showResult(kind, message, eventId) {
  resultBox.hidden = false;
  resultBox.className = "result " + kind;
  resultBox.replaceChildren();

  const title = document.createElement("strong");
  title.textContent = kind === "success" ? "Autenticación correcta" :
    kind === "failure" ? "Autenticación fallida" : "No se pudo confirmar el registro";
  const detail = document.createElement("span");
  detail.textContent = message;
  resultBox.append(title, detail);

  if (eventId) {
    const id = document.createElement("code");
    id.textContent = "Evento: " + eventId;
    resultBox.append(id);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resultBox.hidden = true;

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    showResult("error", "Completa el usuario y la contraseña.");
    return;
  }

  submitButton.disabled = true;
  submitButton.querySelector("span").textContent = "Procesando…";

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ username, password }),
      cache: "no-store",
      credentials: "same-origin"
    });

    const payload = await response.json().catch(() => ({}));
    passwordInput.value = "";

    if (response.ok && payload.authenticated && payload.event_recorded) {
      showResult("success", payload.message, payload.event_id);
    } else if (response.status === 401 && payload.event_recorded) {
      showResult("failure", payload.message, payload.event_id);
    } else {
      showResult("error", payload.error || "No se pudo confirmar el resultado. Revisa Centinela antes de repetir el intento.");
    }
  } catch {
    passwordInput.value = "";
    showResult("error", "No se pudo conectar con el laboratorio. Comprueba la conexión e inténtalo más tarde.");
  } finally {
    submitButton.disabled = false;
    submitButton.querySelector("span").textContent = "Iniciar sesión";
  }
});
