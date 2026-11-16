const form = document.querySelector("#login-form");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const captchaQuestion = document.querySelector("#captcha-question");
const captchaAnswer = document.querySelector("#captcha-answer");
const refreshCaptchaButton = document.querySelector("#refresh-captcha");
const honeypotInput = document.querySelector("#website");
const submitButton = document.querySelector("#submit-button");
const resultBox = document.querySelector("#result");

let currentChallengeId = null;
let challengeLoading = false;

function showResult(kind, message, eventId) {
  resultBox.hidden = false;
  resultBox.className = "result " + kind;
  resultBox.replaceChildren();

  const title = document.createElement("strong");
  title.textContent = kind === "success" ? "Autenticación correcta" :
    kind === "failure" ? "Autenticación fallida" : "Aviso de seguridad";
  const detail = document.createElement("span");
  detail.textContent = message;
  resultBox.append(title, detail);

  if (eventId) {
    const id = document.createElement("code");
    id.textContent = "Evento: " + eventId;
    resultBox.append(id);
  }
}

async function loadCaptcha() {
  challengeLoading = true;
  currentChallengeId = null;
  captchaQuestion.textContent = "Cargando comprobación…";
  captchaAnswer.value = "";
  refreshCaptchaButton.disabled = true;
  submitButton.disabled = true;

  try {
    const response = await fetch("/challenge", {
      method: "GET",
      headers: { "Accept": "application/json" },
      cache: "no-store",
      credentials: "same-origin"
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || typeof payload.challenge_id !== "string" || typeof payload.prompt !== "string") {
      throw new Error(payload.error || "No se pudo generar la comprobación.");
    }
    currentChallengeId = payload.challenge_id;
    captchaQuestion.textContent = payload.prompt;
  } catch (error) {
    captchaQuestion.textContent = "No se pudo cargar la comprobación. Vuelve a intentarlo.";
    showResult("error", error.message || "No se pudo generar el CAPTCHA.");
  } finally {
    challengeLoading = false;
    refreshCaptchaButton.disabled = false;
    submitButton.disabled = !currentChallengeId;
  }
}

refreshCaptchaButton.addEventListener("click", loadCaptcha);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resultBox.hidden = true;

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  const answer = captchaAnswer.value.trim();
  const website = honeypotInput.value;

  if (!username || !password) {
    showResult("error", "Completa el usuario y la contraseña.");
    return;
  }
  if (!currentChallengeId || challengeLoading) {
    showResult("error", "Espera a que se cargue la comprobación de seguridad.");
    return;
  }
  if (!/^\d{1,2}$/.test(answer)) {
    showResult("error", "Resuelve la comprobación de seguridad.");
    return;
  }

  submitButton.disabled = true;
  refreshCaptchaButton.disabled = true;
  submitButton.querySelector("span").textContent = "Procesando…";
  const challengeId = currentChallengeId;
  currentChallengeId = null;

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        username,
        password,
        challenge_id: challengeId,
        challenge_answer: answer,
        website
      }),
      cache: "no-store",
      credentials: "same-origin"
    });

    const payload = await response.json().catch(() => ({}));
    passwordInput.value = "";
    captchaAnswer.value = "";

    if (response.ok && payload.authenticated && payload.event_recorded) {
      showResult("success", payload.message, payload.event_id);
    } else if (response.status === 401 && payload.event_recorded) {
      showResult("failure", payload.message, payload.event_id);
    } else {
      showResult("error", payload.error || "No se pudo confirmar el resultado. Revisa Centinela antes de repetir el intento.");
    }
  } catch {
    passwordInput.value = "";
    showResult("error", "No se pudo conectar con el laboratorio. Comprueba Centinela antes de repetir el intento.");
  } finally {
    submitButton.querySelector("span").textContent = "Iniciar sesión";
    await loadCaptcha();
  }
});

loadCaptcha();
