"""
app_login_demo.py

Este archivo representa el LOGIN REAL de "alguien más" -- un sistema de
autenticación completamente normal, con su propia base de usuarios, que
NO sabe nada de detectores ni de Machine Learning. Solo hace dos llamadas
HTTP a Centinela (el servicio detector) para protegerse.

Esto es exactamente el patrón que usaría cualquier equipo de desarrollo
para integrar Centinela a su propio sistema, sin importar si su login
está hecho en Flask, Django, Node, PHP, Java, etc. -- la idea es la misma:
llamar a /evaluar antes de validar, y a /registrar_intento después.

IMPORTANTE: corre en un puerto DISTINTO al de Centinela (5000 vs 5050),
para que quede claro que son dos sistemas separados que se comunican
por red, tal como pasaría en un despliegue real.

USO:
    python app_login_demo.py
    (Centinela debe estar corriendo en http://localhost:5050)
"""
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

DETECTOR_URL = "http://localhost:5050"

# Base de usuarios de ESTE sistema (nada que ver con Centinela).
# En un caso real, esto sería tu base de datos de usuarios de siempre.
USUARIOS_DEL_SITIO = {
    "admin": "S3guro#2026",
    "carla": "MiClave!789",
    "roberto": "Roberto2026!",
}


def _ip_del_atacante():
    """En este demo, el bot de pruebas manda su IP simulada en la cabecera
    X-Forwarded-For (porque en localhost todo el tráfico real llega como
    127.0.0.1). En un despliegue real detrás de un proxy/CDN, esta misma
    cabecera existe de verdad, pero solo debe confiarse en ella si el
    proxy está configurado para sobreescribirla correctamente -- de lo
    contrario, un atacante podría falsificarla."""
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True) or {}
    ip = _ip_del_atacante()
    usuario = data.get("usuario", "")
    password = data.get("password", "")

    # ---- PASO 1: preguntarle a Centinela si esta IP ya está bloqueada ----
    try:
        resp = requests.post(f"{DETECTOR_URL}/evaluar",
                              json={"ip": ip, "usuario": usuario}, timeout=2)
        resultado = resp.json()
    except requests.exceptions.RequestException:
        # Si Centinela no responde, este demo NO bloquea (fail-open).
        # En producción real, esta decisión (fail-open vs fail-closed)
        # depende de qué tan crítico sea el sistema -- vale la pena
        # documentarlo explícitamente en el artículo como una decisión
        # de diseño con trade-offs de disponibilidad vs. seguridad.
        resultado = {"bloqueado": False}

    if resultado.get("bloqueado"):
        return jsonify({
            "status": "rechazado",
            "mensaje": "Demasiados intentos sospechosos. Intenta más tarde.",
        }), 403

    # ---- PASO 2: tu lógica de login de siempre, sin cambios ----
    exitoso = USUARIOS_DEL_SITIO.get(usuario) == password

    # ---- PASO 3: avisarle a Centinela el resultado, para que seguir aprendiendo ----
    try:
        requests.post(f"{DETECTOR_URL}/registrar_intento",
                      json={"ip": ip, "usuario": usuario, "exitoso": exitoso},
                      timeout=2)
    except requests.exceptions.RequestException:
        pass  # si Centinela no responde, el login sigue funcionando igual

    if exitoso:
        return jsonify({"status": "ok", "mensaje": "Autenticado correctamente"}), 200
    return jsonify({"status": "fallo", "mensaje": "Usuario o contraseña incorrectos"}), 401


@app.route("/")
def home():
    return render_template("login.html")


if __name__ == "__main__":
    print("\nLogin demo corriendo en http://localhost:5000")
    print("Abre esa URL en el navegador para ver el formulario de login.")
    print("Este login consulta a Centinela en http://localhost:5050")
    print("Asegúrate de tener Centinela corriendo antes de probar ataques.\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
