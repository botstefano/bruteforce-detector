"""
app.py
Servidor principal del prototipo.

Expone:
- POST /login            -> endpoint de autenticación simulado
- GET  /                 -> dashboard en tiempo real
- POST /simular/ataque   -> dispara un ataque de fuerza bruta simulado
- POST /simular/legitimo -> genera tráfico de login legítimo
- POST /reset            -> limpia el estado (BD + detectores)
- GET  /api/eventos      -> últimos eventos (JSON)
- GET  /api/metricas     -> métricas comparativas reglas vs ML (JSON)

El dashboard se actualiza en tiempo real vía WebSockets (Flask-SocketIO)
cada vez que ocurre un intento de login, sea real o simulado.
"""
import random
import string
import threading
import time

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO

import database as db
from detector_reglas import DetectorReglas
from detector_ml import DetectorML, generar_muestras_normales

app = Flask(__name__)
app.config["SECRET_KEY"] = "prototipo-tfg-seguridad"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# --- estado global de los detectores (en memoria, vive con el proceso) ---
detector_reglas = DetectorReglas()
detector_ml = DetectorML()
detector_ml.entrenar_con_datos_normales(generar_muestras_normales())

# credenciales "válidas" del sistema simulado, para poder marcar
# éxito/fracaso de forma determinística
CREDENCIALES_VALIDAS = {
    "admin": "S3guro#2026",
    "jperez": "Trujillo!456",
    "mgarcia": "Contrasena_88",
}

USUARIOS_COMUNES = ["admin", "root", "administrator", "user", "test",
                     "jperez", "mgarcia", "guest", "info", "support"]
PASSWORDS_COMUNES = ["123456", "password", "admin123", "qwerty",
                      "letmein", "12345678", "root", "changeme"]


def _procesar_intento(ip, usuario, password, es_ataque_real, origen):
    """Punto único de entrada: valida credenciales, corre ambos
    detectores, persiste el evento y notifica al dashboard."""
    ahora = time.time()
    exitoso = CREDENCIALES_VALIDAS.get(usuario) == password

    resultado_reglas = detector_reglas.evaluar(ip, usuario, exitoso, ahora)
    resultado_ml = detector_ml.registrar_y_evaluar(ip, usuario, exitoso, ahora)

    evento_id = db.registrar_intento(
        ip=ip, usuario=usuario, exitoso=exitoso,
        es_ataque_real=es_ataque_real,
        alerta_reglas=resultado_reglas["alerta"],
        alerta_ml=resultado_ml["alerta"],
        origen=origen, timestamp=ahora,
    )

    evento = {
        "id": evento_id,
        "timestamp": ahora,
        "ip": ip,
        "usuario": usuario,
        "exitoso": exitoso,
        "es_ataque_real": bool(es_ataque_real),
        "alerta_reglas": resultado_reglas["alerta"],
        "razon_reglas": resultado_reglas["razon"],
        "alerta_ml": resultado_ml["alerta"],
        "score_ml": resultado_ml["score"],
        "origen": origen,
    }
    socketio.emit("nuevo_evento", evento)
    return evento


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/login", methods=["POST"])
def login():
    """Endpoint real de login. En producción, esta es la ruta que
    protegerías con el detector antes de dar acceso al sistema."""
    data = request.get_json(force=True)
    ip = request.remote_addr or data.get("ip", "0.0.0.0")
    usuario = data.get("usuario", "")
    password = data.get("password", "")

    evento = _procesar_intento(ip, usuario, password,
                                es_ataque_real=0, origen="login_real")

    if evento["alerta_reglas"] or evento["alerta_ml"]:
        return jsonify({"status": "bloqueado",
                         "mensaje": "Actividad sospechosa detectada"}), 429
    if evento["exitoso"]:
        return jsonify({"status": "ok", "mensaje": "Autenticado"}), 200
    return jsonify({"status": "fallo", "mensaje": "Credenciales inválidas"}), 401


def _ip_aleatoria():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _lanzar_ataque_rapido(usuario_objetivo, num_intentos=10):
    ip = _ip_aleatoria()
    for _ in range(num_intentos):
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd,
                           es_ataque_real=1, origen="ataque_rapido")
        time.sleep(0.3)


def _lanzar_ataque_lento(usuario_objetivo, num_intentos=10, intervalo=2.0):
    ip = _ip_aleatoria()
    for _ in range(num_intentos):
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd,
                           es_ataque_real=1, origen="ataque_lento")
        time.sleep(intervalo)


def _lanzar_ataque_distribuido(usuario_objetivo, num_ips=6):
    ips = [_ip_aleatoria() for _ in range(num_ips)]
    for ip in ips:
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd,
                           es_ataque_real=1, origen="ataque_distribuido")
        time.sleep(0.2)


@app.route("/simular/ataque", methods=["POST"])
def simular_ataque():
    data = request.get_json(force=True) or {}
    tipo = data.get("tipo", "rapido")
    usuario = data.get("usuario") or random.choice(USUARIOS_COMUNES)

    if tipo == "rapido":
        hilo = threading.Thread(target=_lanzar_ataque_rapido, args=(usuario,))
    elif tipo == "lento":
        hilo = threading.Thread(target=_lanzar_ataque_lento, args=(usuario,))
    elif tipo == "distribuido":
        hilo = threading.Thread(target=_lanzar_ataque_distribuido, args=(usuario,))
    else:
        return jsonify({"error": "tipo de ataque no reconocido"}), 400

    hilo.daemon = True
    hilo.start()
    return jsonify({"status": "lanzado", "tipo": tipo, "usuario": usuario})


def _generar_login_legitimo():
    ip = _ip_aleatoria()
    usuario = random.choice(list(CREDENCIALES_VALIDAS.keys()))
    # la mayoría de las veces un humano acierta o falla 1 vez y reintenta
    if random.random() < 0.85:
        password = CREDENCIALES_VALIDAS[usuario]
    else:
        password = "clave_equivocada"
    _procesar_intento(ip, usuario, password,
                       es_ataque_real=0, origen="trafico_legitimo")


@app.route("/simular/legitimo", methods=["POST"])
def simular_legitimo():
    data = request.get_json(force=True) or {}
    cantidad = int(data.get("cantidad", 5))

    def _tarea():
        for _ in range(cantidad):
            _generar_login_legitimo()
            time.sleep(random.uniform(1.0, 3.0))

    hilo = threading.Thread(target=_tarea)
    hilo.daemon = True
    hilo.start()
    return jsonify({"status": "lanzado", "cantidad": cantidad})


@app.route("/reset", methods=["POST"])
def reset():
    db.limpiar()
    detector_reglas.reset()
    detector_ml.reset()
    socketio.emit("reset")
    return jsonify({"status": "ok"})


@app.route("/api/eventos")
def api_eventos():
    return jsonify(db.obtener_intentos_recientes(300))


@app.route("/api/metricas")
def api_metricas():
    return jsonify(db.metricas_resumen())


if __name__ == "__main__":
    db.init_db()
    socketio.run(app, host="0.0.0.0", port=5050, debug=True,
                 allow_unsafe_werkzeug=True)
