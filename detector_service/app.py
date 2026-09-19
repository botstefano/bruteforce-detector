"""
app.py — Centinela (servidor detector)

Este servidor YA NO es un login de ejemplo con detección integrada —
es un microservicio de protección independiente, pensado para ponerse
delante de CUALQUIER sistema de login (propio o de terceros) mediante
dos llamadas HTTP sencillas.

ENDPOINTS PARA PROTEGER UN LOGIN REAL (lo que usaría alguien externo):
    POST /evaluar
        Se llama ANTES de validar la contraseña.
        Body: {"ip": "...", "usuario": "..."}
        Responde: {"bloqueado": true/false, "razon": "...", "segundos_restantes": N}

    POST /registrar_intento
        Se llama DESPUÉS de saber si el login fue exitoso o no.
        Body: {"ip": "...", "usuario": "...", "exitoso": true/false}
        Responde: {"alerta": true/false, "bloqueado_ahora": true/false}
        Si detecta un patrón sospechoso, bloquea la IP automáticamente
        por un tiempo (ver DURACION_BLOQUEO_SEGUNDOS).

ENDPOINTS DE ADMINISTRACIÓN / DEMO (dashboard, experimentos, pruebas):
    GET  /                    -> panel de administración (dashboard)
    POST /login                -> login de PRUEBA interno (no es para producción)
    POST /simular/ataque       -> genera un ataque simulado (para demos/experimentos)
    POST /simular/legitimo     -> genera tráfico legítimo simulado
    POST /reset                 -> limpia la base de datos y el estado de los detectores
    GET  /api/eventos            -> últimos eventos (JSON)
    GET  /api/metricas            -> métricas de la validación experimental (solo tráfico simulado)
    GET  /api/produccion           -> conteo de tráfico real recibido vía /registrar_intento
    GET  /api/bloqueadas             -> lista de IPs actualmente bloqueadas
    GET  /api/estado_modelo           -> de dónde viene el modelo ML actual
    POST /entrenar/cicids              -> entrena el modelo ML con CICIDS2017 traducido
    POST /entrenar/reset_sintetico      -> vuelve a entrenar con datos sintéticos

El dashboard se actualiza en tiempo real vía WebSockets (Flask-SocketIO)
tanto con tráfico simulado como con tráfico real de producción, para que
un administrador pueda monitorear todo desde un solo lugar.
"""
import os
import random
import string
import threading
import time

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO

import database as db
from detector_reglas import DetectorReglas
from detector_ml import DetectorML, generar_muestras_normales
from entrenar_con_cicids import (
    cargar_cicids, preparar_eventos, entrenar_detector_ml_con_benignos,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "centinela-detector-service"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# --- estado global de los detectores (en memoria, vive con el proceso) ---
detector_reglas = DetectorReglas()
detector_ml = DetectorML()
detector_ml.entrenar_con_datos_normales(generar_muestras_normales())

estado_modelo = {
    "fuente": "sintetico",
    "detalle": "Entrenado con datos sintéticos generados al arrancar el servidor. "
               "Se recomienda entrenar con CICIDS2017 para mayor realismo.",
    "cargando": False,
}

# --- lista negra de IPs bloqueadas (bloqueo real) ---
# {ip: timestamp_hasta_cuando_esta_bloqueada}
ips_bloqueadas = {}
DURACION_BLOQUEO_SEGUNDOS = 300  # 5 minutos


def ip_esta_bloqueada(ip):
    hasta = ips_bloqueadas.get(ip)
    if hasta is None:
        return False, 0
    restante = hasta - time.time()
    if restante <= 0:
        del ips_bloqueadas[ip]
        return False, 0
    return True, int(restante)


def bloquear_ip(ip, segundos=DURACION_BLOQUEO_SEGUNDOS):
    ips_bloqueadas[ip] = time.time() + segundos


# credenciales del login de PRUEBA interno (/login) -- no es para producción
CREDENCIALES_VALIDAS = {
    "admin": "S3guro#2026",
    "jperez": "Trujillo!456",
    "mgarcia": "Contrasena_88",
}

USUARIOS_COMUNES = ["admin", "root", "administrator", "user", "test",
                     "jperez", "mgarcia", "guest", "info", "support"]
PASSWORDS_COMUNES = ["123456", "password", "admin123", "qwerty",
                      "letmein", "12345678", "root", "changeme"]


def _procesar_intento(ip, usuario, password_o_exitoso, es_ataque_real,
                       origen, es_simulado=1, ya_es_booleano_exitoso=False):
    """Punto único de entrada para tráfico SIMULADO (dashboard, experimento.py,
    login de prueba). Valida credenciales del login de prueba, corre ambos
    detectores, persiste el evento, bloquea si corresponde, y notifica al
    dashboard."""
    ahora = time.time()
    if ya_es_booleano_exitoso:
        exitoso = bool(password_o_exitoso)
    else:
        exitoso = CREDENCIALES_VALIDAS.get(usuario) == password_o_exitoso

    resultado_reglas = detector_reglas.evaluar(ip, usuario, exitoso, ahora)
    resultado_ml = detector_ml.registrar_y_evaluar(ip, usuario, exitoso, ahora)

    alerta = resultado_reglas["alerta"] or resultado_ml["alerta"]
    if alerta:
        bloquear_ip(ip)

    evento_id = db.registrar_intento(
        ip=ip, usuario=usuario, exitoso=exitoso,
        es_ataque_real=es_ataque_real,
        alerta_reglas=resultado_reglas["alerta"],
        alerta_ml=resultado_ml["alerta"],
        origen=origen, timestamp=ahora, es_simulado=es_simulado,
    )

    evento = {
        "id": evento_id, "timestamp": ahora, "ip": ip, "usuario": usuario,
        "exitoso": exitoso, "es_ataque_real": bool(es_ataque_real),
        "alerta_reglas": resultado_reglas["alerta"],
        "razon_reglas": resultado_reglas["razon"],
        "alerta_ml": resultado_ml["alerta"], "score_ml": resultado_ml["score"],
        "origen": origen, "bloqueado_ahora": alerta, "es_simulado": bool(es_simulado),
    }
    socketio.emit("nuevo_evento", evento)
    return evento


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ============================================================
# ENDPOINTS GENÉRICOS PARA PROTEGER UN LOGIN EXTERNO REAL
# ============================================================

@app.route("/evaluar", methods=["POST"])
def evaluar():
    """Se llama ANTES de validar la contraseña en el sistema de login real."""
    data = request.get_json(force=True) or {}
    ip = data.get("ip") or request.remote_addr
    usuario = data.get("usuario", "")

    bloqueada, restante = ip_esta_bloqueada(ip)
    if bloqueada:
        return jsonify({
            "bloqueado": True,
            "razon": "IP marcada como sospechosa por actividad reciente",
            "segundos_restantes": restante,
        }), 200

    return jsonify({"bloqueado": False}), 200


@app.route("/registrar_intento", methods=["POST"])
def registrar_intento_real():
    """Se llama DESPUÉS de que el login real sepa si la autenticación
    fue exitosa o no. Alimenta a los detectores con tráfico REAL
    (es_simulado=0), y bloquea la IP automáticamente si corresponde."""
    data = request.get_json(force=True) or {}
    ip = data.get("ip") or request.remote_addr
    usuario = data.get("usuario", "")
    exitoso = bool(data.get("exitoso", False))
    ahora = time.time()

    resultado_reglas = detector_reglas.evaluar(ip, usuario, exitoso, ahora)
    resultado_ml = detector_ml.registrar_y_evaluar(ip, usuario, exitoso, ahora)
    alerta = resultado_reglas["alerta"] or resultado_ml["alerta"]

    if alerta:
        bloquear_ip(ip)

    evento_id = db.registrar_intento(
        ip=ip, usuario=usuario, exitoso=exitoso,
        es_ataque_real=0,  # desconocido en tráfico real: no se usa para métricas
        alerta_reglas=resultado_reglas["alerta"],
        alerta_ml=resultado_ml["alerta"],
        origen="produccion_real", timestamp=ahora, es_simulado=0,
    )

    socketio.emit("nuevo_evento", {
        "id": evento_id, "timestamp": ahora, "ip": ip, "usuario": usuario,
        "exitoso": exitoso, "es_ataque_real": False,
        "alerta_reglas": resultado_reglas["alerta"],
        "razon_reglas": resultado_reglas["razon"],
        "alerta_ml": resultado_ml["alerta"], "score_ml": resultado_ml["score"],
        "origen": "produccion_real", "bloqueado_ahora": alerta, "es_simulado": False,
    })

    return jsonify({
        "alerta": alerta,
        "alerta_reglas": resultado_reglas["alerta"],
        "alerta_ml": resultado_ml["alerta"],
        "bloqueado_ahora": alerta,
    })


@app.route("/api/bloqueadas")
def api_bloqueadas():
    ahora = time.time()
    activas = {ip: int(hasta - ahora) for ip, hasta in ips_bloqueadas.items() if hasta > ahora}
    return jsonify(activas)


@app.route("/api/produccion")
def api_produccion():
    return jsonify(db.contador_produccion())


# ============================================================
# LOGIN DE PRUEBA INTERNO (solo para demos, NO usar en producción)
# ============================================================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    ip = request.remote_addr or data.get("ip", "0.0.0.0")
    usuario = data.get("usuario", "")
    password = data.get("password", "")

    bloqueada, restante = ip_esta_bloqueada(ip)
    if bloqueada:
        return jsonify({"status": "rechazado",
                         "mensaje": f"IP bloqueada, intenta en {restante}s"}), 403

    evento = _procesar_intento(ip, usuario, password, es_ataque_real=0,
                                origen="login_prueba_interno", es_simulado=1)

    if evento["alerta_reglas"] or evento["alerta_ml"]:
        return jsonify({"status": "bloqueado",
                         "mensaje": "Actividad sospechosa detectada"}), 429
    if evento["exitoso"]:
        return jsonify({"status": "ok", "mensaje": "Autenticado"}), 200
    return jsonify({"status": "fallo", "mensaje": "Credenciales inválidas"}), 401


# ============================================================
# SIMULACIÓN PARA DEMOS Y EXPERIMENTOS (sin cambios de comportamiento)
# ============================================================

def _ip_aleatoria():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _lanzar_ataque_rapido(usuario_objetivo, num_intentos=10):
    ip = _ip_aleatoria()
    for _ in range(num_intentos):
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd, es_ataque_real=1, origen="ataque_rapido")
        time.sleep(0.3)


def _lanzar_ataque_lento(usuario_objetivo, num_intentos=10, intervalo=2.0):
    ip = _ip_aleatoria()
    for _ in range(num_intentos):
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd, es_ataque_real=1, origen="ataque_lento")
        time.sleep(intervalo)


def _lanzar_ataque_distribuido(usuario_objetivo, num_ips=6):
    ips = [_ip_aleatoria() for _ in range(num_ips)]
    for ip in ips:
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd, es_ataque_real=1, origen="ataque_distribuido")
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
    if random.random() < 0.85:
        password = CREDENCIALES_VALIDAS[usuario]
    else:
        password = "clave_equivocada"
    _procesar_intento(ip, usuario, password, es_ataque_real=0, origen="trafico_legitimo")


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
    ips_bloqueadas.clear()
    socketio.emit("reset")
    return jsonify({"status": "ok"})


@app.route("/api/eventos")
def api_eventos():
    return jsonify(db.obtener_intentos_recientes(300))


@app.route("/api/metricas")
def api_metricas():
    return jsonify(db.metricas_resumen())


@app.route("/api/estado_modelo")
def api_estado_modelo():
    return jsonify(estado_modelo)


def _entrenar_con_cicids_en_segundo_plano(carpeta, max_benignos):
    global detector_ml, estado_modelo

    estado_modelo["cargando"] = True
    socketio.emit("entrenamiento_progreso", {"mensaje": "Cargando archivos CSV..."})

    try:
        df = cargar_cicids(carpeta)
        socketio.emit("entrenamiento_progreso",
                      {"mensaje": f"Cargados {len(df)} flujos. Traduciendo a eventos..."})

        eventos = preparar_eventos(df)
        eventos_benignos = [e for e in eventos if not e["es_ataque_real"]]
        eventos_ataque = [e for e in eventos if e["es_ataque_real"]]

        if not eventos_ataque:
            raise ValueError("El dataset no contiene eventos de ataque (bruteforce)")

        if len(eventos_benignos) > max_benignos:
            paso = len(eventos_benignos) // max_benignos
            eventos_benignos = eventos_benignos[::paso][:max_benignos]

        socketio.emit("entrenamiento_progreso", {
            "mensaje": f"Entrenando con {len(eventos_benignos)} eventos benignos reales..."
        })

        nuevo_detector = entrenar_detector_ml_con_benignos(eventos_benignos)
        nuevo_detector.reset()

        detector_ml = nuevo_detector
        estado_modelo.update({
            "fuente": "cicids2017",
            "detalle": f"Entrenado con {len(eventos_benignos)} eventos benignos reales "
                       f"traducidos de CICIDS2017 (carpeta: {carpeta})",
            "cargando": False,
        })
        socketio.emit("entrenamiento_completo", estado_modelo)

    except Exception as e:
        estado_modelo["cargando"] = False
        socketio.emit("entrenamiento_error", {"mensaje": str(e)})


@app.route("/entrenar/cicids", methods=["POST"])
def entrenar_cicids():
    if estado_modelo["cargando"]:
        return jsonify({"error": "ya hay un entrenamiento en curso"}), 409

    data = request.get_json(force=True) or {}
    carpeta = data.get("carpeta", "").strip()
    max_benignos = int(data.get("max_benignos", 5000))

    if not carpeta:
        return jsonify({"error": "falta la ruta de la carpeta"}), 400
    if not os.path.isdir(carpeta):
        return jsonify({"error": f"la carpeta '{carpeta}' no existe en el servidor"}), 400

    hilo = threading.Thread(target=_entrenar_con_cicids_en_segundo_plano,
                             args=(carpeta, max_benignos))
    hilo.daemon = True
    hilo.start()
    return jsonify({"status": "entrenamiento_iniciado"})


@app.route("/entrenar/reset_sintetico", methods=["POST"])
def reset_a_sintetico():
    global detector_ml, estado_modelo
    detector_ml = DetectorML()
    detector_ml.entrenar_con_datos_normales(generar_muestras_normales())
    estado_modelo.update({
        "fuente": "sintetico",
        "detalle": "Entrenado con datos sintéticos generados al arrancar el servidor",
        "cargando": False,
    })
    socketio.emit("entrenamiento_completo", estado_modelo)
    return jsonify(estado_modelo)


if __name__ == "__main__":
    db.init_db()
    print("\nCentinela (detector) corriendo en http://localhost:5050")
    print("Endpoints para proteger un login externo: POST /evaluar, POST /registrar_intento\n")
    socketio.run(app, host="0.0.0.0", port=5050, debug=True, allow_unsafe_werkzeug=True)
