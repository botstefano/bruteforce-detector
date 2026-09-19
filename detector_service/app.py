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

ENDPOINTS DE ADMINISTRACIÓN / DEMO (dashboard, experimentos, pruebas)
  — requieren autenticación por token o contraseña maestra del dashboard:
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
    POST /lanzar_bot                     -> lanza el bot atacante contra el login demo

El dashboard se actualiza en tiempo real vía WebSockets (Flask-SocketIO)
tanto con tráfico simulado como con tráfico real de producción, para que
un administrador pueda monitorear todo desde un solo lugar.
"""
import os
import secrets
import random
import string
import threading
import time
import ipaddress
from urllib.parse import urlparse
from functools import wraps

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_socketio import SocketIO, emit, disconnect
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

import database as db
from detector_reglas import DetectorReglas
from detector_ml import DetectorML, generar_muestras_normales
from entrenar_con_cicids import (
    cargar_cicids, preparar_eventos, entrenar_detector_ml_con_benignos,
)

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)

# =====================================================================
# ProxyFix para entornos detrás de balanceadores (Render, Cloudflare, etc.)
# Valores recomendados según TRUSTED_PROXIES:
#   "render"     -> x_for=2, x_proto=1, x_host=1, x_port=1 (Render: 2 proxies)
#   "cloudflare" -> x_for=1
#   "" (default) -> sin ProxyFix (localhost/dev)
# =====================================================================
_trusted = os.getenv("TRUSTED_PROXIES", "").strip().lower()
if _trusted == "render":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1, x_port=1, x_prefix=1)
elif _trusted == "cloudflare":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
elif _trusted:
    try:
        n = max(1, int(_trusted))
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=1, x_host=1)
    except ValueError:
        pass


@app.after_request
def aplicar_headers_seguridad(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "connect-src 'self' https: wss: ws:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), interest-cohort=(), "
        "fullscreen=(self), payment=()"
    )
    return response


def _ip_del_cliente(data_override=None):
    """Devuelve la IP real del cliente priorizando:
    1) Campo 'ip' del body JSON (si el login externo ya la resolvió).
    2) request.remote_addr (ya arreglado por ProxyFix si TRUSTED_PROXIES está seteado).
    3) Header X-Forwarded-For como fallback manual.
    """
    if isinstance(data_override, dict):
        explicit_ip = (data_override.get("ip") or "").strip()
        if explicit_ip:
            return explicit_ip
    proxy_fix_activo = bool(_trusted)
    if proxy_fix_activo:
        ip_proxy = request.remote_addr or ""
        if ip_proxy and ip_proxy not in ("127.0.0.1", "0.0.0.0", "::1"):
            return ip_proxy
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip() or request.remote_addr
    return request.remote_addr or "0.0.0.0"

_origins_raw = os.getenv("ALLOWED_ORIGINS", "*")
if _origins_raw.strip() in ("*", ""):
    _allowed_origins = "*"
else:
    _allowed_origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]

socketio = SocketIO(
    app,
    cors_allowed_origins=_allowed_origins,
    async_mode=os.getenv("SOCKETIO_ASYNC_MODE", "eventlet"),
)

DURACION_BLOQUEO_SEGUNDOS = int(os.getenv("DURACION_BLOQUEO_SEGUNDOS", "300"))
DEBUG_MODE = os.getenv("FLASK_ENV", "production").lower() == "development"
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD")
DASHBOARD_TOKEN_EXPIRY_SEG = 60 * 60 * 8  # 8h

detector_reglas = DetectorReglas()
detector_ml = DetectorML()
detector_ml.entrenar_con_datos_normales(generar_muestras_normales())

estado_modelo = {
    "fuente": "sintetico",
    "detalle": "Entrenado con datos sintéticos generados al arrancar el servidor. "
               "Se recomienda entrenar con CICIDS2017 para mayor realismo.",
    "cargando": False,
}

CREDENCIALES_VALIDAS = {
    "admin": "S3guro#2026",
    "jperez": "Trujillo!456",
    "mgarcia": "Contrasena_88",
}

USUARIOS_COMUNES = ["admin", "root", "administrator", "user", "test",
                     "jperez", "mgarcia", "guest", "info", "support"]
PASSWORDS_COMUNES = ["123456", "password", "admin123", "qwerty",
                      "letmein", "12345678", "root", "changeme"]


# =================================================================
# Autenticación para rutas administrativas: 2 estrategias
# 1) Sesión cookie con contraseña maestra (UI humana del dashboard)
# 2) Bearer token en header Authorization (para API / scripts)
# =================================================================

def _api_token_valido():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if DASHBOARD_PASSWORD and secrets.compare_digest(token, DASHBOARD_PASSWORD):
            return True
    return False


def requiere_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if DASHBOARD_PASSWORD is None or len(DASHBOARD_PASSWORD) == 0:
            return f(*args, **kwargs)
        if _api_token_valido():
            return f(*args, **kwargs)
        if session.get("admin_autenticado", False):
            expira = session.get("admin_expira", 0)
            if expira > time.time():
                return f(*args, **kwargs)
            session.clear()
        if request.path.startswith("/api/") or request.method == "POST":
            return jsonify({"error": "autenticación requerida"}), 401
        return redirect(url_for("login_dashboard"))
    return wrapper


@app.route("/login-admin", methods=["GET", "POST"])
def login_dashboard():
    if DASHBOARD_PASSWORD is None or len(DASHBOARD_PASSWORD) == 0:
        session["admin_autenticado"] = True
        session["admin_expira"] = time.time() + DASHBOARD_TOKEN_EXPIRY_SEG
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        pwd = (request.form or {}).get("password", "") or \
              ((request.get_json(silent=True) or {}).get("password", ""))
        if secrets.compare_digest(pwd, DASHBOARD_PASSWORD):
            session["admin_autenticado"] = True
            session["admin_expira"] = time.time() + DASHBOARD_TOKEN_EXPIRY_SEG
            if request.is_json:
                return jsonify({"status": "ok"})
            return redirect(url_for("dashboard"))
        if request.is_json:
            return jsonify({"error": "contraseña incorrecta"}), 401
        return render_template(
            "login_admin.html",
            error="Contraseña incorrecta.",
            tiene_password=True,
        )
    return render_template("login_admin.html", error=None, tiene_password=True)


@app.route("/logout-admin", methods=["GET", "POST"])
def logout_admin():
    session.clear()
    return redirect(url_for("login_dashboard"))


@socketio.on("connect")
def _socketio_connect():
    if DASHBOARD_PASSWORD and len(DASHBOARD_PASSWORD) > 0:
        if not (session.get("admin_autenticado") and session.get("admin_expira", 0) > time.time()):
            token = None
            try:
                token = request.args.get("token")
            except Exception:
                pass
            if not (token and secrets.compare_digest(token, DASHBOARD_PASSWORD)):
                disconnect()
                return False
    return True


# =================================================================
# Helpers
# =================================================================

def _ip_aleatoria():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _es_url_segura(url):
    """Evita SSRF: no permitir IPs privadas/loopback/link-local,
    salvo localhost en modo development explícito."""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = (p.hostname or "").lower()
        if not host:
            return False
        if host in ("localhost", "127.0.0.1", "::1"):
            return DEBUG_MODE or os.getenv("PERMITIR_LOCALHOST_BOT", "1") == "1"
        try:
            ip = ipaddress.ip_address(host)
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                return False
        except ValueError:
            pass
        return True
    except Exception:
        return False


def _procesar_intento(ip, usuario, password_o_exitoso, es_ataque_real,
                       origen, es_simulado=1, ya_es_booleano_exitoso=False):
    ahora = time.time()
    if ya_es_booleano_exitoso:
        exitoso = bool(password_o_exitoso)
    else:
        exitoso = CREDENCIALES_VALIDAS.get(usuario) == password_o_exitoso

    resultado_reglas = detector_reglas.evaluar(ip, usuario, exitoso, ahora)
    resultado_ml = detector_ml.registrar_y_evaluar(ip, usuario, exitoso, ahora)

    alerta = resultado_reglas["alerta"] or resultado_ml["alerta"]
    if alerta:
        db.bloquear_ip(ip, DURACION_BLOQUEO_SEGUNDOS)

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


# =================================================================
# Ruta principal: dashboard (con auth si hay contraseña)
# =================================================================

@app.route("/")
@requiere_admin
def dashboard():
    return render_template("dashboard.html", requiere_auth=bool(DASHBOARD_PASSWORD))


# =================================================================
# ENDPOINTS GENÉRICOS PARA PROTEGER UN LOGIN EXTERNO REAL
# (SIN autenticación — cualquier login externo los usa)
# =================================================================

@app.route("/health")
def health_check():
    return jsonify({
        "status": "ok",
        "service": "centinela-v2-detector",
        "timestamp": time.time(),
        "db_ok": db.check_connection() if hasattr(db, "check_connection") else True,
    })


@app.route("/evaluar", methods=["POST"])
def evaluar():
    """Se llama ANTES de validar la contraseña en el sistema de login real."""
    data = request.get_json(force=True, silent=True) or {}
    ip = _ip_del_cliente(data)
    usuario = data.get("usuario", "")

    bloqueada, restante = db.ip_esta_bloqueada(ip)
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
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or request.remote_addr or "0.0.0.0"
    usuario = data.get("usuario", "")
    exitoso = bool(data.get("exitoso", False))
    ahora = time.time()

    resultado_reglas = detector_reglas.evaluar(ip, usuario, exitoso, ahora)
    resultado_ml = detector_ml.registrar_y_evaluar(ip, usuario, exitoso, ahora)
    alerta = resultado_reglas["alerta"] or resultado_ml["alerta"]

    if alerta:
        db.bloquear_ip(ip, DURACION_BLOQUEO_SEGUNDOS)

    evento_id = db.registrar_intento(
        ip=ip, usuario=usuario, exitoso=exitoso,
        es_ataque_real=0,
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
    return jsonify(db.listar_ips_bloqueadas())


@app.route("/api/produccion")
def api_produccion():
    return jsonify(db.contador_produccion())


# =================================================================
# LOGIN DE PRUEBA INTERNO (solo para demos, NO usar en producción)
# =================================================================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    ip = _ip_del_cliente(data)
    usuario = data.get("usuario", "")
    password = data.get("password", "")

    bloqueada, restante = db.ip_esta_bloqueada(ip)
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


# =================================================================
# SIMULACIÓN PARA DEMOS Y EXPERIMENTOS (solo admin)
# =================================================================

def _lanzar_ataque_rapido(usuario_objetivo, num_intentos=10, intervalo=0.3):
    ip = _ip_aleatoria()
    for _ in range(num_intentos):
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd, es_ataque_real=1, origen="ataque_rapido")
        time.sleep(intervalo)


def _lanzar_ataque_lento(usuario_objetivo, num_intentos=10, intervalo=2.0):
    ip = _ip_aleatoria()
    for _ in range(num_intentos):
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd, es_ataque_real=1, origen="ataque_lento")
        time.sleep(intervalo)


def _lanzar_ataque_distribuido(usuario_objetivo, num_ips=6, intervalo=0.2):
    ips = [_ip_aleatoria() for _ in range(num_ips)]
    for ip in ips:
        pwd = random.choice(PASSWORDS_COMUNES)
        _procesar_intento(ip, usuario_objetivo, pwd, es_ataque_real=1, origen="ataque_distribuido")
        time.sleep(intervalo)


@app.route("/simular/ataque", methods=["POST"])
@requiere_admin
def simular_ataque():
    data = request.get_json(force=True, silent=True) or {}
    tipo = data.get("tipo", "rapido")
    usuario = data.get("usuario") or random.choice(USUARIOS_COMUNES)
    intervalo = float(data.get("intervalo",
        0.3 if tipo == "rapido" else 2.0 if tipo == "lento" else 0.2))
    num_intentos = int(data.get("intentos", 10))
    num_ips = int(data.get("ips", 6))

    if tipo == "rapido":
        hilo = threading.Thread(target=_lanzar_ataque_rapido,
                                args=(usuario, num_intentos, intervalo))
    elif tipo == "lento":
        hilo = threading.Thread(target=_lanzar_ataque_lento,
                                args=(usuario, num_intentos, intervalo))
    elif tipo == "distribuido":
        hilo = threading.Thread(target=_lanzar_ataque_distribuido,
                                args=(usuario, num_ips, intervalo))
    else:
        return jsonify({"error": "tipo de ataque no reconocido"}), 400

    hilo.daemon = True
    hilo.start()
    return jsonify({"status": "lanzado", "tipo": tipo, "usuario": usuario})


def _generar_login_legitimo(cantidad_intervalo_min=1.0, cantidad_intervalo_max=3.0):
    ip = _ip_aleatoria()
    usuario = random.choice(list(CREDENCIALES_VALIDAS.keys()))
    if random.random() < 0.85:
        password = CREDENCIALES_VALIDAS[usuario]
    else:
        password = "clave_equivocada"
    _procesar_intento(ip, usuario, password, es_ataque_real=0, origen="trafico_legitimo")
    return cantidad_intervalo_min, cantidad_intervalo_max


@app.route("/simular/legitimo", methods=["POST"])
@requiere_admin
def simular_legitimo():
    data = request.get_json(force=True, silent=True) or {}
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
@requiere_admin
def reset():
    db.limpiar()
    db.limpiar_bloqueos()
    detector_reglas.reset()
    detector_ml.reset()
    socketio.emit("reset")
    return jsonify({"status": "ok"})


@app.route("/api/eventos")
@requiere_admin
def api_eventos():
    return jsonify(db.obtener_intentos_recientes(300))


@app.route("/api/metricas")
def api_metricas():
    return jsonify(db.metricas_resumen())


@app.route("/api/estado_modelo")
def api_estado_modelo():
    return jsonify(estado_modelo)


# =================================================================
# Entrenamiento CICIDS / sintético (admin)
# =================================================================

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
@requiere_admin
def entrenar_cicids():
    if estado_modelo["cargando"]:
        return jsonify({"error": "ya hay un entrenamiento en curso"}), 409

    data = request.get_json(force=True, silent=True) or {}
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
@requiere_admin
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


# =================================================================
# Endpoint: lanzar bot GUI (admin) — integración con bot_ataque.py
# =================================================================

@app.route("/lanzar_bot", methods=["POST"])
@requiere_admin
def lanzar_bot_endpoint():
    data = request.get_json(force=True, silent=True) or {}
    tipo = data.get("tipo", "rapido")
    if tipo not in ("rapido", "lento", "distribuido"):
        return jsonify({"error": "tipo invalido"}), 400

    url = (data.get("url") or os.getenv("LOGIN_DEMO_URL",
           "http://localhost:5000/login")).strip()
    if not _es_url_segura(url):
        return jsonify({"error": "URL no permitida por politica SSRF"}), 400

    usuario = data.get("usuario") or None
    intentos = int(data.get("intentos", 10))
    ips = int(data.get("ips", 6))
    intervalo = float(data.get("intervalo",
        0.3 if tipo == "rapido" else 2.0 if tipo == "lento" else 0.2))
    passwords_custom = None
    if isinstance(data.get("passwords"), list) and data["passwords"]:
        passwords_custom = [str(p) for p in data["passwords"] if str(p).strip()]

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "bot_modulo",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bot_ataque.py"))
        )
        bot_modulo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bot_modulo)
    except Exception as e:
        return jsonify({"error": f"no se pudo cargar bot_ataque.py: {e}"}), 500

    def _emitir_log(mensaje):
        socketio.emit("bot_log", {"mensaje": mensaje, "timestamp": time.time()})

    def _tarea():
        _emitir_log(f"Iniciando ataque {tipo} contra {url} ...")
        try:
            kwargs = {"url": url, "usuario": usuario, "on_progreso": _emitir_log}
            if tipo == "rapido":
                kwargs.update(num_intentos=intentos, intervalo=intervalo)
                if passwords_custom: kwargs["passwords"] = passwords_custom
                bot_modulo.ataque_rapido(**kwargs)
            elif tipo == "lento":
                kwargs.update(num_intentos=intentos, intervalo=intervalo)
                if passwords_custom: kwargs["passwords"] = passwords_custom
                bot_modulo.ataque_lento(**kwargs)
            else:
                kwargs.update(num_ips=ips, intervalo=intervalo)
                if passwords_custom: kwargs["passwords"] = passwords_custom
                bot_modulo.ataque_distribuido(**kwargs)
        except Exception as e:
            _emitir_log(f"[ERROR] {e}")
        _emitir_log("Ataque finalizado.")

    hilo = threading.Thread(target=_tarea, daemon=True)
    hilo.start()
    return jsonify({"status": "lanzado", "tipo": tipo, "url": url})


if __name__ == "__main__":
    db.init_db()
    print("\nCentinela (detector) corriendo en http://localhost:5050")
    print("Endpoints para proteger un login externo: POST /evaluar, POST /registrar_intento")
    if DASHBOARD_PASSWORD:
        print(f"Dashboard protegido con contraseña. Visita http://localhost:5050/login-admin")
    socketio.run(app, host="0.0.0.0", port=5050, debug=DEBUG_MODE,
                 allow_unsafe_werkzeug=DEBUG_MODE)
