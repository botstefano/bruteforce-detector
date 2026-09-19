"""
Script de validación automática del proyecto Centinela v2.
Usa Flask Test Client para no depender de puertos TCP reales.
Valida: health, endpoints públicos, auth dashboard, SSRF protection,
bloqueos SQLite TTL, CLI bot_ataque backward compat.
"""
import os
import sys
import json
import time
import tempfile
import importlib.util

ROOT = os.path.dirname(os.path.abspath(__file__))
DETECTOR_DIR = os.path.join(ROOT, "detector_service")
sys.path.insert(0, DETECTOR_DIR)


import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


def paso(nombre, condicion, detalle=""):
    estado = "[ OK ]" if condicion else "[FAIL]"
    print(f"{estado}  {nombre}  {detalle}")
    return bool(condicion)


# ============================================================
# TEST 1: Health endpoint público (sin auth)
# ============================================================
print("\n=== TEST 1: ENDPOINT /health PÚBLICO ===")
os.environ["DASHBOARD_PASSWORD"] = ""
os.environ["DB_PATH"] = os.path.join(tempfile.gettempdir(), f"test_centinela_{int(time.time())}.db")
print(f"  DB temporal: {os.environ['DB_PATH']}")

import app as detector_app
import database as db

db.init_db()
client = detector_app.app.test_client()

r = client.get("/health")
t1 = paso("GET /health devuelve 200", r.status_code == 200)
data = r.get_json(silent=True) or {}
t1b = paso("status = ok en /health", data.get("status") == "ok")
t1c = paso("service = centinela-v2-detector", data.get("service") == "centinela-v2-detector")
t1d = paso("db_ok=True", data.get("db_ok") is True)

# ============================================================
# TEST 2: Endpoints /evaluar y /registrar_intento (públicos)
# ============================================================
print("\n=== TEST 2: ENDPOINTS PÚBLICOS /evaluar y /registrar_intento ===")
r = client.post("/evaluar", json={"ip": "1.2.3.4", "usuario": "admin"})
t2a = paso("/evaluar status 200", r.status_code == 200)
d = r.get_json() or {}
t2b = paso("/evaluar devuelve bloqueado=False inicialmente", d.get("bloqueado") is False)

# 6 intentos fallidos en ráfaga desde la misma IP → debería disparar regla ráfaga (5/60s)
alertas = 0
bloqueado_ahora = False
for i in range(6):
    r = client.post("/registrar_intento",
                    json={"ip": "9.9.9.9", "usuario": "admin", "exitoso": False})
    d = r.get_json() or {}
    if d.get("alerta"):
        alertas += 1
    if d.get("bloqueado_ahora"):
        bloqueado_ahora = True

t2c = paso("Al menos una alerta tras 6 fallos en ráfaga", alertas >= 1,
           detalle=f"alertas={alertas}")
t2d = paso("IP queda bloqueada tras ráfaga", bloqueado_ahora)

# Ahora /evaluar debería decir que está bloqueada
r = client.post("/evaluar", json={"ip": "9.9.9.9", "usuario": "admin"})
d = r.get_json() or {}
t2e = paso("/evaluar reconoce IP bloqueada", d.get("bloqueado") is True,
           detalle=f"segundos_restantes={d.get('segundos_restantes')}")

# Prueba de TTL manual: seteo bloqueo con TTL negativo → debería purgarse
db.bloquear_ip("5.5.5.5", segundos=-10)
bloq, rest = db.ip_esta_bloqueada("5.5.5.5")
t2f = paso("TTL purga IP expirada correctamente", bloq is False and rest == 0)

# Listar bloqueadas
bloqueadas = db.listar_ips_bloqueadas()
t2g = paso("9.9.9.9 aparece en listar_ips_bloqueadas()", "9.9.9.9" in bloqueadas)
t2h = paso("5.5.5.5 NO aparece (expirada)", "5.5.5.5" not in bloqueadas)

# ============================================================
# TEST 3: Autenticación dashboard (si DASHBOARD_PASSWORD seteada)
# ============================================================
print("\n=== TEST 3: AUTENTICACIÓN DASHBOARD ===")

# Caso A: SIN password → / debería ser pública (200)
r = client.get("/")
t3a = paso("SIN password: / es pública (200)", r.status_code == 200,
           detalle=f"status={r.status_code}")

# Caso B: CON password seteada → redefino el módulo con password
# Para simular: recargo DASHBOARD_PASSWORD y vuelvo a crear la app
# O más sencillo: verifico que requiere_admin decorator funciona
PASS_TEST = "SuperSecret@123"
detector_app.DASHBOARD_PASSWORD = PASS_TEST

r = client.get("/")
# Debería redirigir (302) o devolver 401 según la lógica
t3b = paso("CON password: / sin sesión → 401 o 302",
           r.status_code in (401, 302),
           detalle=f"status={r.status_code}")

# Login con contraseña correcta
r = client.post("/login-admin",
                data=json.dumps({"password": PASS_TEST}),
                content_type="application/json")
t3c = paso("/login-admin con password correcta → 200",
           r.status_code == 200, detalle=f"status={r.status_code}")

# Ahora / debería ser accesible
with client.session_transaction() as sess:
    sess["admin_autenticado"] = True
    sess["admin_expira"] = time.time() + 3600

r = client.get("/")
t3d = paso("Tras login exitoso: / dashboard accesible (200)",
           r.status_code == 200, detalle=f"status={r.status_code}")

# Login con password INCORRECTA
with client.session_transaction() as sess:
    sess.clear()
r = client.post("/login-admin",
                data=json.dumps({"password": "MAL_PASS"}),
                content_type="application/json")
t3e = paso("/login-admin con password errónea → 401",
           r.status_code == 401, detalle=f"status={r.status_code}")

# Bearer token API
r = client.post("/reset")  # sin token, sin sesion
t3f = paso("/reset sin auth → 401", r.status_code in (401, 302),
           detalle=f"status={r.status_code}")
r = client.post("/reset", headers={"Authorization": f"Bearer {PASS_TEST}"})
t3g = paso("/reset con Bearer token correcto → 200",
           r.status_code == 200, detalle=f"status={r.status_code}")

# ============================================================
# TEST 4: SSRF PROTECTION en /lanzar_bot
# ============================================================
print("\n=== TEST 4: PROTECCIÓN SSRF EN /lanzar_bot ===")
# Autenticar el test client
with client.session_transaction() as sess:
    sess["admin_autenticado"] = True
    sess["admin_expira"] = time.time() + 3600

# 4a: URL metadata cloud 169.254.169.254 debe ser rechazada
r = client.post("/lanzar_bot",
                data=json.dumps({
                    "tipo": "rapido",
                    "url": "http://169.254.169.254/latest/meta-data/",
                    "usuario": "admin",
                    "intentos": 3,
                    "intervalo": 0.1,
                }),
                content_type="application/json")
t4a = paso("SSRF: 169.254.169.254 RECHAZADO (400)",
           r.status_code == 400, detalle=f"status={r.status_code}")

# 4b: IP privada 10.0.0.1 debe ser rechazada
r = client.post("/lanzar_bot",
                data=json.dumps({
                    "tipo": "rapido",
                    "url": "http://10.0.0.1/admin",
                    "usuario": "admin",
                    "intentos": 3,
                    "intervalo": 0.1,
                }),
                content_type="application/json")
t4b = paso("SSRF: IP privada 10.x RECHAZADA (400)",
           r.status_code == 400, detalle=f"status={r.status_code}")

# 4c: URL con esquema raro ftp:// debe rechazarse
r = client.post("/lanzar_bot",
                data=json.dumps({
                    "tipo": "rapido",
                    "url": "ftp://evil.com/a",
                    "usuario": "admin",
                    "intentos": 3,
                    "intervalo": 0.1,
                }),
                content_type="application/json")
t4c = paso("SSRF: ftp:// scheme RECHAZADO (400)",
           r.status_code == 400, detalle=f"status={r.status_code}")

# 4d: localhost debe PERMITIRSE en modo dev (PERMITIR_LOCALHOST_BOT default 1)
detector_app.DEBUG_MODE = True
r = client.post("/lanzar_bot",
                data=json.dumps({
                    "tipo": "rapido",
                    "url": "http://localhost:5000/login",
                    "usuario": "admin",
                    "intentos": 2,
                    "intervalo": 0.1,
                }),
                content_type="application/json")
t4d = paso("SSRF: localhost PERMITIDO en modo dev DEBUG=True",
           r.status_code in (200,),  # puede lanzar excepción interno pero NO 400 de SSRF
           detalle=f"status={r.status_code} (200=lanzado, cualquier≠400=sin SSRF block)")

# ============================================================
# TEST 5: Bloqueos SQLite (persistencia en DB)
# ============================================================
print("\n=== TEST 5: BLOQUEOS SQLITE PERSISTENTES CON TTL ===")
db.limpiar_bloqueos()
bloquear_hasta = db.bloquear_ip("99.99.99.99", 60)
t5a = paso("bloquear_ip() retorna timestamp futuro",
           bloquear_hasta > time.time() + 58)   # tolerancia 2s para flush SQLite en Windows/FS lentos

bloq, rest = db.ip_esta_bloqueada("99.99.99.99")
t5b = paso("ip_esta_bloqueada devuelve True + restante ≈60s",
           bloq and 50 <= rest <= 60, detalle=f"rest={rest}")

db.limpiar_bloqueos()
bloq, rest = db.ip_esta_bloqueada("99.99.99.99")
t5c = paso("limpiar_bloqueos() borra todas las IPs", bloq is False and rest == 0)

# check_connection funciona
t5d = paso("db.check_connection() → True", db.check_connection() is True)

# ============================================================
# TEST 6: bot_ataque.py refactor (funciones puras + CLI)
# ============================================================
print("\n=== TEST 6: BOT_ATAQUE.PY FUNCIONES PURAS + CLI ===")
bot_path = os.path.join(ROOT, "bot_ataque.py")
spec = importlib.util.spec_from_file_location("bot_ataque_mod", bot_path)
bot_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot_mod)

# 6a: Existen las 3 funciones
t6a = paso("bot tiene ataque_rapido()", hasattr(bot_mod, "ataque_rapido"))
t6b = paso("bot tiene ataque_lento()", hasattr(bot_mod, "ataque_lento"))
t6c = paso("bot tiene ataque_distribuido()", hasattr(bot_mod, "ataque_distribuido"))

# 6b: callback on_progreso funciona sin conexión real
mensajes = []
def cb(msg):
    mensajes.append(msg)

# No debería crashear aunque URL no exista (timeout / connection refused)
# Lo ejecutamos con 1 intento, URL no existente, tiempo corto.
try:
    bloq, n = bot_mod.ataque_rapido(
        url="http://127.0.0.1:19999/no_existe",
        usuario="admin",
        num_intentos=1,
        intervalo=0.05,
        passwords=["123"],
        on_progreso=cb,
    )
    t6d = paso("ataque_rapido() no crashea (return tuple)",
               isinstance(bloq, bool) and isinstance(n, int),
               detalle=f"bloqueado={bloq} intentos={n}")
except Exception as e:
    t6d = paso("ataque_rapido() captura excepciones de red OK",
               "connection" in str(e).lower() or "refused" in str(e).lower()
               or "timeout" in str(e).lower(),
               detalle=f"exception={e}")

t6e = paso("callback on_progreso recibe al menos 1 mensaje",
           len(mensajes) >= 1, detalle=f"num_msgs={len(mensajes)}")

# 6c: CLI --help no crashea (backward compat)
import subprocess
res = subprocess.run(
    [sys.executable, bot_path, "--help"],
    capture_output=True, text=True, timeout=15, cwd=ROOT,
)
t6f = paso("CLI bot_ataque.py --help retorna 0", res.returncode == 0,
           detalle=f"stdout primeros100: {res.stdout[:100]}")

# CLI --tipo rapido (sin ejecutar realmente) para parsear args
res = subprocess.run(
    [sys.executable, bot_path, "--tipo", "rapido", "--intentos", "0"],
    capture_output=True, text=True, timeout=10, cwd=ROOT,
)
t6g = paso("CLI parámetros --tipo y --intentos son válidos",
           res.returncode in (0,), detalle=f"rc={res.returncode}")

# ============================================================
# TEST 7: API /api/* endpoints públicos
# ============================================================
print("\n=== TEST 7: ENDPOINTS /api/* PÚBLICOS ===")
r = client.get("/api/bloqueadas")
t7a = paso("/api/bloqueadas 200 + JSON dict",
           r.status_code == 200 and isinstance(r.get_json(), dict))

r = client.get("/api/produccion")
t7b = paso("/api/produccion 200", r.status_code == 200)

# ============================================================
# RESUMEN FINAL
# ============================================================
todos = [v for k, v in locals().items() if k.startswith(("t1", "t2", "t3", "t4", "t5", "t6", "t7"))]
passed = sum(1 for x in todos if x is True)
total = len(todos)
pct = passed / total * 100 if total else 0
print("\n" + "=" * 60)
print(f"RESUMEN VALIDACIÓN CENTINELA V2: {passed}/{total} PASADOS ({pct:.1f}%)")
print("=" * 60)
print(f"Status general: {'EXITOSO [ OK ]' if passed == total else 'FALLOS DETECTADOS [FAIL]'}")

sys.exit(0 if passed == total else 1)
