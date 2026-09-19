"""
database.py
Capa de acceso a datos: almacena cada intento de login y las
decisiones tomadas por los detectores (reglas y ML), y ahora también
la **lista negra de IPs bloqueadas con TTL** (para que sobreviva a
reinicios del proceso y sea compartida entre múltiples workers).

NUEVO en esta versión: columna 'es_simulado'. Distingue:
  - es_simulado=1 -> tráfico generado por los botones del dashboard,
    experimento.py, o el bot de pruebas (tiene 'es_ataque_real' confiable,
    porque tú mismo lo generaste sabiendo qué era)
  - es_simulado=0 -> tráfico real que llegó desde un login externo vía
    /registrar_intento (no se conoce con certeza si fue un ataque real,
    así que NO se usa para calcular precisión/recall del artículo)

Esto evita que tráfico de producción real contamine las métricas de
validación experimental.
"""
import os
import sqlite3
import time
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DB_PATH", "data/eventos.db")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS intentos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                ip TEXT NOT NULL,
                usuario TEXT NOT NULL,
                exitoso INTEGER NOT NULL,
                es_ataque_real INTEGER NOT NULL DEFAULT 0,
                alerta_reglas INTEGER NOT NULL DEFAULT 0,
                alerta_ml INTEGER NOT NULL DEFAULT 0,
                origen TEXT DEFAULT 'simulador',
                es_simulado INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip_timestamp
            ON intentos (ip, timestamp)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_bloqueadas (
                ip TEXT PRIMARY KEY,
                hasta REAL NOT NULL,
                creada_en REAL NOT NULL
            )
        """)


def registrar_intento(ip, usuario, exitoso, es_ataque_real=0,
                       alerta_reglas=0, alerta_ml=0, origen="simulador",
                       timestamp=None, es_simulado=1):
    ts = timestamp if timestamp is not None else time.time()
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO intentos
            (timestamp, ip, usuario, exitoso, es_ataque_real,
             alerta_reglas, alerta_ml, origen, es_simulado)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, ip, usuario, int(exitoso), int(es_ataque_real),
              int(alerta_reglas), int(alerta_ml), origen, int(es_simulado)))
        return cur.lastrowid


def obtener_intentos_recientes(limite=200, solo_produccion=False):
    with get_conn() as conn:
        if solo_produccion:
            rows = conn.execute("""
                SELECT * FROM intentos WHERE es_simulado=0
                ORDER BY timestamp DESC LIMIT ?
            """, (limite,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM intentos ORDER BY timestamp DESC LIMIT ?
            """, (limite,)).fetchall()
        return [dict(r) for r in rows]


def limpiar():
    with get_conn() as conn:
        conn.execute("DELETE FROM intentos")


def metricas_resumen():
    """Calcula matriz de confusión y métricas para reglas y ML, usando
    'es_ataque_real' como verdad fundamental. SOLO considera eventos
    simulados (es_simulado=1) -- tráfico real de producción no tiene
    verdad fundamental confiable y se excluye de estas métricas."""
    with get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) c FROM intentos WHERE es_simulado=1"
        ).fetchone()["c"]
        if total == 0:
            return None

        resultado = {}
        for metodo in ["alerta_reglas", "alerta_ml"]:
            vp = conn.execute(f"""
                SELECT COUNT(*) c FROM intentos
                WHERE es_simulado=1 AND es_ataque_real=1 AND {metodo}=1
            """).fetchone()["c"]
            fn = conn.execute(f"""
                SELECT COUNT(*) c FROM intentos
                WHERE es_simulado=1 AND es_ataque_real=1 AND {metodo}=0
            """).fetchone()["c"]
            fp = conn.execute(f"""
                SELECT COUNT(*) c FROM intentos
                WHERE es_simulado=1 AND es_ataque_real=0 AND {metodo}=1
            """).fetchone()["c"]
            vn = conn.execute(f"""
                SELECT COUNT(*) c FROM intentos
                WHERE es_simulado=1 AND es_ataque_real=0 AND {metodo}=0
            """).fetchone()["c"]

            precision = vp / (vp + fp) if (vp + fp) > 0 else 0
            recall = vp / (vp + fn) if (vp + fn) > 0 else 0
            f1 = (2 * precision * recall / (precision + recall)
                  if (precision + recall) > 0 else 0)

            resultado[metodo] = {
                "verdaderos_positivos": vp,
                "falsos_negativos": fn,
                "falsos_positivos": fp,
                "verdaderos_negativos": vn,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1": round(f1, 3),
            }
        resultado["total_intentos"] = total
        return resultado


def contador_produccion():
    """Cuenta eventos reales de producción (es_simulado=0), para
    mostrar en el dashboard sin mezclarlos con las métricas del
    experimento."""
    with get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) c FROM intentos WHERE es_simulado=0"
        ).fetchone()["c"]
        alertas = conn.execute("""
            SELECT COUNT(*) c FROM intentos
            WHERE es_simulado=0 AND (alerta_reglas=1 OR alerta_ml=1)
        """).fetchone()["c"]
        return {"total": total, "alertas": alertas}


# =================================================================
# Gestión de IPs bloqueadas (con TTL, persistente en SQLite)
# Reemplaza el diccionario en memoria para que sobreviva a reinicios
# y sea compartida entre múltiples workers de Gunicorn.
# =================================================================

def _purgar_expiradas(conn):
    ahora = time.time()
    conn.execute("DELETE FROM ip_bloqueadas WHERE hasta <= ?", (ahora,))


def ip_esta_bloqueada(ip):
    ahora = time.time()
    with get_conn() as conn:
        _purgar_expiradas(conn)
        row = conn.execute(
            "SELECT hasta FROM ip_bloqueadas WHERE ip = ?", (ip,)
        ).fetchone()
        if row is None:
            return False, 0
        restante = int(row["hasta"] - ahora)
        if restante <= 0:
            return False, 0
        return True, restante


def bloquear_ip(ip, segundos):
    ahora = time.time()
    hasta = ahora + segundos
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO ip_bloqueadas (ip, hasta, creada_en)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                hasta = excluded.hasta,
                creada_en = excluded.creada_en
        """, (ip, hasta, ahora))
    return hasta


def listar_ips_bloqueadas():
    ahora = time.time()
    with get_conn() as conn:
        _purgar_expiradas(conn)
        rows = conn.execute(
            "SELECT ip, hasta FROM ip_bloqueadas WHERE hasta > ?", (ahora,)
        ).fetchall()
        return {r["ip"]: int(r["hasta"] - ahora) for r in rows}


def limpiar_bloqueos():
    with get_conn() as conn:
        conn.execute("DELETE FROM ip_bloqueadas")


def check_connection():
    try:
        with get_conn() as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False
