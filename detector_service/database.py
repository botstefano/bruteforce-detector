"""
database.py
Capa de acceso a datos: almacena cada intento de login y las
decisiones tomadas por los detectores (reglas y ML).

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
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "data/eventos.db"


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
