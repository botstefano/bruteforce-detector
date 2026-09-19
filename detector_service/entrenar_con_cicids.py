"""
entrenar_con_cicids.py

Traduce el dataset CICIDS2017 al formato de eventos que esperan los
detectores ORIGINALES del prototipo (detector_reglas.py y detector_ml.py),
sin modificar ni una línea de esos dos archivos.

MAPEO usado (supuesto metodológico a declarar en el artículo):
    - IP origen del flujo de red   -> "ip" del intento de login
    - IP destino del flujo de red  -> "usuario" objetivo (el servicio atacado)
    - Timestamp del flujo          -> timestamp del intento
    - Todo flujo BENIGN            -> intento "exitoso=False" de tráfico normal
      (no hay concepto de "contraseña correcta" en CICIDS, así que todos los
      eventos se tratan como intentos fallidos; lo relevante para las features
      es la CADENCIA temporal, no el resultado del login)
    - Todo flujo *Bruteforce*      -> intento "exitoso=False" de ataque real

Esto asume que la cadencia de conexiones en un ataque de fuerza bruta SSH/FTP
es representativa de la cadencia de intentos de autenticación individuales
(supuesto razonable: en fuerza bruta SSH cada conexión suele ser un intento).

USO:
    python entrenar_con_cicids.py --carpeta /ruta/a/MachineLearningCSV

Requiere que detector_reglas.py y detector_ml.py estén en la misma carpeta
(son los archivos ORIGINALES del prototipo, sin cambios).
"""
import os
import glob
import argparse
import csv
import numpy as np
import pandas as pd

from detector_reglas import DetectorReglas
from detector_ml import DetectorML


# ---------- Carga y normalización de columnas ----------

POSIBLES_COLS_IP_ORIGEN = ["Source IP", " Source IP", "src_ip"]
POSIBLES_COLS_IP_DESTINO = ["Destination IP", " Destination IP", "dst_ip"]
POSIBLES_COLS_TIMESTAMP = ["Timestamp", " Timestamp"]
POSIBLES_COLS_LABEL = ["Label", " Label", "label"]


def _buscar_columna(df, candidatas):
    for c in candidatas:
        if c in df.columns:
            return c
    return None


def cargar_cicids(carpeta):
    archivos = glob.glob(os.path.join(carpeta, "*.csv"))
    if not archivos:
        raise FileNotFoundError(f"No se encontraron CSV en {carpeta}")

    print(f"Encontrados {len(archivos)} archivos CSV")
    dfs = []
    for archivo in archivos:
        print(f"  Cargando {os.path.basename(archivo)}...", end=" ", flush=True)
        try:
            df = pd.read_csv(archivo, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
            print(f"OK ({len(df)} filas)")
        except Exception as e:
            print(f"ERROR: {e}")
    return pd.concat(dfs, ignore_index=True)


def preparar_eventos(df):
    """
    Convierte el DataFrame de CICIDS en una lista de eventos con la forma
    exacta que espera el prototipo original: (timestamp, ip, usuario,
    exitoso, es_ataque_real).
    """
    col_label = _buscar_columna(df, POSIBLES_COLS_LABEL)
    if col_label is None:
        raise ValueError("No se encontró columna de etiqueta (Label) en el dataset")
    df[col_label] = df[col_label].astype(str).str.strip().str.lower()

    col_ip_origen = _buscar_columna(df, POSIBLES_COLS_IP_ORIGEN)
    col_ip_destino = _buscar_columna(df, POSIBLES_COLS_IP_DESTINO)
    col_timestamp = _buscar_columna(df, POSIBLES_COLS_TIMESTAMP)

    usa_ips_reales = col_ip_origen is not None and col_ip_destino is not None
    usa_timestamp_real = col_timestamp is not None

    if not usa_ips_reales:
        print("\nAVISO: este CSV no trae columnas de IP origen/destino "
              "(la versión 'MachineLearningCSV' de CICIDS2017 suele omitirlas "
              "por privacidad). Se usarán IPs sintéticas agrupando filas "
              "consecutivas de la misma clase como si vinieran del mismo host. "
              "Esto es una aproximación adicional que debe declararse en el "
              "artículo junto con el supuesto de traducción principal.\n")

    if not usa_timestamp_real:
        print("\nAVISO: este CSV no trae columna de Timestamp utilizable. "
              "Se generarán timestamps sintéticos que preservan el ORDEN "
              "de las filas, espaciados 1 segundo entre sí dentro de cada "
              "grupo de ataque/benigno.\n")

    df = df[df[col_label].notna()].reset_index(drop=True)

    eventos = []
    tiempo_sintetico_base = 1_700_000_000.0  # ancla arbitraria, solo para orden relativo

    if usa_ips_reales:
        grupos_ip_origen = df[col_ip_origen]
    else:
        # Agrupa cada 10 filas consecutivas de la misma etiqueta como "una IP"
        # (aproximación cuando el dataset no trae IPs reales)
        grupos_ip_origen = (
            df.groupby((df[col_label] != df[col_label].shift()).cumsum())
              .cumcount() // 10
        ).astype(str) + "_" + df[col_label].astype(str)
        grupos_ip_origen = "host_" + grupos_ip_origen

    for i, fila in df.iterrows():
        label = fila[col_label]
        es_ataque = "bruteforce" in label or "brute force" in label or "patator" in label

        ip = str(grupos_ip_origen.iloc[i]) if usa_ips_reales else str(grupos_ip_origen.iloc[i])
        usuario = str(fila[col_ip_destino]) if usa_ips_reales else "servicio_objetivo"

        if usa_timestamp_real:
            try:
                ts = pd.to_datetime(fila[col_timestamp]).timestamp()
            except Exception:
                ts = tiempo_sintetico_base + i * 1.0
        else:
            ts = tiempo_sintetico_base + i * 1.0

        eventos.append({
            "timestamp": ts,
            "ip": ip,
            "usuario": usuario,
            "exitoso": False,       # CICIDS no distingue éxito de login
            "es_ataque_real": es_ataque,
        })

    eventos.sort(key=lambda e: e["timestamp"])
    return eventos


# ---------- Entrenamiento y evaluación con las clases ORIGINALES ----------

def entrenar_detector_ml_con_benignos(eventos_benignos):
    """
    Usa el mismo extractor de features interno de DetectorML
    (detector_ml.py, sin modificar) para construir muestras de
    entrenamiento a partir de tráfico BENIGN real de CICIDS.
    """
    detector_temporal = DetectorML()  # solo para usar su extractor de features

    muestras = []
    for ev in eventos_benignos:
        detector_temporal.intentos_por_ip[ev["ip"]].append((ev["timestamp"], ev["usuario"]))
        features = detector_temporal._extraer_features(ev["ip"], ev["timestamp"])
        muestras.append(features)

    detector_ml = DetectorML()
    detector_ml.entrenar_con_datos_normales(muestras)
    return detector_ml


def evaluar_todos_los_eventos(eventos, detector_reglas, detector_ml):
    resultados = []
    for ev in eventos:
        res_reglas = detector_reglas.evaluar(ev["ip"], ev["usuario"], ev["exitoso"], ev["timestamp"])
        res_ml = detector_ml.registrar_y_evaluar(ev["ip"], ev["usuario"], ev["exitoso"], ev["timestamp"])

        resultados.append({
            "es_ataque_real": ev["es_ataque_real"],
            "alerta_reglas": res_reglas["alerta"],
            "alerta_ml": res_ml["alerta"],
        })
    return resultados


def calcular_metricas(resultados):
    metricas = {}
    for campo in ["alerta_reglas", "alerta_ml"]:
        vp = sum(1 for r in resultados if r["es_ataque_real"] and r[campo])
        fn = sum(1 for r in resultados if r["es_ataque_real"] and not r[campo])
        fp = sum(1 for r in resultados if not r["es_ataque_real"] and r[campo])
        vn = sum(1 for r in resultados if not r["es_ataque_real"] and not r[campo])

        precision = vp / (vp + fp) if (vp + fp) > 0 else 0
        recall = vp / (vp + fn) if (vp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metricas[campo] = {
            "verdaderos_positivos": vp, "falsos_negativos": fn,
            "falsos_positivos": fp, "verdaderos_negativos": vn,
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        }
    return metricas


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--carpeta", required=True, help="Carpeta con los CSV de CICIDS2017")
    parser.add_argument("--max_benignos", type=int, default=20000,
                         help="Límite de flujos BENIGN a usar (por rendimiento; default 20000)")
    parser.add_argument("--salida", default="resultados_cicids_traducido.csv")
    args = parser.parse_args()

    print(f"Cargando CICIDS2017 desde {args.carpeta}...")
    df = cargar_cicids(args.carpeta)

    print(f"\nTraduciendo {len(df)} filas al formato de eventos del prototipo...")
    eventos = preparar_eventos(df)

    eventos_benignos = [e for e in eventos if not e["es_ataque_real"]]
    eventos_ataque = [e for e in eventos if e["es_ataque_real"]]

    print(f"  Eventos benignos: {len(eventos_benignos)}")
    print(f"  Eventos de ataque: {len(eventos_ataque)}")

    if len(eventos_ataque) == 0:
        print("ERROR: no se encontraron eventos de ataque (bruteforce) en el dataset.")
        return

    # Limitar benignos por rendimiento (evaluar millones de filas es lento
    # en Python puro con las clases originales, que no están vectorizadas)
    if len(eventos_benignos) > args.max_benignos:
        print(f"  Limitando a {args.max_benignos} eventos benignos por rendimiento "
              f"(usa --max_benignos para ajustar)")
        paso = len(eventos_benignos) // args.max_benignos
        eventos_benignos = eventos_benignos[::paso][:args.max_benignos]

    print("\nEntrenando DetectorML con tráfico BENIGN real de CICIDS2017...")
    detector_ml = entrenar_detector_ml_con_benignos(eventos_benignos)
    print("Listo.")

    # Reset del detector de reglas y reinicio de colas del ML antes de evaluar,
    # para que el entrenamiento no "contamine" el historial de la evaluación
    detector_ml.reset()
    detector_reglas = DetectorReglas()

    todos_los_eventos = sorted(eventos_benignos + eventos_ataque, key=lambda e: e["timestamp"])

    print(f"\nEvaluando {len(todos_los_eventos)} eventos con ambos detectores "
          "(reglas y ML originales del prototipo)...")
    resultados = evaluar_todos_los_eventos(todos_los_eventos, detector_reglas, detector_ml)

    metricas = calcular_metricas(resultados)

    print("\n" + "=" * 60)
    print("RESULTADOS — Prototipo original entrenado con CICIDS2017 real")
    print("=" * 60)
    for campo, m in metricas.items():
        nombre = "REGLAS ADAPTATIVAS" if "reglas" in campo else "ISOLATION FOREST (ML)"
        print(f"\n{nombre}:")
        print(f"  Precisión: {m['precision']}  Recall: {m['recall']}  F1: {m['f1']}")
        print(f"  VP={m['verdaderos_positivos']} FN={m['falsos_negativos']} "
              f"FP={m['falsos_positivos']} VN={m['verdaderos_negativos']}")

    with open(args.salida, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "escenario", "total_eventos", "precision_reglas", "recall_reglas", "f1_reglas",
            "fp_reglas", "fn_reglas", "precision_ml", "recall_ml", "f1_ml", "fp_ml", "fn_ml",
        ])
        writer.writeheader()
        writer.writerow({
            "escenario": "CICIDS2017_traducido_a_eventos_login",
            "total_eventos": len(resultados),
            "precision_reglas": metricas["alerta_reglas"]["precision"],
            "recall_reglas": metricas["alerta_reglas"]["recall"],
            "f1_reglas": metricas["alerta_reglas"]["f1"],
            "fp_reglas": metricas["alerta_reglas"]["falsos_positivos"],
            "fn_reglas": metricas["alerta_reglas"]["falsos_negativos"],
            "precision_ml": metricas["alerta_ml"]["precision"],
            "recall_ml": metricas["alerta_ml"]["recall"],
            "f1_ml": metricas["alerta_ml"]["f1"],
            "fp_ml": metricas["alerta_ml"]["falsos_positivos"],
            "fn_ml": metricas["alerta_ml"]["falsos_negativos"],
        })

    print(f"\nResultados guardados en: {args.salida}")


if __name__ == "__main__":
    main()
