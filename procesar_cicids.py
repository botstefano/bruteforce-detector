"""
procesar_cicids.py
Carga el dataset CICIDS2017, filtra ataques de fuerza bruta, y evalúa
ambos detectores (reglas y ML) sobre datos reales de red.

USO:
    python procesar_cicids.py --carpeta /ruta/a/CICIDS2017

Genera: resultados_cicids.csv con métricas sobre datos reales etiquetados.

IMPORTANTE:
    - CICIDS2017 viene como tráfico de red (flujos con features de paquetes)
    - Hay que adaptar los detectores para interpretar esas features
    - No usamos los mismos 5 features que en tiempo real, sino features
      disponibles en CICIDS (duración, paquetes, bytes, etc.)
"""
import os
import sys
import glob
import argparse
import csv
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ============ DETECTOR DE REGLAS (adaptado para features de CICIDS) ============

class DetectorReglasICIDS:
    """
    Detector heurístico basado en características de flujo de red.
    Ataques de fuerza bruta típicamente muestran:
    - Muchos paquetes en poco tiempo (corta duración)
    - Bajo número de bytes por paquete (comandos SSH simples, intentos fallidos)
    - Patrones repetitivos (flujos muy similares desde/hacia la misma IP destino)
    """
    def __init__(self):
        self.thresholds = {
            "baja_duracion": 10,          # flujos < 10s son sospechosos
            "paquetes_por_segundo": 20,   # > 20 pkts/s es ráfaga
            "bytes_bajos": 5000,          # < 5KB en todo el flujo es típico de fallo SSH
        }

    def evaluar(self, fila):
        """
        fila: dict con features de CICIDS como 'Flow Duration',
        'Total Fwd Packets', 'Total Bwd Packets', 'Total Length of Fwd Packets', etc.
        """
        duracion = fila.get("Flow Duration", 1)
        if duracion == 0: duracion = 1
        
        paquetes_fwd = fila.get("Total Fwd Packets", 0)
        paquetes_bwd = fila.get("Total Bwd Packets", 0)
        paquetes_total = paquetes_fwd + paquetes_bwd
        
        bytes_fwd = fila.get("Total Length of Fwd Packets", 0)
        bytes_bwd = fila.get("Total Length of Bwd Packets", 0)
        bytes_total = bytes_fwd + bytes_bwd
        
        paquetes_por_seg = paquetes_total / duracion if duracion > 0 else 0

        alertas = 0
        razones = []

        # Regla 1: ráfaga de paquetes (ataque rápido)
        if paquetes_por_seg > self.thresholds["paquetes_por_segundo"]:
            alertas += 1
            razones.append(f"ráfaga: {paquetes_por_seg:.1f} pkts/s")

        # Regla 2: flujo muy corto con muchos paquetes (típico de intentos fallidos SSH)
        if duracion < self.thresholds["baja_duracion"] and paquetes_total > 5:
            alertas += 1
            razones.append(f"conexión corta con {paquetes_total} paquetes")

        # Regla 3: pocos bytes totales (intentos SSH fallidos = poco tráfico útil)
        if bytes_total < self.thresholds["bytes_bajos"] and paquetes_total > 3:
            alertas += 1
            razones.append(f"tráfico bajo ({bytes_total} bytes)")

        return {"alerta": alertas >= 2, "razon": " + ".join(razones) if razones else None}


# ============ DETECTOR ML (Isolation Forest sobre features reales) ============

def preparar_features_ml(df):
    """
    Selecciona y normaliza features de CICIDS para el modelo ML.
    Usa features que correlacionan con ataques de fuerza bruta.
    """
    features_seleccionadas = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Bwd Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
        "Flow IAT Mean",  # Inter-Arrival Time
    ]

    # Filtrar solo columnas que existen
    features = [f for f in features_seleccionadas if f in df.columns]
    
    # Rellenar NaN con 0
    X = df[features].fillna(0).values
    
    # Normalizar
    scaler = StandardScaler()
    return scaler.fit_transform(X), features, scaler


def entrenar_modelo_ml(df_benign):
    """Entrena un Isolation Forest con tráfico BENIGN como "normal"."""
    X_normal, features, scaler = preparar_features_ml(df_benign)
    modelo = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    modelo.fit(X_normal)
    return modelo, scaler, features


def evaluar_ml(modelo, scaler, X_raw):
    """Evalúa una muestra con el modelo entrenado."""
    X_norm = scaler.transform(X_raw.reshape(1, -1))
    pred = modelo.predict(X_norm)[0]
    score = modelo.decision_function(X_norm)[0]
    return {"alerta": pred == -1, "score": float(score)}


# ============ PROCESAMIENTO PRINCIPAL ============

def cargar_cicids(carpeta):
    """Carga todos los CSV de CICIDS2017 desde una carpeta."""
    archivos = glob.glob(os.path.join(carpeta, "*.csv"))
    if not archivos:
        raise FileNotFoundError(f"No se encontraron archivos CSV en {carpeta}")
    
    print(f"Encontrados {len(archivos)} archivos CSV en {carpeta}")
    
    dfs = []
    for archivo in archivos:
        print(f"  Cargando {os.path.basename(archivo)}...", end=" ", flush=True)
        try:
            df = pd.read_csv(archivo)
            # CICIDS a veces usa espacios en los nombres de columnas
            df.columns = df.columns.str.strip()
            dfs.append(df)
            print(f"OK ({len(df)} filas)")
        except Exception as e:
            print(f"ERROR: {e}")
    
    return pd.concat(dfs, ignore_index=True) if dfs else None


def procesar_dataset(df):
    """
    Filtra y etiqueta el dataset.
    Retorna (datos_benign, datos_ataque, labels_verdad).
    """
    # Normalizar etiquetas (CICIDS2017 usa diferentes formatos según fuente)
    if 'Label' in df.columns:
        etiqueta_col = 'Label'
    elif 'label' in df.columns:
        etiqueta_col = 'label'
    else:
        raise ValueError("No se encontró columna 'Label' o 'label' en el dataset")

    df[etiqueta_col] = df[etiqueta_col].str.strip().str.lower()

    # Separar BENIGN de ataques de fuerza bruta
    df_benign = df[df[etiqueta_col] == 'benign'].copy()
    df_ataques = df[df[etiqueta_col].str.contains('bruteforce|ssh-bruteforce|ftp-bruteforce', 
                                                     case=False, na=False)].copy()

    print(f"\nEstad√≠stica del dataset:")
    print(f"  BENIGN: {len(df_benign)} flujos")
    print(f"  Ataques de fuerza bruta: {len(df_ataques)} flujos")
    print(f"  Total: {len(df)} flujos")

    if len(df_ataques) == 0:
        print("ADVERTENCIA: No se encontraron flujos etiquetados como ataque de fuerza bruta")
    if len(df_benign) == 0:
        print("ADVERTENCIA: No se encontr√≥ tráfico BENIGN para entrenar el modelo")

    return df_benign, df_ataques, etiqueta_col


def evaluar_detectores(df_benign, df_ataques, etiqueta_col):
    """
    Entrena modelos con BENIGN y evalúa sobre BENIGN + ataques.
    Retorna lista de dicts con resultados por flujo.
    """
    print("\nEntrenando Isolation Forest con tráfico BENIGN...", end=" ", flush=True)
    modelo_ml, scaler, features = entrenar_modelo_ml(df_benign)
    print("OK")

    detector_reglas = DetectorReglasICIDS()

    resultados = []
    
    # Evaluar tráfico BENIGN (debería pasar, pocos falsos positivos)
    print(f"Evaluando {len(df_benign)} flujos BENIGN...", end=" ", flush=True)
    for idx, (_, fila) in enumerate(df_benign.iterrows()):
        if idx % 1000 == 0: print(".", end="", flush=True)
        
        res_reglas = detector_reglas.evaluar(fila)
        
        X_raw = np.array([fila.get(f, 0) for f in features])
        res_ml = evaluar_ml(modelo_ml, scaler, X_raw)
        
        resultados.append({
            "es_ataque_real": False,
            "alerta_reglas": res_reglas["alerta"],
            "alerta_ml": res_ml["alerta"],
            "score_ml": res_ml["score"],
        })
    print(" OK")

    # Evaluar ataques (debería alertar, pocos falsos negativos)
    print(f"Evaluando {len(df_ataques)} flujos de ATAQUE...", end=" ", flush=True)
    for idx, (_, fila) in enumerate(df_ataques.iterrows()):
        if idx % 1000 == 0: print(".", end="", flush=True)
        
        res_reglas = detector_reglas.evaluar(fila)
        
        X_raw = np.array([fila.get(f, 0) for f in features])
        res_ml = evaluar_ml(modelo_ml, scaler, X_raw)
        
        resultados.append({
            "es_ataque_real": True,
            "alerta_reglas": res_reglas["alerta"],
            "alerta_ml": res_ml["alerta"],
            "score_ml": res_ml["score"],
        })
    print(" OK")

    return resultados


def calcular_metricas(resultados):
    """Calcula precisión, recall, F1 para ambos detectores."""
    metricas = {}
    
    for detector in ["alerta_reglas", "alerta_ml"]:
        vp = sum(1 for r in resultados if r["es_ataque_real"] and r[detector])
        fn = sum(1 for r in resultados if r["es_ataque_real"] and not r[detector])
        fp = sum(1 for r in resultados if not r["es_ataque_real"] and r[detector])
        vn = sum(1 for r in resultados if not r["es_ataque_real"] and not r[detector])

        precision = vp / (vp + fp) if (vp + fp) > 0 else 0
        recall = vp / (vp + fn) if (vp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        metricas[detector] = {
            "verdaderos_positivos": vp,
            "falsos_negativos": fn,
            "falsos_positivos": fp,
            "verdaderos_negativos": vn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        }
    
    return metricas


def main():
    parser = argparse.ArgumentParser(
        description="Procesa CICIDS2017 y evalúa detectores de fuerza bruta"
    )
    parser.add_argument("--carpeta", required=True,
                        help="Ruta a la carpeta con CSVs de CICIDS2017")
    parser.add_argument("--salida", default="resultados_cicids.csv",
                        help="Archivo CSV de salida (default: resultados_cicids.csv)")
    args = parser.parse_args()

    print(f"Cargando CICIDS2017 desde {args.carpeta}...")
    df = cargar_cicids(args.carpeta)
    if df is None or len(df) == 0:
        print("ERROR: No se pudo cargar el dataset")
        return

    print(f"\nProcesando {len(df)} flujos...")
    df_benign, df_ataques, etiqueta_col = procesar_dataset(df)

    print("\nEvaluando detectores...")
    resultados = evaluar_detectores(df_benign, df_ataques, etiqueta_col)

    print("\nCalculando métricas...")
    metricas = calcular_metricas(resultados)

    print("\n" + "="*60)
    print("RESULTADOS — Evaluación sobre CICIDS2017 (datos reales)")
    print("="*60)
    for detector, m in metricas.items():
        nombre = "REGLAS ADAPTATIVAS" if "reglas" in detector else "ISOLATION FOREST (ML)"
        print(f"\n{nombre}:")
        print(f"  Precisión: {m['precision']}")
        print(f"  Recall:    {m['recall']}")
        print(f"  F1:        {m['f1']}")
        print(f"  VP={m['verdaderos_positivos']} FN={m['falsos_negativos']} "
              f"FP={m['falsos_positivos']} VN={m['verdaderos_negativos']}")

    # Guardar en CSV (formato compatible con análisis posterior)
    with open(args.salida, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "escenario", "precision_reglas", "recall_reglas", "f1_reglas",
            "fp_reglas", "fn_reglas", "precision_ml", "recall_ml", "f1_ml",
            "fp_ml", "fn_ml", "total_flujos"
        ])
        writer.writeheader()
        writer.writerow({
            "escenario": "CICIDS2017_brute_force",
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
            "total_flujos": len(resultados),
        })

    print(f"\n✓ Resultados guardados en: {args.salida}")


if __name__ == "__main__":
    main()
