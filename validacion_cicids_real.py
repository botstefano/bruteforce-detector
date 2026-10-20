#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validacion_cicids_real.py
=============================================================================
VALIDACIÓN CIENTÍFICA DE CENTINELA CON FLUJOS REALES DE CICIDS2017 (UNB/CIC)
=============================================================================

Este script ejecuta la validación rigurosa sin fuga temporal de información
(zero-leakage temporal split) sobre los archivos CSV oficiales de CICIDS2017
("TrafficLabelling" con Source IP, Destination IP, Timestamp y Label).

Detectores evaluados:
  1. Reglas heurísticas WAF (ventana 60s, flujos a mismo puerto destino)
  2. Isolation Forest (lógica Centinela)
  3. One-Class SVM (lógica Centinela)
  4. Local Outlier Factor / LOF (lógica Centinela)
  5. Ensamble Centinela (consenso multi-modelo)
  6. Random Forest Supervisado (referencia empírica superior)

Archivos requeridos en --data-dir:
  - Monday-WorkingHours.pcap_ISCX.csv (Solo benigno -> ENTRENAMIENTO)
  - Tuesday-WorkingHours.pcap_ISCX.csv (Benigno + FTP/SSH-Patator -> 30% VAL / 70% TEST 1)
  - Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv (Benigno + Web Brute Force -> TEST 2)

Salidas generadas:
  - resultados_cicids_real.json (consumible por el panel Centinela)
  - resultados_cicids_real.csv (tabular plano para análisis en R/Pandas/Excel)
  - reporte_cicids_real.md (tablas académicas listas para publicación)
  - reproducibilidad_cicids.json (SHA-256, conteos exactos, versiones y semillas)

Uso:
  python3 validacion_cicids_real.py --data-dir /ruta/a/csvs/ [opciones]
"""

import os
import sys
import time
import json
import hashlib
import argparse
import platform
from collections import deque
from typing import Dict, List, Tuple, Any, Optional

# Verificación de dependencias de terceros
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        precision_score, recall_score, f1_score, accuracy_score,
        roc_auc_score, average_precision_score, confusion_matrix,
        roc_curve, precision_recall_curve
    )
    import sklearn
except ImportError as e:
    print(f"\n[ERROR CRÍTICO] Dependencia faltante: {e}")
    print("Por favor instala los paquetes requeridos ejecutando:")
    print("    pip install numpy pandas scikit-learn scipy\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# CONSTANTES Y CONFIGURACIÓN CIENTÍFICA
# ---------------------------------------------------------------------------
ORIGEN_DATOS = "CICIDS2017 real (UNB/CIC)"
URL_OFICIAL_CIC = "https://www.unb.ca/cic/datasets/ids-2017.html"

NOMBRES_ARCHIVOS_ESPERADOS = {
    "monday": ["Monday-WorkingHours.pcap_ISCX.csv", "Monday-WorkingHours.csv"],
    "tuesday": ["Tuesday-WorkingHours.pcap_ISCX.csv", "Tuesday-WorkingHours.csv"],
    "thursday": ["Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "Thursday-WorkingHours-Morning-WebAttacks.csv"]
}

COLUMNAS_FLUJO_BASE = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Average Packet Size"
]

COLUMNAS_VENTANA_60S = [
    "src_flows_same_dst_port_60s",
    "src_interflow_mean_60s",
    "src_interflow_std_60s"
]

SEMILLAS_POR_DEFECTO = [42, 101, 2023, 777, 999, 1234, 54321, 1337, 8888, 2026]


# ---------------------------------------------------------------------------
# UTILIDADES DE INTEGRIDAD Y SHA-256
# ---------------------------------------------------------------------------
def calcular_sha256(ruta_archivo: str, tamano_bloque: int = 1024 * 1024) -> str:
    """Calcula el hash SHA-256 de un archivo en bloques sin sobrecargar la memoria RAM."""
    sha256 = hashlib.sha256()
    with open(ruta_archivo, "rb") as f:
        while True:
            bloque = f.read(tamano_bloque)
            if not bloque:
                break
            sha256.update(bloque)
    return sha256.hexdigest()


def buscar_archivo_en_directorio(data_dir: str, alias: str) -> Optional[str]:
    """Busca el archivo correspondiente al alias de forma exacta o por coincidencia insensible a mayúsculas."""
    posibles = NOMBRES_ARCHIVOS_ESPERADOS[alias]
    archivos_reales = os.listdir(data_dir)
    
    # 1. Búsqueda exacta
    for nombre in posibles:
        if nombre in archivos_reales:
            return os.path.join(data_dir, nombre)
            
    # 2. Búsqueda insensible a mayúsculas
    archivos_lower = {a.lower(): a for a in archivos_reales}
    for nombre in posibles:
        if nombre.lower() in archivos_lower:
            return os.path.join(data_dir, archivos_lower[nombre.lower()])
            
    # 3. Búsqueda por subcadena
    clave = "monday" if alias == "monday" else ("tuesday" if alias == "tuesday" else "thursday")
    for a in archivos_reales:
        if clave in a.lower() and a.lower().endswith(".csv"):
            if alias == "thursday" and "web" not in a.lower():
                continue
            return os.path.join(data_dir, a)
            
    return None


# ---------------------------------------------------------------------------
# LIMPIEZA DE DATOS ESTRICTA (SEGÚN ESPECIFICACIÓN)
# ---------------------------------------------------------------------------
def limpiar_dataframe(df: pd.DataFrame, nombre_etapa: str) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Elimina espacios en los nombres de columna, filas con NaN/inf y duplicados exactos.
    Retorna el DataFrame limpio y un diccionario detallado con los conteos antes y después.
    """
    conteo_inicial = len(df)
    
    # 1. Eliminar espacios en los nombres de columna
    df.columns = df.columns.str.strip()
    
    # 2. Reemplazar inf y -inf por NaN
    df_reemplazado = df.replace([np.inf, -np.inf], np.nan)
    
    # 3. Eliminar filas con NaN
    df_sin_nan = df_reemplazado.dropna()
    conteo_tras_nan = len(df_sin_nan)
    filas_nan_inf = conteo_inicial - conteo_tras_nan
    
    # 4. Eliminar duplicados exactos
    df_limpio = df_sin_nan.drop_duplicates()
    conteo_final = len(df_limpio)
    filas_duplicadas = conteo_tras_nan - conteo_final
    
    # Conteos por etiqueta
    conteos_etiquetas = df_limpio["Label"].value_counts().to_dict() if "Label" in df_limpio.columns else {}
    
    registro_limpieza = {
        "etapa": nombre_etapa,
        "filas_originales": conteo_inicial,
        "filas_nan_o_inf_eliminadas": filas_nan_inf,
        "filas_tras_nan_inf": conteo_tras_nan,
        "filas_duplicadas_eliminadas": filas_duplicadas,
        "filas_finales_limpias": conteo_final,
        "conteo_por_etiqueta": {str(k): int(v) for k, v in conteos_etiquetas.items()}
    }
    
    return df_limpio, registro_limpieza


# ---------------------------------------------------------------------------
# INGENIERÍA DE CARACTERÍSTICAS TEMPORALES EN VENTANAS DE 60 SEGUNDOS
# ---------------------------------------------------------------------------
def calcular_features_ventana_60s(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calcula por Source IP en ventanas deslizantes de 60 segundos:
      - número de flujos hacia el mismo Destination Port
      - media del tiempo entre flujos
      - desviación estándar del tiempo entre flujos
      
    Implementación optimizada con deques temporales por clave (Source IP, Destination Port).
    """
    # Asegurar orden temporal estricto
    df = df.copy()
    if not np.issubdtype(df["timestamp_dt"].dtype, np.datetime64):
        df["timestamp_dt"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    
    df = df.sort_values(by="timestamp_dt").reset_index(drop=True)
    timestamps_sec = df["timestamp_dt"].astype("int64") // 10**9
    
    n = len(df)
    flows_same_port_arr = np.zeros(n, dtype=np.int32)
    interflow_mean_arr = np.zeros(n, dtype=np.float32)
    interflow_std_arr = np.zeros(n, dtype=np.float32)
    
    # Estructuras para ventanas deslizantes de 60s
    # cola por (src_ip, dst_port) para conteo de flujos al mismo puerto
    colas_ip_puerto: Dict[Tuple[str, int], deque] = {}
    # cola por src_ip para tiempos entre flujos generales de la IP
    colas_ip_tiempos: Dict[str, deque] = {}
    
    src_ips = df["Source IP"].astype(str).values
    dst_ports = df["Destination Port"].astype(int).values
    ts_vals = timestamps_sec.values
    
    VENTANA = 60.0 # 60 segundos
    
    for i in range(n):
        ahora = ts_vals[i]
        sip = src_ips[i]
        dport = dst_ports[i]
        clave_puerto = (sip, dport)
        
        # 1. Ventana para flujos al mismo puerto destino
        if clave_puerto not in colas_ip_puerto:
            colas_ip_puerto[clave_puerto] = deque()
        q_puerto = colas_ip_puerto[clave_puerto]
        limite = ahora - VENTANA
        while q_puerto and q_puerto[0] < limite:
            q_puerto.popleft()
        # Se agrega el flujo actual
        q_puerto.append(ahora)
        flows_same_port_arr[i] = len(q_puerto)
        
        # 2. Ventana para media y std de intervalos de inter-llegada por Source IP
        if sip not in colas_ip_tiempos:
            colas_ip_tiempos[sip] = deque()
        q_ip = colas_ip_tiempos[sip]
        while q_ip and q_ip[0] < limite:
            q_ip.popleft()
        q_ip.append(ahora)
        
        tam_ip = len(q_ip)
        if tam_ip >= 2:
            # Calcular diferencias entre tiempos consecutivos
            diffs = [q_ip[j] - q_ip[j - 1] for j in range(1, tam_ip)]
            m = sum(diffs) / len(diffs)
            interflow_mean_arr[i] = m
            if len(diffs) >= 2:
                var = sum((d - m) ** 2 for d in diffs) / len(diffs)
                interflow_std_arr[i] = np.sqrt(var)
            else:
                interflow_std_arr[i] = 0.0
        else:
            interflow_mean_arr[i] = 60.0 # Valor por defecto sin historial previo
            interflow_std_arr[i] = 0.0
            
    df["src_flows_same_dst_port_60s"] = flows_same_port_arr
    df["src_interflow_mean_60s"] = interflow_mean_arr
    df["src_interflow_std_60s"] = interflow_std_arr
    
    return df


# ---------------------------------------------------------------------------
# VECTORIZACIÓN Y MAPEO DE CARACTERÍSTICAS
# ---------------------------------------------------------------------------
def preparar_matriz_features(df: pd.DataFrame, columnas_requeridas: List[str]) -> np.ndarray:
    """Extrae las columnas numéricas de features aplicando transformaciones robustas para estabilidad numérica."""
    # Verificar nombres equivalentes en CICIDS2017 si difieren sutilmente
    mapeo_columnas = {
        "Flow Duration": ["Flow Duration"],
        "Total Fwd Packets": ["Total Fwd Packets", "Tot Fwd Pkts"],
        "Total Backward Packets": ["Total Backward Packets", "Tot Bwd Pkts"],
        "Total Length of Fwd Packets": ["Total Length of Fwd Packets", "TotLen Fwd Pkts"],
        "Flow Bytes/s": ["Flow Bytes/s", "Flow Byts/s"],
        "Flow Packets/s": ["Flow Packets/s", "Flow Pkts/s"],
        "Flow IAT Mean": ["Flow IAT Mean"],
        "Flow IAT Std": ["Flow IAT Std"],
        "Average Packet Size": ["Average Packet Size", "Avg Pkt Size", "Packet Length Mean"],
        "src_flows_same_dst_port_60s": ["src_flows_same_dst_port_60s"],
        "src_interflow_mean_60s": ["src_interflow_mean_60s"],
        "src_interflow_std_60s": ["src_interflow_std_60s"]
    }
    
    columnas_seleccionadas = []
    for col in columnas_requeridas:
        encontrada = None
        for candidata in mapeo_columnas.get(col, [col]):
            if candidata in df.columns:
                encontrada = candidata
                break
        if encontrada is not None:
            columnas_seleccionadas.append(encontrada)
        else:
            raise KeyError(f"No se encontró la columna requerida '{col}' en el dataset.")
            
    matriz = df[columnas_seleccionadas].values.astype(np.float64)
    # Limpieza de seguridad para evitar NaN o inf residuales
    matriz = np.nan_to_num(matriz, nan=0.0, posinf=1e9, neginf=-1e9)
    return matriz


# ---------------------------------------------------------------------------
# DETECTOR HEURÍSTICO WAF ADAPTADO A FLUJOS
# ---------------------------------------------------------------------------
class ReglasWafFlujo:
    """
    Reglas heurísticas WAF adaptadas a flujos:
    Alerta si una Source IP supera N flujos hacia el mismo Destination Port en una ventana de 60 s.
    El parámetro N se calibra en el tramo de validación (Tuesday 30%) y se fija.
    """
    def __init__(self, n_umbral: int = 10):
        self.n_umbral = n_umbral
        
    def calibrar(self, flows_val: np.ndarray, y_val: np.ndarray, criterio: str = "max_f1") -> Tuple[int, Dict[str, Any]]:
        """
        Barre candidatos para N en el tramo de validación.
        Criterios:
          - 'max_f1': Maximiza F1-Score en validación.
          - 'fpr_1pct': Maximiza Recall garantizando FPR <= 1.0%.
        """
        candidatos_n = list(range(2, 60))
        mejor_n = 5
        mejor_f1 = -1.0
        mejor_recall_fpr1 = -1.0
        n_fpr1 = 15
        
        registro_sweep = []
        
        for n_cand in candidatos_n:
            y_pred = (flows_val >= n_cand).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_val, y_pred, labels=[0, 1]).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            
            registro_sweep.append({
                "N": n_cand,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4)
            })
            
            if f1 > mejor_f1:
                mejor_f1 = f1
                mejor_n = n_cand
                
            if fpr <= 0.01 and rec > mejor_recall_fpr1:
                mejor_recall_fpr1 = rec
                n_fpr1 = n_cand
                
        if criterio == "fpr_1pct":
            self.n_umbral = n_fpr1
        else:
            self.n_umbral = mejor_n
            
        return self.n_umbral, {
            "criterio": criterio,
            "n_optimo_f1": mejor_n,
            "f1_en_val": mejor_f1,
            "n_optimo_fpr1": n_fpr1,
            "sweep": registro_sweep
        }
        
    def predecir(self, flows_arr: np.ndarray) -> np.ndarray:
        return (flows_arr >= self.n_umbral).astype(int)
        
    def score_anomalia(self, flows_arr: np.ndarray) -> np.ndarray:
        # Score escalado sigmoide para consistencia con ROC/AUC
        return 1.0 / (1.0 + np.exp(-0.2 * (flows_arr - self.n_umbral)))


# ---------------------------------------------------------------------------
# SUITE DE MACHINE LEARNING CENTINELA (ISOLATION FOREST, OC-SVM, LOF, ENSAMBLE)
# ---------------------------------------------------------------------------
class CentinelaMLSuite:
    """
    Implementación fiel de los detectores de anomalías de Centinela:
      - Isolation Forest (árboles aleatorios)
      - One-Class SVM (frontera de distancia estandarizada / RBF)
      - Local Outlier Factor (densidad local k-NN)
      - Ensamble Centinela (consenso ponderado y mayoritario)
      - Random Forest Supervisado (referencia empírica)
    """
    def __init__(self, seed: int = 42, max_samples_train: int = 40000):
        self.seed = seed
        self.max_samples_train = max_samples_train
        self.scaler = StandardScaler()
        self.iforest = IsolationForest(
            n_estimators=100,
            max_samples=128,
            contamination=0.05,
            random_state=seed,
            n_jobs=-1
        )
        self.ocsvm = OneClassSVM(
            kernel='rbf',
            gamma='scale',
            nu=0.05
        )
        self.lof = LocalOutlierFactor(
            n_neighbors=15,
            novelty=True,
            n_jobs=-1
        )
        self.rf_supervisado = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            random_state=seed,
            n_jobs=-1
        )
        
        # Umbrales calibrados en el tramo de validación
        self.umbrales_calibrados_f1: Dict[str, float] = {}
        self.umbrales_calibrados_fpr1: Dict[str, float] = {}
        self.ajustado = False
        
    def fit_unsupervised(self, X_train_benign: np.ndarray):
        """Entrena los detectores no supervisados EXCLUSIVAMENTE con tráfico benigno (Monday)."""
        # Si el conjunto benigno es gigantesco (ej. > 400k), se submuestrea para entrenamiento de modelos O(N^2)
        if len(X_train_benign) > self.max_samples_train:
            np.random.seed(self.seed)
            idx_sub = np.random.choice(len(X_train_benign), self.max_samples_train, replace=False)
            X_sub = X_train_benign[idx_sub]
        else:
            X_sub = X_train_benign
            
        # 1. Ajustar Scaler solo con tráfico benigno de Monday
        self.scaler.fit(X_sub)
        X_scaled = self.scaler.transform(X_sub)
        
        # 2. Entrenar Isolation Forest
        self.iforest.fit(X_scaled)
        
        # 3. Entrenar One-Class SVM (en una muestra representativa de 10,000 para eficiencia)
        idx_svm = np.random.choice(len(X_scaled), min(len(X_scaled), 10000), replace=False)
        self.ocsvm.fit(X_scaled[idx_svm])
        
        # 4. Entrenar LOF en modo novedad
        idx_lof = np.random.choice(len(X_scaled), min(len(X_scaled), 8000), replace=False)
        self.lof.fit(X_scaled[idx_lof])
        
        self.ajustado = True

    def fit_supervised_reference(self, X_ref: np.ndarray, y_ref: np.ndarray):
        """Entrena un Random Forest como referencia superior con datos de validación / referencia."""
        X_scaled = self.scaler.transform(X_ref)
        self.rf_supervisado.fit(X_scaled, y_ref)

    def obtener_scores(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """Calcula scores de anomalía normalizados en [0, 1] donde mayor = más anómalo."""
        X_scaled = self.scaler.transform(X)
        
        # 1. Isolation Forest score
        # decision_function: negativo para anomalías, positivo para normales
        raw_if = -self.iforest.score_samples(X_scaled) # a mayor valor, mayor anomalía
        score_if = 1.0 / (1.0 + np.exp(-10.0 * (raw_if - np.median(raw_if))))
        
        # 2. One-Class SVM score
        raw_svm = -self.ocsvm.decision_function(X_scaled)
        score_svm = 1.0 / (1.0 + np.exp(-raw_svm))
        
        # 3. LOF score
        raw_lof = -self.lof.decision_function(X_scaled)
        score_lof = 1.0 / (1.0 + np.exp(-raw_lof))
        
        # 4. Ensamble Centinela: promedio de scores normalizados de los 3 modelos no supervisados
        score_ensamble = (score_if + score_svm + score_lof) / 3.0
        
        # 5. Random Forest Supervisado (probabilidad de clase ataque)
        score_rf = self.rf_supervisado.predict_proba(X_scaled)[:, 1] if hasattr(self.rf_supervisado, "classes_") and len(self.rf_supervisado.classes_) > 1 else np.zeros(len(X))
        
        return {
            "isolation_forest": score_if,
            "one_class_svm": score_svm,
            "lof": score_lof,
            "ensamble": score_ensamble,
            "rf_supervisado": score_rf
        }

    def calibrar_umbrales(self, scores_val: Dict[str, np.ndarray], y_val: np.ndarray) -> Dict[str, Any]:
        """
        Calibra los umbrales de decisión estrictamente sobre el tramo de validación (Tuesday 30%).
        Guarda tanto la calibración por Max F1 como con FPR objetivo <= 1.0%.
        """
        registro_calibracion = {}
        candidatos_umbrales = np.linspace(0.01, 0.99, 100)
        
        for modelo, scores in scores_val.items():
            mejor_f1 = -1.0
            opt_th_f1 = 0.5
            mejor_rec_fpr1 = -1.0
            opt_th_fpr1 = 0.8
            
            for th in candidatos_umbrales:
                pred = (scores >= th).astype(int)
                tn, fp, fn, tp = confusion_matrix(y_val, pred, labels=[0, 1]).ravel()
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
                prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
                rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
                
                if f1 > mejor_f1:
                    mejor_f1 = f1
                    opt_th_f1 = th
                    
                if fpr <= 0.01 and rec > mejor_rec_fpr1:
                    mejor_rec_fpr1 = rec
                    opt_th_fpr1 = th
                    
            self.umbrales_calibrados_f1[modelo] = float(opt_th_f1)
            self.umbrales_calibrados_fpr1[modelo] = float(opt_th_fpr1)
            
            registro_calibracion[modelo] = {
                "umbral_max_f1": float(opt_th_f1),
                "f1_val": float(mejor_f1),
                "umbral_fpr_1pct": float(opt_th_fpr1),
                "recall_fpr_1pct_val": float(mejor_rec_fpr1)
            }
            
        return registro_calibracion


# ---------------------------------------------------------------------------
# CÁLCULO DE MÉTRICAS Y BOOTSTRAP DE INTERVALOS DE CONFIANZA (95%)
# ---------------------------------------------------------------------------
def evaluar_metricas(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_scores: np.ndarray,
    latencia_ms_total: float
) -> Dict[str, Any]:
    """Calcula el conjunto completo de métricas científicas para un detector dado."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    total = len(y_true)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    especificidad = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    
    # AUC-ROC y AUC-PR
    try:
        auc_roc = float(roc_auc_score(y_true, y_scores))
    except Exception:
        auc_roc = 0.5
        
    try:
        auc_pr = float(average_precision_score(y_true, y_scores))
    except Exception:
        auc_pr = 0.0
        
    latencia_por_flujo_ms = latencia_ms_total / total if total > 0 else 0.0
    
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fpr),
        "especificidad": float(especificidad),
        "accuracy": float(accuracy),
        "auc_roc": float(auc_roc),
        "auc_pr": float(auc_pr),
        "VP": int(tp),
        "FP": int(fp),
        "FN": int(fn),
        "VN": int(tn),
        "latencia_ms_por_flujo": float(latencia_por_flujo_ms)
    }


def calcular_bootstrap_ci_95(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    n_bootstrap: int = 1000,
    seed: int = 42
) -> Dict[str, Tuple[float, float]]:
    """Calcula intervalos de confianza al 95% no paramétricos vía bootstrap para Precision, Recall, F1, FPR."""
    rng = np.random.default_rng(seed)
    n = len(y_true)
    
    f1_boot = np.empty(n_bootstrap)
    rec_boot = np.empty(n_bootstrap)
    prec_boot = np.empty(n_bootstrap)
    fpr_boot = np.empty(n_bootstrap)
    
    for b in range(n_bootstrap):
        idx = rng.choice(n, size=n, replace=True)
        yt = y_true[idx]
        yp = y_pred[idx]
        
        tn, fp, fn, tp = confusion_matrix(yt, yp, labels=[0, 1]).ravel()
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f = 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        prec_boot[b] = p
        rec_boot[b] = r
        f1_boot[b] = f
        fpr_boot[b] = fp_rate
        
    ci_95 = {
        "precision": (float(np.percentile(prec_boot, 2.5)), float(np.percentile(prec_boot, 97.5))),
        "recall": (float(np.percentile(rec_boot, 2.5)), float(np.percentile(rec_boot, 97.5))),
        "f1": (float(np.percentile(f1_boot, 2.5)), float(np.percentile(f1_boot, 97.5))),
        "fpr": (float(np.percentile(fpr_boot, 2.5)), float(np.percentile(fpr_boot, 97.5)))
    }
    return ci_95


# ---------------------------------------------------------------------------
# PIPELINE COMPLETO DE VALIDACIÓN
# ---------------------------------------------------------------------------
def ejecutar_validacion_completa(args):
    print("=" * 80)
    print(f" CENTINELA — EXPERIMENTO DE VALIDACIÓN CON DATOS REALES DE {ORIGEN_DATOS}")
    print("=" * 80)
    
    data_dir = os.path.abspath(args.data_dir)
    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. VERIFICACIÓN ESTRICTA DE ARCHIVOS (REGLA: "Si falta un archivo, detente y avísame")
    rutas_archivos = {}
    archivos_faltantes = []
    
    for clave in ["monday", "tuesday", "thursday"]:
        encontrado = buscar_archivo_en_directorio(data_dir, clave)
        if encontrado and os.path.isfile(encontrado):
            rutas_archivos[clave] = encontrado
        else:
            archivos_faltantes.append(clave)
            
    if archivos_faltantes:
        print("\n" + "!" * 80)
        print(" [DETENCIÓN ESTRICTA] FALTAN ARCHIVOS OFICIALES DE CICIDS2017")
        print("!" * 80)
        print(f"Directorio consultado: {data_dir}\n")
        print("Los siguientes archivos no fueron encontrados:")
        for falta in archivos_faltantes:
            esperados = NOMBRES_ARCHIVOS_ESPERADOS[falta]
            print(f"  ❌ {falta.upper()}: se esperaba alguno de {esperados}")
            
        print("\nInstrucciones para resolver:")
        print(f"  1. Descarga el dataset oficial desde: {URL_OFICIAL_CIC}")
        print("  2. Selecciona la versión 'GeneratedLabelledFlows' o 'TrafficLabelling_CSV'")
        print("  3. Coloca los archivos descomprimidos en una carpeta (ej. /datos/cicids2017/)")
        print("  4. Re-ejecuta este script especificando la carpeta correcta:")
        print(f"     python3 validacion_cicids_real.py --data-dir /ruta/a/la/carpeta/\n")
        print("De acuerdo con las reglas estrictas, ningún cálculo ficticio será realizado.")
        sys.exit(1)
        
    print("\n[OK] Los 3 archivos oficiales fueron localizados:")
    for k, v in rutas_archivos.items():
        peso_mb = os.path.getsize(v) / (1024 * 1024)
        print(f"  ✔ {k.upper():8s} -> {os.path.basename(v)} ({peso_mb:.1f} MB)")
        
    # 2. CÁLCULO DE INTEGRIDAD SHA-256
    print("\nCalculando hashes de integridad SHA-256 de los CSV reales...")
    hashes_sha256 = {}
    for k, v in rutas_archivos.items():
        t0 = time.time()
        h = calcular_sha256(v)
        hashes_sha256[k] = {
            "archivo": os.path.basename(v),
            "ruta_completa": v,
            "tamano_bytes": os.path.getsize(v),
            "sha256": h,
            "tiempo_calculo_seg": round(time.time() - t0, 2)
        }
        print(f"  [{k}] SHA-256: {h}")
        
    # 3. CARGA Y LIMPIEZA RIGUROSA
    print("\n" + "-" * 80)
    print(" CARGA Y LIMPIEZA DE DATOS (Drop NaN/Inf, Drop Duplicados, Strip Columns)")
    print("-" * 80)
    
    registros_limpieza = {}
    
    # Carga Monday
    print("Cargando Monday (Entrenamiento Benigno)...")
    df_mon_raw = pd.read_csv(rutas_archivos["monday"], encoding="utf-8", low_memory=False)
    df_mon, reg_mon = limpiar_dataframe(df_mon_raw, "Monday-WorkingHours")
    registros_limpieza["monday"] = reg_mon
    del df_mon_raw
    print(f"  Monday: {reg_mon['filas_originales']} -> {reg_mon['filas_finales_limpias']} filas limpias.")
    
    # Carga Tuesday
    print("Cargando Tuesday (Calibración + Prueba 1: FTP/SSH-Patator)...")
    df_tue_raw = pd.read_csv(rutas_archivos["tuesday"], encoding="utf-8", low_memory=False)
    df_tue, reg_tue = limpiar_dataframe(df_tue_raw, "Tuesday-WorkingHours")
    registros_limpieza["tuesday"] = reg_tue
    del df_tue_raw
    print(f"  Tuesday: {reg_tue['filas_originales']} -> {reg_tue['filas_finales_limpias']} filas limpias.")
    
    # Carga Thursday Morning
    print("Cargando Thursday Morning (Prueba 2: Web Attack Brute Force)...")
    df_thu_raw = pd.read_csv(rutas_archivos["thursday"], encoding="utf-8", low_memory=False)
    df_thu_clean, reg_thu = limpiar_dataframe(df_thu_raw, "Thursday-WorkingHours-Morning-WebAttacks")
    del df_thu_raw
    
    # Filtrado estricto en Thursday: Ignorar XSS y SQL Injection de acuerdo a la instrucción
    conteos_previos_thu = df_thu_clean["Label"].value_counts().to_dict()
    filas_xss_descartadas = sum(v for k, v in conteos_previos_thu.items() if "xss" in str(k).lower())
    filas_sqli_descartadas = sum(v for k, v in conteos_previos_thu.items() if "sql" in str(k).lower())
    
    # Filtro: Mantener solo BENIGN y Web Attack Brute Force
    mascara_web_bruteforce = (
        (df_thu_clean["Label"].str.strip().str.upper() == "BENIGN") |
        (df_thu_clean["Label"].str.contains("Brute Force", case=False, na=False))
    )
    df_thu = df_thu_clean[mascara_web_bruteforce].copy()
    conteo_post_filtro_thu = len(df_thu)
    
    reg_thu["filas_xss_excluidas_documentadas"] = int(filas_xss_descartadas)
    reg_thu["filas_sqli_excluidas_documentadas"] = int(filas_sqli_descartadas)
    reg_thu["filas_finales_evaluacion_prueba2"] = int(conteo_post_filtro_thu)
    registros_limpieza["thursday"] = reg_thu
    print(f"  Thursday: {reg_thu['filas_originales']} -> {conteo_post_filtro_thu} filas (excluidas {filas_xss_descartadas} XSS y {filas_sqli_descartadas} SQLi).")
    
    # 4. INGENIERÍA DE CARACTERÍSTICAS TEMPORALES (VENTANAS DE 60S POR SOURCE IP)
    print("\n" + "-" * 80)
    print(" INGENIERÍA DE CARACTERÍSTICAS (Ventana 60s por Source IP: Flujos a mismo puerto y Delays)")
    print("-" * 80)
    
    print("Calculando ventanas temporales de 60s en Monday...")
    df_mon = calcular_features_ventana_60s(df_mon)
    print("Calculando ventanas temporales de 60s en Tuesday...")
    df_tue = calcular_features_ventana_60s(df_tue)
    print("Calculando ventanas temporales de 60s en Thursday...")
    df_thu = calcular_features_ventana_60s(df_thu)
    
    columnas_requeridas_modelo = COLUMNAS_FLUJO_BASE + COLUMNAS_VENTANA_60S
    
    # 5. PARTICIÓN SIN FUGA DE INFORMACIÓN (ZERO-LEAKAGE TEMPORAL SPLIT)
    print("\n" + "-" * 80)
    print(" PARTICIÓN TEMPORAL SIN FUGA DE INFORMACIÓN")
    print("-" * 80)
    # Monday: Solo tráfico benigno
    mascara_benigno_mon = df_mon["Label"].str.strip().str.upper() == "BENIGN"
    df_train_monday = df_mon[mascara_benigno_mon]
    print(f"  Entrenamiento: 100% Benigno de Monday ({len(df_train_monday)} flujos).")
    
    # Tuesday: Orden cronológico estricto
    # Primer 30% -> Validación / Calibración
    # 70% restante -> Prueba 1 (FTP-Patator + SSH-Patator)
    n_tue = len(df_tue)
    corte_30 = int(n_tue * 0.30)
    df_val_tuesday = df_tue.iloc[:corte_30].copy()
    df_test1_tuesday = df_tue.iloc[corte_30:].copy()
    
    val_benignos = (df_val_tuesday["Label"].str.strip().str.upper() == "BENIGN").sum()
    val_ataques = len(df_val_tuesday) - val_benignos
    test1_benignos = (df_test1_tuesday["Label"].str.strip().str.upper() == "BENIGN").sum()
    test1_ataques = len(df_test1_tuesday) - test1_benignos
    
    print(f"  Validación (Tuesday primeros 30% temporal): {len(df_val_tuesday)} flujos ({val_benignos} Benignos, {val_ataques} Ataques).")
    print(f"  Prueba 1 (Tuesday 70% restante temporal): {len(df_test1_tuesday)} flujos ({test1_benignos} Benignos, {test1_ataques} Ataques).")
    
    # Thursday: Prueba 2 completa (Web Attack Brute Force)
    test2_benignos = (df_thu["Label"].str.strip().str.upper() == "BENIGN").sum()
    test2_ataques = len(df_thu) - test2_benignos
    print(f"  Prueba 2 (Thursday mañana completo): {len(df_thu)} flujos ({test2_benignos} Benignos, {test2_ataques} Web Brute Force).")
    
    # Vectorización
    X_train = preparar_matriz_features(df_train_monday, columnas_requeridas_modelo)
    
    X_val = preparar_matriz_features(df_val_tuesday, columnas_requeridas_modelo)
    y_val = (df_val_tuesday["Label"].str.strip().str.upper() != "BENIGN").astype(int).values
    val_flows_waf = df_val_tuesday["src_flows_same_dst_port_60s"].values
    
    X_test1 = preparar_matriz_features(df_test1_tuesday, columnas_requeridas_modelo)
    y_test1 = (df_test1_tuesday["Label"].str.strip().str.upper() != "BENIGN").astype(int).values
    test1_flows_waf = df_test1_tuesday["src_flows_same_dst_port_60s"].values
    test1_labels_str = df_test1_tuesday["Label"].astype(str).values
    
    X_test2 = preparar_matriz_features(df_thu, columnas_requeridas_modelo)
    y_test2 = (df_thu["Label"].str.strip().str.upper() != "BENIGN").astype(int).values
    test2_flows_waf = df_thu["src_flows_same_dst_port_60s"].values
    test2_labels_str = df_thu["Label"].astype(str).values
    
    # 6. CALIBRACIÓN DE DETECTORES EN TRAMO DE VALIDACIÓN (FIJADA ANTES DE MIRAR PRUEBA)
    print("\n" + "-" * 80)
    print(" CALIBRACIÓN DE UMBRALES EN VALIDACIÓN (TUESDAY 30%)")
    print("-" * 80)
    
    # 6.1 Calibrar Reglas Heurísticas WAF
    reglas_waf = ReglasWafFlujo()
    n_opt_f1, info_calib_waf_f1 = reglas_waf.calibrar(val_flows_waf, y_val, criterio="max_f1")
    n_opt_fpr1, info_calib_waf_fpr1 = reglas_waf.calibrar(val_flows_waf, y_val, criterio="fpr_1pct")
    print(f"  Reglas WAF: Umbral N seleccionado = {n_opt_f1} flujos/60s (Max F1: {info_calib_waf_f1['f1_en_val']:.4f}).")
    print(f"  Reglas WAF: Umbral N (FPR <= 1%)  = {n_opt_fpr1} flujos/60s.")
    
    # 7. EXPERIMENTO MULTI-SEMILLA (10 SEMILLAS)
    semillas = args.seeds if isinstance(args.seeds, list) else SEMILLAS_POR_DEFECTO[:args.num_seeds]
    print(f"\nIniciando evaluaciones con {len(semillas)} semillas: {semillas}")
    
    resultados_semillas: List[Dict[str, Any]] = []
    
    detectores_nombres = [
        "reglas_waf",
        "isolation_forest",
        "one_class_svm",
        "lof",
        "ensamble_centinela",
        "random_forest_supervisado"
    ]
    
    # Contenedores para cálculo de medias y stds
    acumulador_metricas = {
        "test1_natural": {det: [] for det in detectores_nombres},
        "test1_balanceado": {det: [] for det in detectores_nombres},
        "test2_natural": {det: [] for det in detectores_nombres},
        "test2_balanceado": {det: [] for det in detectores_nombres},
        "recall_por_ataque": {
            "ftp_patator": {det: [] for det in detectores_nombres},
            "ssh_patator": {det: [] for det in detectores_nombres},
            "web_brute_force": {det: [] for det in detectores_nombres}
        }
    }
    
    for s_idx, seed in enumerate(semillas, 1):
        print(f"\n---> Semilla {s_idx}/{len(semillas)} [seed={seed}]")
        t_inicio_seed = time.time()
        
        # Instanciar suite Centinela
        suite = CentinelaMLSuite(seed=seed, max_samples_train=args.max_train_samples)
        suite.fit_unsupervised(X_train)
        suite.fit_supervised_reference(X_val, y_val)
        
        # Calibrar umbrales con validación
        scores_val = suite.obtener_scores(X_val)
        calib_ml = suite.calibrar_umbrales(scores_val, y_val)
        
        # Predicción y Scores en Prueba 1 (Tuesday 70%)
        t0 = time.time()
        scores_test1 = suite.obtener_scores(X_test1)
        t_ml_test1 = (time.time() - t0) * 1000
        
        # WAF en Prueba 1
        t0 = time.time()
        pred_waf_test1 = (test1_flows_waf >= n_opt_f1).astype(int)
        score_waf_test1 = reglas_waf.score_anomalia(test1_flows_waf)
        t_waf_test1 = (time.time() - t0) * 1000
        
        preds_test1 = {
            "reglas_waf": pred_waf_test1,
            "isolation_forest": (scores_test1["isolation_forest"] >= suite.umbrales_calibrados_f1["isolation_forest"]).astype(int),
            "one_class_svm": (scores_test1["one_class_svm"] >= suite.umbrales_calibrados_f1["one_class_svm"]).astype(int),
            "lof": (scores_test1["lof"] >= suite.umbrales_calibrados_f1["lof"]).astype(int),
            "ensamble_centinela": (scores_test1["ensamble"] >= suite.umbrales_calibrados_f1["ensamble"]).astype(int),
            "random_forest_supervisado": (scores_test1["rf_supervisado"] >= suite.umbrales_calibrados_f1["rf_supervisado"]).astype(int)
        }
        all_scores_test1 = {
            "reglas_waf": score_waf_test1,
            "isolation_forest": scores_test1["isolation_forest"],
            "one_class_svm": scores_test1["one_class_svm"],
            "lof": scores_test1["lof"],
            "ensamble_centinela": scores_test1["ensamble"],
            "random_forest_supervisado": scores_test1["rf_supervisado"]
        }
        
        # Predicción y Scores en Prueba 2 (Thursday Web Attacks)
        t0 = time.time()
        scores_test2 = suite.obtener_scores(X_test2)
        t_ml_test2 = (time.time() - t0) * 1000
        
        t0 = time.time()
        pred_waf_test2 = (test2_flows_waf >= n_opt_f1).astype(int)
        score_waf_test2 = reglas_waf.score_anomalia(test2_flows_waf)
        t_waf_test2 = (time.time() - t0) * 1000
        
        preds_test2 = {
            "reglas_waf": pred_waf_test2,
            "isolation_forest": (scores_test2["isolation_forest"] >= suite.umbrales_calibrados_f1["isolation_forest"]).astype(int),
            "one_class_svm": (scores_test2["one_class_svm"] >= suite.umbrales_calibrados_f1["one_class_svm"]).astype(int),
            "lof": (scores_test2["lof"] >= suite.umbrales_calibrados_f1["lof"]).astype(int),
            "ensamble_centinela": (scores_test2["ensamble"] >= suite.umbrales_calibrados_f1["ensamble"]).astype(int),
            "random_forest_supervisado": (scores_test2["rf_supervisado"] >= suite.umbrales_calibrados_f1["rf_supervisado"]).astype(int)
        }
        all_scores_test2 = {
            "reglas_waf": score_waf_test2,
            "isolation_forest": scores_test2["isolation_forest"],
            "one_class_svm": scores_test2["one_class_svm"],
            "lof": scores_test2["lof"],
            "ensamble_centinela": scores_test2["ensamble"],
            "random_forest_supervisado": scores_test2["rf_supervisado"]
        }
        
        # Submuestreo balanceado 50/50 para Prueba 1 y Prueba 2
        rng = np.random.default_rng(seed)
        
        # Balance Prueba 1
        idx_ataques_t1 = np.where(y_test1 == 1)[0]
        idx_benignos_t1 = np.where(y_test1 == 0)[0]
        n_bal_t1 = min(len(idx_ataques_t1), len(idx_benignos_t1))
        idx_bal_t1 = np.concatenate([
            rng.choice(idx_ataques_t1, n_bal_t1, replace=False),
            rng.choice(idx_benignos_t1, n_bal_t1, replace=False)
        ])
        
        # Balance Prueba 2
        idx_ataques_t2 = np.where(y_test2 == 1)[0]
        idx_benignos_t2 = np.where(y_test2 == 0)[0]
        n_bal_t2 = min(len(idx_ataques_t2), len(idx_benignos_t2))
        idx_bal_t2 = np.concatenate([
            rng.choice(idx_ataques_t2, n_bal_t2, replace=False),
            rng.choice(idx_benignos_t2, n_bal_t2, replace=False)
        ])
        
        # Evaluación por detector
        for det in detectores_nombres:
            lat_t1 = t_waf_test1 if det == "reglas_waf" else t_ml_test1 / 4.0
            lat_t2 = t_waf_test2 if det == "reglas_waf" else t_ml_test2 / 4.0
            
            # Prueba 1 Natural
            m_t1_nat = evaluar_metricas(y_test1, preds_test1[det], all_scores_test1[det], lat_t1)
            acumulador_metricas["test1_natural"][det].append(m_t1_nat)
            
            # Prueba 1 Balanceada
            m_t1_bal = evaluar_metricas(y_test1[idx_bal_t1], preds_test1[det][idx_bal_t1], all_scores_test1[det][idx_bal_t1], lat_t1)
            acumulador_metricas["test1_balanceado"][det].append(m_t1_bal)
            
            # Prueba 2 Natural
            m_t2_nat = evaluar_metricas(y_test2, preds_test2[det], all_scores_test2[det], lat_t2)
            acumulador_metricas["test2_natural"][det].append(m_t2_nat)
            
            # Prueba 2 Balanceada
            m_t2_bal = evaluar_metricas(y_test2[idx_bal_t2], preds_test2[det][idx_bal_t2], all_scores_test2[det][idx_bal_t2], lat_t2)
            acumulador_metricas["test2_balanceado"][det].append(m_t2_bal)
            
            # Recall por tipo de ataque específico
            # FTP-Patator
            mask_ftp = np.char.find(np.char.lower(test1_labels_str), "ftp") >= 0
            if mask_ftp.sum() > 0:
                rec_ftp = float(preds_test1[det][mask_ftp].sum() / mask_ftp.sum())
            else:
                rec_ftp = 0.0
            acumulador_metricas["recall_por_ataque"]["ftp_patator"][det].append(rec_ftp)
            
            # SSH-Patator
            mask_ssh = np.char.find(np.char.lower(test1_labels_str), "ssh") >= 0
            if mask_ssh.sum() > 0:
                rec_ssh = float(preds_test1[det][mask_ssh].sum() / mask_ssh.sum())
            else:
                rec_ssh = 0.0
            acumulador_metricas["recall_por_ataque"]["ssh_patator"][det].append(rec_ssh)
            
            # Web Brute Force (Thursday)
            mask_web = np.char.find(np.char.lower(test2_labels_str), "brute") >= 0
            if mask_web.sum() > 0:
                rec_web = float(preds_test2[det][mask_web].sum() / mask_web.sum())
            else:
                rec_web = 0.0
            acumulador_metricas["recall_por_ataque"]["web_brute_force"][det].append(rec_web)
            
        print(f"  Semilla completada en {time.time() - t_inicio_seed:.1f} s.")
        
    # 8. CONSOLIDACIÓN DE MEDIAS, DESVIACIONES ESTÁNDAR E INTERVALOS BOOTSTRAP 95%
    print("\n" + "=" * 80)
    print(" CONSOLIDANDO RESULTADOS Y CALCULANDO INTERVALOS BOOTSTRAP 95%")
    print("=" * 80)
    
    # Bootstrap sobre la última semilla para estimación empírica en Test 1 y Test 2
    bootstrap_intervals = {
        "test1": {},
        "test2": {}
    }
    for det in detectores_nombres:
        bootstrap_intervals["test1"][det] = calcular_bootstrap_ci_95(y_test1, preds_test1[det], n_bootstrap=args.n_bootstrap, seed=42)
        bootstrap_intervals["test2"][det] = calcular_bootstrap_ci_95(y_test2, preds_test2[det], n_bootstrap=args.n_bootstrap, seed=42)
        
    def compilar_resumen_estadistico(lista_metricas_dict):
        res = {}
        for campo in ["precision", "recall", "f1", "fpr", "especificidad", "accuracy", "auc_roc", "auc_pr", "latencia_ms_por_flujo"]:
            valores = [m[campo] for m in lista_metricas_dict]
            res[campo] = {
                "media": float(np.mean(valores)),
                "std": float(np.std(valores)),
                "min": float(np.min(valores)),
                "max": float(np.max(valores))
            }
        # Promedio de matriz de confusión
        for campo_cm in ["VP", "FP", "FN", "VN"]:
            res[campo_cm] = int(round(np.mean([m[campo_cm] for m in lista_metricas_dict])))
        return res

    resumen_final = {
        "origen_datos": ORIGEN_DATOS,
        "fecha_ejecucion": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "semillas_evaluadas": semillas,
        "n_bootstrap": args.n_bootstrap,
        "hashes_sha256": hashes_sha256,
        "limpieza_datos": registros_limpieza,
        "features_utilizadas": columnas_requeridas_modelo,
        "calibracion": {
            "criterio": "Tuesday primeros 30% cronológico (zero-leakage)",
            "reglas_waf_n": n_opt_f1,
            "reglas_waf_n_fpr1": n_opt_fpr1,
            "umbrales_ml_f1": suite.umbrales_calibrados_f1,
            "umbrales_ml_fpr1": suite.umbrales_calibrados_fpr1
        },
        "metricas": {
            "prueba1_tuesday_natural": {
                det: {
                    **compilar_resumen_estadistico(acumulador_metricas["test1_natural"][det]),
                    "bootstrap_ci_95": bootstrap_intervals["test1"][det]
                } for det in detectores_nombres
            },
            "prueba1_tuesday_balanceado": {
                det: compilar_resumen_estadistico(acumulador_metricas["test1_balanceado"][det])
                for det in detectores_nombres
            },
            "prueba2_thursday_natural": {
                det: {
                    **compilar_resumen_estadistico(acumulador_metricas["test2_natural"][det]),
                    "bootstrap_ci_95": bootstrap_intervals["test2"][det]
                } for det in detectores_nombres
            },
            "prueba2_thursday_balanceado": {
                det: compilar_resumen_estadistico(acumulador_metricas["test2_balanceado"][det])
                for det in detectores_nombres
            },
            "recall_por_tipo_ataque": {
                ataque: {
                    det: {
                        "media": float(np.mean(acumulador_metricas["recall_por_ataque"][ataque][det])),
                        "std": float(np.std(acumulador_metricas["recall_por_ataque"][ataque][det]))
                    } for det in detectores_nombres
                } for ataque in ["ftp_patator", "ssh_patator", "web_brute_force"]
            }
        }
    }
    
    # 9. GUARDAR ARCHIVOS DE SALIDA (JSON, CSV, REPORTE MD, REPRODUCIBILIDAD)
    ruta_json = os.path.join(output_dir, "resultados_cicids_real.json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(resumen_final, f, indent=2, ensure_ascii=False)
    print(f"\n[1/4] Resultados en JSON guardados en: {ruta_json}")
    
    # CSV Tabular plano
    filas_csv = []
    for prueba_clave, prueba_nombre in [
        ("prueba1_tuesday_natural", "Prueba 1 (Tuesday - Natural)"),
        ("prueba1_tuesday_balanceado", "Prueba 1 (Tuesday - Balanceado 50/50)"),
        ("prueba2_thursday_natural", "Prueba 2 (Thursday - Natural)"),
        ("prueba2_thursday_balanceado", "Prueba 2 (Thursday - Balanceado 50/50)")
    ]:
        for det in detectores_nombres:
            d = resumen_final["metricas"][prueba_clave][det]
            filas_csv.append({
                "Origen": ORIGEN_DATOS,
                "Evaluacion": prueba_nombre,
                "Detector": det,
                "F1_Media": d["f1"]["media"],
                "F1_Std": d["f1"]["std"],
                "Recall_Media": d["recall"]["media"],
                "Recall_Std": d["recall"]["std"],
                "Precision_Media": d["precision"]["media"],
                "Precision_Std": d["precision"]["std"],
                "FPR_Media": d["fpr"]["media"],
                "FPR_Std": d["fpr"]["std"],
                "Especificidad_Media": d["especificidad"]["media"],
                "Accuracy_Media": d["accuracy"]["media"],
                "AUC_ROC_Media": d["auc_roc"]["media"],
                "AUC_PR_Media": d["auc_pr"]["media"],
                "VP": d["VP"],
                "FP": d["FP"],
                "FN": d["FN"],
                "VN": d["VN"],
                "Latencia_ms": d["latencia_ms_por_flujo"]["media"]
            })
    df_csv = pd.DataFrame(filas_csv)
    ruta_csv = os.path.join(output_dir, "resultados_cicids_real.csv")
    df_csv.to_csv(ruta_csv, index=False)
    print(f"[2/4] Resultados tabulares CSV guardados en: {ruta_csv}")
    
    # Certificado de reproducibilidad
    ruta_reprod = os.path.join(output_dir, "reproducibilidad_cicids.json")
    info_reprod = {
        "origen_datos": ORIGEN_DATOS,
        "entorno_ejecucion": {
            "python_version": platform.python_version(),
            "scikit_learn_version": sklearn.__version__,
            "numpy_version": np.__version__,
            "pandas_version": pd.__version__,
            "sistema_operativo": platform.platform()
        },
        "hashes_sha256": hashes_sha256,
        "limpieza_y_conteos": registros_limpieza,
        "semillas_usadas": semillas,
        "parametros_calibrados": resumen_final["calibracion"],
        "lista_features_exacta": columnas_requeridas_modelo
    }
    with open(ruta_reprod, "w", encoding="utf-8") as f:
        json.dump(info_reprod, f, indent=2, ensure_ascii=False)
    print(f"[3/4] Certificado de reproducibilidad guardado en: {ruta_reprod}")
    
    # Generar Reporte Markdown para el Artículo Científico
    ruta_md = os.path.join(output_dir, "reporte_cicids_real.md")
    generar_reporte_markdown(resumen_final, ruta_md)
    print(f"[4/4] Reporte académico en Markdown guardado en: {ruta_md}")
    
    print("\n" + "=" * 80)
    print(" VALIDACIÓN COMPLETADA EXITOSAMENTE CON DATOS REALES DE CICIDS2017")
    print("=" * 80)
    return resumen_final


def generar_reporte_markdown(r: Dict[str, Any], ruta_salida: str):
    """Genera tablas en Markdown rigurosas listas para pegar en el manuscrito científico."""
    m = r["metricas"]
    
    nombres_legibles = {
        "reglas_waf": "Reglas Heurísticas WAF (Flujos N-Puerto)",
        "isolation_forest": "Isolation Forest (Centinela)",
        "one_class_svm": "One-Class SVM (Centinela RBF)",
        "lof": "Local Outlier Factor (LOF Centinela)",
        "ensamble_centinela": "Ensamble Ponderado Centinela",
        "random_forest_supervisado": "Random Forest (Supervisado - Referencia)"
    }
    
    lineas = [
        f"# Evaluación Empírica de Centinela con Datos Reales de {ORIGEN_DATOS}",
        "",
        "> **Declaración de Origen**: Todos los datos evaluados provienen estrictamente de los archivos oficiales",
        f"> de CICIDS2017 del Canadian Institute for Cybersecurity ({URL_OFICIAL_CIC}).",
        "> Partición cronológica estricta sin fuga de información (Zero-Leakage Split).",
        "",
        "## 1. Tabla 1: Rendimiento con Prevalencia Natural de Ataques",
        "",
        "### A. Prueba 1: Tráfico Tuesday (Patator: FTP y SSH)",
        "| Detector | F1-Score (Media ± Std) | Recall (TPR) | Precisión (PPV) | FPR (Tasa Falsos Pos.) | AUC-ROC | Latencia (ms/flujo) | IC 95% Bootstrap F1 |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]
    
    for det, val in m["prueba1_tuesday_natural"].items():
        ci = val.get("bootstrap_ci_95", {}).get("f1", (0.0, 0.0))
        nombre = nombres_legibles.get(det, det)
        lineas.append(
            f"| **{nombre}** | {val['f1']['media']:.4f} ± {val['f1']['std']:.4f} | "
            f"{val['recall']['media']:.4f} | {val['precision']['media']:.4f} | "
            f"{val['fpr']['media']:.4f} | {val['auc_roc']['media']:.4f} | "
            f"{val['latencia_ms_por_flujo']['media']:.3f} ms | [{ci[0]:.4f}, {ci[1]:.4f}] |"
        )
        
    lineas.extend([
        "",
        "### B. Prueba 2: Tráfico Thursday Morning (Web Attack Brute Force)",
        "| Detector | F1-Score (Media ± Std) | Recall (TPR) | Precisión (PPV) | FPR | AUC-ROC | Latencia (ms/flujo) | IC 95% Bootstrap F1 |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ])
    for det, val in m["prueba2_thursday_natural"].items():
        ci = val.get("bootstrap_ci_95", {}).get("f1", (0.0, 0.0))
        nombre = nombres_legibles.get(det, det)
        lineas.append(
            f"| **{nombre}** | {val['f1']['media']:.4f} ± {val['f1']['std']:.4f} | "
            f"{val['recall']['media']:.4f} | {val['precision']['media']:.4f} | "
            f"{val['fpr']['media']:.4f} | {val['auc_roc']['media']:.4f} | "
            f"{val['latencia_ms_por_flujo']['media']:.3f} ms | [{ci[0]:.4f}, {ci[1]:.4f}] |"
        )
        
    lineas.extend([
        "",
        "## 2. Tabla 2: Rendimiento con Submuestreo Balanceado (50% Benigno / 50% Ataque)",
        "| Detector | F1 Prueba 1 (Patator) | F1 Prueba 2 (Web Brute Force) | Recall Prueba 1 | Recall Prueba 2 | Especificidad P1 | Especificidad P2 |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |"
    ])
    for det in m["prueba1_tuesday_balanceado"].keys():
        v1 = m["prueba1_tuesday_balanceado"][det]
        v2 = m["prueba2_thursday_balanceado"][det]
        nombre = nombres_legibles.get(det, det)
        lineas.append(
            f"| **{nombre}** | {v1['f1']['media']:.4f} | {v2['f1']['media']:.4f} | "
            f"{v1['recall']['media']:.4f} | {v2['recall']['media']:.4f} | "
            f"{v1['especificidad']['media']:.4f} | {v2['especificidad']['media']:.4f} |"
        )
        
    lineas.extend([
        "",
        "## 3. Tabla 3: Tasa de Detección (Recall) Desglosada por Familia de Ataque",
        "| Detector | FTP-Patator (Tuesday) | SSH-Patator (Tuesday) | Web Attack Brute Force (Thursday) |",
        "| :--- | :---: | :---: | :---: |"
    ])
    rec_ataques = m["recall_por_tipo_ataque"]
    for det in nombres_legibles.keys():
        ftp_v = rec_ataques["ftp_patator"][det]
        ssh_v = rec_ataques["ssh_patator"][det]
        web_v = rec_ataques["web_brute_force"][det]
        nombre = nombres_legibles[det]
        lineas.append(
            f"| **{nombre}** | {ftp_v['media']*100:.2f}% ± {ftp_v['std']*100:.2f}% | "
            f"{ssh_v['media']*100:.2f}% ± {ssh_v['std']*100:.2f}% | "
            f"{web_v['media']*100:.2f}% ± {web_v['std']*100:.2f}% |"
        )
        
    lineas.extend([
        "",
        "## 4. Parámetros de Calibración Sin Fuga Temporal (Tuesday 30%)",
        f"- **Umbral Reglas WAF (N)**: `{r['calibracion']['reglas_waf_n']}` flujos/60s a mismo puerto destino.",
        f"- **Umbral Reglas WAF (FPR <= 1%)**: `{r['calibracion']['reglas_waf_n_fpr1']}` flujos/60s.",
        f"- **Umbral Ensamble Centinela**: `{r['calibracion']['umbrales_ml_f1']['ensamble']:.4f}`.",
        f"- **Umbral Isolation Forest**: `{r['calibracion']['umbrales_ml_f1']['isolation_forest']:.4f}`.",
        "",
        "## 5. Integridad Criptográfica de los Archivos Evaluados",
    ])
    for k, v in r["hashes_sha256"].items():
        lineas.append(f"- **{k.upper()}** (`{v['archivo']}`): `SHA-256: {v['sha256']}` ({v['tamano_bytes']} bytes)")
        
    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas) + "\n")


# ---------------------------------------------------------------------------
# PUNTO DE ENTRADA CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Validación Científica de Centinela con Datos Reales de CICIDS2017 (Zero-Leakage)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplo de ejecución:
  python3 validacion_cicids_real.py --data-dir /datasets/cicids2017/ --output-dir ./resultados_reales/
        """
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=".",
        help="Carpeta que contiene los CSVs oficiales de CICIDS2017 (Monday, Tuesday, Thursday)."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="Carpeta donde se guardarán los resultados (JSON, CSV, MD y reproducibilidad)."
    )
    parser.add_argument(
        "--num-seeds",
        type=int,
        default=10,
        help="Número de semillas para repeticiones (por defecto: 10)."
    )
    parser.add_argument(
        "--seeds",
        type=int,
        nargs="+",
        default=None,
        help="Lista personalizada de semillas (ej. --seeds 42 101 2023)."
    )
    parser.add_argument(
        "--max-train-samples",
        type=int,
        default=40000,
        help="Muestra máxima para ajuste de algoritmos no lineales O(N^2) (por defecto: 40000)."
    )
    parser.add_argument(
        "--n-bootstrap",
        type=int,
        default=1000,
        help="Número de remuestreos bootstrap para intervalos al 95% (por defecto: 1000)."
    )
    
    args = parser.parse_args()
    ejecutar_validacion_completa(args)


if __name__ == "__main__":
    main()
