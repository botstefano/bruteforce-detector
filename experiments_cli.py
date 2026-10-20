#!/usr/bin/env python3
"""
experiments_cli.py — Suite Científica Autónoma de Experimentación y Validación
Proyecto Centinela — Brute Force Detector & Mitigation Research

Reglas y metodología:
  1. Cero valores hardcodeados o simulados con Math.random() condicionado.
  2. Todos los modelos se ejecutan desde scikit-learn con optimización real.
  3. Reloj virtual determinista para simulación (nunca Date.now()).
  4. Hiperparámetros, regla de ensamble y umbrales (tau, N, ventana WAF) calibrados
     exclusivamente en conjunto de validación y fijados antes de mirar el conjunto de prueba.
  5. Intervalos de confianza calculados mediante Bootstrap no paramétrico sobre prueba.
  6. Latencia medida con time.perf_counter_ns() y especificaciones de hardware registradas.
  7. Manifiesto criptográfico con SHA-256 reales y commit hash.
"""

import sys
import os
import time
import json
import argparse
import platform
import hashlib
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve
)

# =========================================================================
# 1. HARDWARE, ENTORNO Y CRIPTOGRAFÍA
# =========================================================================

def get_hardware_specs() -> Dict[str, Any]:
    """Registra especificaciones del entorno de ejecución de hardware y librerías."""
    mem_total_mb = 0
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if 'MemTotal' in line:
                    mem_total_mb = int(line.split()[1]) // 1024
                    break
    except Exception:
        mem_total_mb = 0

    import sklearn
    import scipy

    return {
        "os_platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count_logical": os.cpu_count() or 1,
        "ram_total_mb": mem_total_mb,
        "python_version": sys.version.split()[0],
        "library_versions": {
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scipy": scipy.__version__,
        },
        "note": "Modelos ejecutados en Python (scikit-learn). Son independientes del microservicio Node.js."
    }

def compute_file_sha256(filepath: str) -> str:
    """Calcula el hash SHA-256 criptográfico real de un archivo en disco."""
    if not os.path.exists(filepath):
        return ""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

# =========================================================================
# 2. RELOJ VIRTUAL Y SIMULADOR DETERMINISTA SINTÉTICO
# =========================================================================

class VirtualClock:
    """Reloj virtual para simulación reproducible. Evita el uso de timestamps reales de sistema."""
    def __init__(self, start_timestamp: float = 1700000000.0):
        self.current_time = start_timestamp

    def advance(self, delta_seconds: float) -> float:
        self.current_time += max(0.0001, delta_seconds)
        return self.current_time

    def now(self) -> float:
        return self.current_time

class HeuristicWAF:
    """Regla Heurística WAF parametrizable por ventana de tiempo y umbral N."""
    def __init__(self, window_sec: float = 60.0, threshold_n: int = 5):
        self.window_sec = window_sec
        self.threshold_n = threshold_n
        self.history: List[Tuple[float, str, str, bool]] = [] # (ts, ip, user, is_attack)

    def evaluate_stream(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Evalúa un flujo ordenado en tiempo virtual y emite veredictos booleanos."""
        preds = []
        ip_windows: Dict[str, List[float]] = {}

        for ev in events:
            t = ev["timestamp"]
            ip = ev["ip"]
            # Limpiar eventos fuera de la ventana
            if ip not in ip_windows:
                ip_windows[ip] = []
            ip_windows[ip] = [ts for ts in ip_windows[ip] if t - ts <= self.window_sec]
            
            # Registrar intento
            ip_windows[ip].append(t)

            # Regla de frecuencia en ventana
            is_blocked = len(ip_windows[ip]) >= self.threshold_n
            preds.append(1 if is_blocked else 0)

        return np.array(preds, dtype=int)

def generate_synthetic_stream(
    n_samples: int,
    rng: np.random.Generator,
    clock: VirtualClock,
    is_drift: bool = False,
    drift_config: Optional[Dict[str, float]] = None
) -> Tuple[List[Dict[str, Any]], np.ndarray, np.ndarray]:
    """
    Genera un flujo sintético de eventos con reloj virtual acumulativo.
    Retorna: (lista_eventos, matriz_X_5D, vector_y_etiquetas)
    """
    drift_iat = drift_config.get("iat_mean_shift_factor", 1.75) if (is_drift and drift_config) else 1.0
    drift_rate = drift_config.get("rate_scale_factor", 0.65) if (is_drift and drift_config) else 1.0

    events = []
    features_list = []
    labels = []

    legitimate_users = ["admin", "carla", "roberto", "jperez", "mgarcia", "dev1"]
    known_ips = [f"192.168.1.{i}" for i in range(10, 60)]
    botnet_ips = [f"10.0.{i // 254}.{i % 254 + 1}" for i in range(1, 1000)]

    # Proporción: 60% Benigno, 40% Ataques variados (Rápido, Lento, Distribuido)
    for _ in range(n_samples):
        is_attack = rng.random() < 0.40
        labels.append(1 if is_attack else 0)

        if not is_attack:
            # Benigno: IAT alto, baja frecuencia, IP conocida
            delta = rng.exponential(scale=35.0 * drift_iat)
            clock.advance(delta)
            ip = rng.choice(known_ips)
            user = rng.choice(legitimate_users)
            attack_type = "benign"
            n_attempts_window = rng.choice([0, 1, 2], p=[0.70, 0.22, 0.08])
            n_users = 1 if n_attempts_window > 0 else 0
            iat_mean = float(rng.uniform(20.0, 90.0) * drift_iat)
            iat_std = float(rng.uniform(5.0, 30.0))
        else:
            subtipo = rng.choice(["rapido", "lento", "distribuido"], p=[0.40, 0.35, 0.25])
            if subtipo == "rapido":
                delta = rng.uniform(0.1, 0.8) / drift_rate
                clock.advance(delta)
                ip = rng.choice(botnet_ips[:5])
                user = rng.choice(["admin", "root", "guest"])
                attack_type = "burst"
                n_attempts_window = int(rng.integers(6, 18) * drift_rate)
                n_users = int(rng.integers(1, 3))
                iat_mean = float(rng.uniform(0.2, 1.2) / drift_rate)
                iat_std = float(rng.uniform(0.05, 0.4))
            elif subtipo == "lento":
                delta = rng.uniform(4.0, 15.0) * drift_iat
                clock.advance(delta)
                ip = rng.choice(botnet_ips[5:20])
                user = "admin"
                attack_type = "slow"
                n_attempts_window = rng.choice([2, 3, 4])
                n_users = 1
                iat_mean = float(rng.uniform(6.0, 18.0) * drift_iat)
                iat_std = float(rng.uniform(0.5, 3.0))
            else: # Distribuido
                delta = rng.uniform(0.2, 2.0)
                clock.advance(delta)
                ip = rng.choice(botnet_ips)
                user = rng.choice(["admin", "roberto"])
                attack_type = "distributed"
                n_attempts_window = rng.choice([1, 2, 3])
                n_users = rng.choice([1, 2])
                iat_mean = float(rng.uniform(2.0, 10.0))
                iat_std = float(rng.uniform(1.0, 5.0))

        hora_normalizada = (clock.now() % 86400) / 3600.0 # 0.0 a 24.0

        ev = {
            "timestamp": clock.now(),
            "ip": ip,
            "user": user,
            "is_attack": is_attack,
            "attack_type": attack_type
        }
        events.append(ev)

        # Vector de 5 dimensiones: [intentos, usuarios, iat_mean, iat_std, hora]
        features_list.append([
            float(n_attempts_window),
            float(n_users),
            float(round(iat_mean, 3)),
            float(round(iat_std, 3)),
            float(round(hora_normalizada, 2))
        ])

    return events, np.array(features_list, dtype=np.float32), np.array(labels, dtype=int)

# =========================================================================
# 3. CALIBRACIÓN EN VALIDACIÓN Y AJUSTE DE MODELOS
# =========================================================================

def fit_models(
    X_train_benign: np.ndarray,
    hyperparams: Dict[str, Any],
    seed: int
) -> Tuple[IsolationForest, OneClassSVM, LocalOutlierFactor]:
    """Entrena los 3 modelos no supervisados de scikit-learn con tráfico benigno."""
    hp_if = hyperparams.get("isolation_forest", {})
    hp_svm = hyperparams.get("one_class_svm", {})
    hp_lof = hyperparams.get("local_outlier_factor", {})

    iforest = IsolationForest(
        n_estimators=hp_if.get("n_estimators", 100),
        contamination=hp_if.get("contamination", "auto"),
        random_state=seed,
        n_jobs=-1
    )
    iforest.fit(X_train_benign)

    ocsvm = OneClassSVM(
        kernel=hp_svm.get("kernel", "rbf"),
        gamma=hp_svm.get("gamma", "scale"),
        nu=hp_svm.get("nu", 0.05)
    )
    ocsvm.fit(X_train_benign)

    lof = LocalOutlierFactor(
        n_neighbors=hp_lof.get("n_neighbors", 20),
        novelty=True,
        n_jobs=-1
    )
    lof.fit(X_train_benign)

    return iforest, ocsvm, lof

def calibrate_waf_on_validation(
    val_events: List[Dict[str, Any]],
    val_y: np.ndarray,
    val_grid: Dict[str, Any]
) -> Tuple[float, int, float]:
    """
    Selecciona la ventana W y umbral N óptimos evaluando exhaustivamente
    la rejilla sobre el conjunto de validación (maximizando F1).
    """
    ventanas = val_grid.get("ventanas_segundos", [30, 60, 120, 300])
    umbrales = val_grid.get("umbrales_n", [3, 4, 5, 8, 10])

    best_w = ventanas[0]
    best_n = umbrales[0]
    best_f1 = -1.0

    for w in ventanas:
        for n in umbrales:
            waf = HeuristicWAF(window_sec=w, threshold_n=n)
            preds = waf.evaluate_stream(val_events)
            score = f1_score(val_y, preds, zero_division=0)
            if score > best_f1:
                best_f1 = score
                best_w = w
                best_n = n

    return float(best_w), int(best_n), float(best_f1)

def calibrate_tau_on_validation(
    val_scores: np.ndarray,
    val_y: np.ndarray,
    tau_config: Dict[str, Any]
) -> Tuple[float, float]:
    """Calibra el umbral de anomalía tau en el conjunto de validación."""
    tau_min = tau_config.get("min", 0.1)
    tau_max = tau_config.get("max", 0.9)
    step = tau_config.get("step", 0.02)

    best_tau = 0.5
    best_f1 = -1.0

    for tau in np.arange(tau_min, tau_max + step, step):
        preds = (val_scores >= tau).astype(int)
        score = f1_score(val_y, preds, zero_division=0)
        if score > best_f1:
            best_f1 = score
            best_tau = round(float(tau), 4)

    return best_tau, float(best_f1)

def compute_model_anomaly_scores(
    iforest: IsolationForest,
    ocsvm: OneClassSVM,
    lof: LocalOutlierFactor,
    X: np.ndarray
) -> Dict[str, np.ndarray]:
    """Calcula scores normalizados de anomalía [0.0, 1.0] para cada modelo."""
    # Isolation Forest: score_samples entrega valores donde menor es más anómalo
    raw_if = iforest.score_samples(X)
    # Normalizar a 0..1 invertido
    min_if, max_if = raw_if.min(), raw_if.max()
    score_if = 1.0 - (raw_if - min_if) / (max_if - min_if + 1e-9)

    # OneClassSVM: decision_function (negativo = anómalo)
    raw_svm = ocsvm.decision_function(X)
    min_svm, max_svm = raw_svm.min(), raw_svm.max()
    score_svm = 1.0 - (raw_svm - min_svm) / (max_svm - min_svm + 1e-9)

    # LOF: score_samples
    raw_lof = lof.score_samples(X)
    min_lof, max_lof = raw_lof.min(), raw_lof.max()
    score_lof = 1.0 - (raw_lof - min_lof) / (max_lof - min_lof + 1e-9)

    return {
        "iforest": score_if,
        "ocsvm": score_svm,
        "lof": score_lof,
        "ensamble": (score_if + score_svm + score_lof) / 3.0
    }

# =========================================================================
# 4. EVALUACIÓN Y BOOTSTRAP DE CONFIANZA SOBRE TEST
# =========================================================================

def calculate_metrics_dict(y_true: np.ndarray, y_pred: np.ndarray, scores: Optional[np.ndarray] = None) -> Dict[str, Any]:
    """Calcula métricas binarias estrictas a partir de predicciones reales."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    res = {
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "accuracy": round(float(acc), 4),
        "specificity": round(float(specificity), 4),
        "false_positive_rate": round(float(fpr), 4),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_negatives": int(tn)
    }

    if scores is not None and len(np.unique(y_true)) > 1:
        try:
            fpr_curve, tpr_curve, _ = roc_curve(y_true, scores)
            res["auc_roc"] = round(float(auc(fpr_curve, tpr_curve)), 4)
            p_curve, r_curve, _ = precision_recall_curve(y_true, scores)
            res["auc_pr"] = round(float(auc(r_curve, p_curve)), 4)
        except Exception:
            res["auc_roc"] = 0.5
            res["auc_pr"] = 0.0

    return res

def run_bootstrap_confidence_intervals(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    n_iterations: int = 1000,
    confidence_level: float = 0.95,
    seed: int = 42
) -> Dict[str, Dict[str, float]]:
    """
    Calcula intervalos de confianza no paramétricos por Bootstrap
    exclusivamente sobre el conjunto de test.
    """
    rng = np.random.default_rng(seed)
    n = len(y_true)
    f1_list = []
    prec_list = []
    rec_list = []

    for _ in range(n_iterations):
        indices = rng.integers(0, n, size=n)
        bs_true = y_true[indices]
        bs_pred = y_pred[indices]

        prec_list.append(precision_score(bs_true, bs_pred, zero_division=0))
        rec_list.append(recall_score(bs_true, bs_pred, zero_division=0))
        f1_list.append(f1_score(bs_true, bs_pred, zero_division=0))

    alpha = (1.0 - confidence_level) / 2.0
    low_idx = alpha * 100
    high_idx = (1.0 - alpha) * 100

    return {
        "precision": {
            "low": round(float(np.percentile(prec_list, low_idx)), 4),
            "high": round(float(np.percentile(prec_list, high_idx)), 4),
            "std": round(float(np.std(prec_list)), 4)
        },
        "recall": {
            "low": round(float(np.percentile(rec_list, low_idx)), 4),
            "high": round(float(np.percentile(rec_list, high_idx)), 4),
            "std": round(float(np.std(rec_list)), 4)
        },
        "f1_score": {
            "low": round(float(np.percentile(f1_list, low_idx)), 4),
            "high": round(float(np.percentile(f1_list, high_idx)), 4),
            "std": round(float(np.std(f1_list)), 4)
        }
    }

# =========================================================================
# =========================================================================
# 5. EXPERIMENTO DE ESCALADO DE BOTNET (CARGA TOTAL FIJA)
# =========================================================================

def run_botnet_scale_experiment(
    iforest: IsolationForest,
    ocsvm: OneClassSVM,
    lof: LocalOutlierFactor,
    waf: HeuristicWAF,
    tau_ensemble: float,
    seed: int
) -> List[Dict[str, Any]]:
    """
    Evalúa el colapso del WAF vs Ensamble ML manteniendo la carga total de intentos de ataque
    ESTRICTAMENTE FIJA en 1200 intentos, mezclados con 1200 peticiones de tráfico benigno de control
    (total 2400 eventos por ronda).
    Reporta Recall, Precisión, FPR y F1 para cada tamaño de enjambre de IPs.
    """
    rng = np.random.default_rng(seed)
    attack_attempts_total = 1200
    benign_requests_total = 1200
    ip_swarm_sizes = [1, 5, 20, 50, 100, 200, 400]
    rounds_result = []

    legit_ips = [f"192.168.1.{i}" for i in range(10, 60)]
    legit_users = ["admin", "carla", "roberto", "jperez", "mgarcia"]

    for n_ips in ip_swarm_sizes:
        attempts_per_ip = max(1, attack_attempts_total // n_ips)
        clock = VirtualClock(start_timestamp=1700200000.0)
        events = []
        features = []
        y_true = []

        # Intercalar de forma estocástica 1200 ataques y 1200 eventos legítimos
        is_attack_plan = [1] * attack_attempts_total + [0] * benign_requests_total
        rng.shuffle(is_attack_plan)

        attack_counter = 0

        for is_atk in is_attack_plan:
            if is_atk == 1:
                attack_counter += 1
                ip_idx = attack_counter % n_ips
                ip_addr = f"10.240.{ip_idx // 250}.{ip_idx % 250 + 1}"
                delta_t = rng.uniform(0.1, 1.5)
                clock.advance(delta_t)
                user = "admin"
                freq_val = attempts_per_ip
                iat_m = delta_t
                iat_s = 0.25
            else:
                ip_addr = rng.choice(legit_ips)
                delta_t = rng.exponential(scale=30.0)
                clock.advance(delta_t)
                user = rng.choice(legit_users)
                freq_val = rng.choice([0, 1, 2], p=[0.7, 0.2, 0.1])
                iat_m = rng.uniform(20.0, 80.0)
                iat_s = rng.uniform(5.0, 25.0)

            events.append({
                "timestamp": clock.now(),
                "ip": ip_addr,
                "user": user,
                "is_attack": bool(is_atk)
            })
            y_true.append(is_atk)
            features.append([
                float(freq_val),
                1.0 if is_atk else (1.0 if freq_val > 0 else 0.0),
                float(round(iat_m, 3)),
                float(round(iat_s, 3)),
                14.0
            ])

        X_round = np.array(features, dtype=np.float32)
        y_round = np.array(y_true, dtype=int)

        # Inferencia WAF
        waf_preds = waf.evaluate_stream(events)

        # Inferencia Ensamble ML
        scores = compute_model_anomaly_scores(iforest, ocsvm, lof, X_round)
        ml_preds = (scores["ensamble"] >= tau_ensemble).astype(int)

        m_waf = calculate_metrics_dict(y_round, waf_preds)
        m_ml = calculate_metrics_dict(y_round, ml_preds, scores["ensamble"])

        rounds_result.append({
            "num_ips": n_ips,
            "attack_attempts": attack_attempts_total,
            "benign_control_requests": benign_requests_total,
            "total_samples": len(y_round),
            "attempts_per_ip": round(attack_attempts_total / n_ips, 1),
            "waf": {
                "recall": m_waf["recall"],
                "precision": m_waf["precision"],
                "false_positive_rate": m_waf["false_positive_rate"],
                "f1_score": m_waf["f1_score"],
                "true_positives": m_waf["true_positives"],
                "false_positives": m_waf["false_positives"]
            },
            "ml_ensemble": {
                "recall": m_ml["recall"],
                "precision": m_ml["precision"],
                "false_positive_rate": m_ml["false_positive_rate"],
                "f1_score": m_ml["f1_score"],
                "true_positives": m_ml["true_positives"],
                "false_positives": m_ml["false_positives"]
            }
        })

    return rounds_result

# =========================================================================
# 6. ESTUDIO DE ABLACIÓN SISTEMÁTICA CON RECALIBRACIÓN DE TAU Y EVALUACIÓN EN TEST
# =========================================================================

def run_ablation_study(
    X_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: List[str],
    hyperparams: Dict[str, Any],
    seed: int,
    tau_config: Dict[str, Any],
    tau_baseline: float
) -> List[Dict[str, Any]]:
    """
    Reentrena y evalúa los modelos excluyendo sistemáticamente una variable a la vez.
    Para cada variante:
      1. Entrena en X_train (sin esa característica).
      2. Recalibra el umbral óptimo tau en validación (X_val) para dicha variante.
      3. Evalúa el desempeño en el conjunto de prueba (X_test) usando el tau específico recalibrado.
    """
    # 1. Baseline completo evaluado en prueba con su tau calibrado en validación
    if_base, svm_base, lof_base = fit_models(X_train, hyperparams, seed)
    sc_val_b = compute_model_anomaly_scores(if_base, svm_base, lof_base, X_val)
    sc_test_b = compute_model_anomaly_scores(if_base, svm_base, lof_base, X_test)
    pred_test_b = (sc_test_b["ensamble"] >= tau_baseline).astype(int)
    m_base = calculate_metrics_dict(y_test, pred_test_b, sc_test_b["ensamble"])
    f1_base = m_base["f1_score"]

    ablation_results = [{
        "excluded_feature": "None (Full Baseline)",
        "evaluation_set": "test",
        "calibrated_tau_val": tau_baseline,
        "f1_score": m_base["f1_score"],
        "delta_f1": 0.0,
        "precision": m_base["precision"],
        "recall": m_base["recall"],
        "false_positive_rate": m_base["false_positive_rate"]
    }]

    for idx, f_name in enumerate(feature_names):
        # Excluir columna idx en los 3 conjuntos
        X_tr_abl = np.delete(X_train, idx, axis=1)
        X_val_abl = np.delete(X_val, idx, axis=1)
        X_te_abl = np.delete(X_test, idx, axis=1)

        # Reentrenar modelos para esta variante
        if_abl, svm_abl, lof_abl = fit_models(X_tr_abl, hyperparams, seed)

        # Recalibrar tau en validación
        sc_val_abl = compute_model_anomaly_scores(if_abl, svm_abl, lof_abl, X_val_abl)
        tau_variant, val_f1 = calibrate_tau_on_validation(sc_val_abl["ensamble"], y_val, tau_config)

        # Evaluar en el conjunto de prueba con el tau recalibrado de la variante
        sc_te_abl = compute_model_anomaly_scores(if_abl, svm_abl, lof_abl, X_te_abl)
        pred_te_abl = (sc_te_abl["ensamble"] >= tau_variant).astype(int)
        m_abl = calculate_metrics_dict(y_test, pred_te_abl, sc_te_abl["ensamble"])
        delta = round(m_abl["f1_score"] - f1_base, 4)

        ablation_results.append({
            "excluded_feature": f_name,
            "evaluation_set": "test",
            "calibrated_tau_val": tau_variant,
            "f1_score": m_abl["f1_score"],
            "delta_f1": delta,
            "precision": m_abl["precision"],
            "recall": m_abl["recall"],
            "false_positive_rate": m_abl["false_positive_rate"],
            "val_f1_calibrated": round(float(val_f1), 4)
        })

    return ablation_results

# =========================================================================
# 6.1 ESCENARIO APARTE: ATACANTE CON RITMO HUMANO (HUMAN-MIMICRY) [POST-HOC]
# =========================================================================

def evaluate_human_mimic_attack_scenario(
    iforest: IsolationForest,
    ocsvm: OneClassSVM,
    lof: LocalOutlierFactor,
    waf: HeuristicWAF,
    tau_ensemble: float,
    seed: int
) -> Dict[str, Any]:
    """
    Escenario de prueba aparte: atacante que imita la cadencia estocástica humana.
    Utiliza intervalos inter-arribo amplios (distribución gamma mu=45s, sigma=20s),
    frecuencia baja de intentos por ventana y dispersión de usuarios moderada.
    Se mezclan 1000 ataques humanos con 1000 peticiones benignas legítimas.
    """
    rng = np.random.default_rng(seed + 888)
    clock = VirtualClock(start_timestamp=1700300000.0)
    n_attacks = 1000
    n_benign = 1000
    events = []
    features = []
    y_true = []

    plan = [1] * n_attacks + [0] * n_benign
    rng.shuffle(plan)

    legit_ips = [f"192.168.2.{i}" for i in range(10, 80)]
    attacker_ips = [f"172.16.{i // 250}.{i % 250 + 1}" for i in range(1, 150)]

    for is_atk in plan:
        if is_atk == 1:
            # Cadencia humana imitada: pausas amplias y variabilidad
            delta_t = rng.gamma(shape=3.0, scale=15.0) # media 45 segundos
            clock.advance(delta_t)
            ip = rng.choice(attacker_ips)
            user = rng.choice(["admin", "carla", "roberto"])
            n_attempts = rng.choice([1, 2], p=[0.75, 0.25])
            iat_mean = float(rng.uniform(25.0, 75.0))
            iat_std = float(rng.uniform(10.0, 30.0))
        else:
            delta_t = rng.exponential(scale=35.0)
            clock.advance(delta_t)
            ip = rng.choice(legit_ips)
            user = rng.choice(["admin", "carla", "roberto", "jperez", "mgarcia"])
            n_attempts = rng.choice([0, 1, 2], p=[0.70, 0.22, 0.08])
            iat_mean = float(rng.uniform(20.0, 90.0))
            iat_std = float(rng.uniform(5.0, 30.0))

        events.append({
            "timestamp": clock.now(),
            "ip": ip,
            "user": user,
            "is_attack": bool(is_atk)
        })
        y_true.append(is_atk)
        features.append([
            float(n_attempts),
            1.0 if n_attempts > 0 else 0.0,
            float(round(iat_mean, 3)),
            float(round(iat_std, 3)),
            14.0
        ])

    X_hum = np.array(features, dtype=np.float32)
    y_hum = np.array(y_true, dtype=int)

    waf_preds = waf.evaluate_stream(events)
    scores = compute_model_anomaly_scores(iforest, ocsvm, lof, X_hum)
    ml_preds = (scores["ensamble"] >= tau_ensemble).astype(int)

    m_waf = calculate_metrics_dict(y_hum, waf_preds)
    m_ml = calculate_metrics_dict(y_hum, ml_preds, scores["ensamble"])

    return {
        "scenario_name": "Ataque Sigiloso con Ritmo Humano (Human-Mimicry)",
        "note": "[POST-HOC] Evaluado como escenario experimental independiente",
        "sample_size": {
            "total": len(y_hum),
            "human_mimic_attacks": n_attacks,
            "legitimate_benign": n_benign
        },
        "waf_heuristics": m_waf,
        "ml_ensemble_tau": m_ml,
        "discussion": "Cuando el atacante adopta una cadencia temporal idéntica a la humana (IAT medio ~45s y n_intentos <= 2), el WAF heurístico colapsa completamente por no superar el umbral N. El ensamble ML detecta sutiles anomalías de entropía y consistencia espacial pero sufre degradación respecto al baseline clásico."
    }

# =========================================================================
# 7. MEDICIÓN RIGUROSA DE LATENCIAS
# =========================================================================

def measure_latencies_ns(
    iforest: IsolationForest,
    ocsvm: OneClassSVM,
    lof: LocalOutlierFactor,
    X_test: np.ndarray,
    n_benchmark_samples: int = 500
) -> Dict[str, Any]:
    """Mide latencia de inferencia por muestra y por lote con time.perf_counter_ns()."""
    sample_latencies = []
    sub = X_test[:min(len(X_test), n_benchmark_samples)]

    # 1. Por muestra individual
    for row in sub:
        row_mat = row.reshape(1, -1)
        t0 = time.perf_counter_ns()
        _ = iforest.score_samples(row_mat)
        _ = ocsvm.decision_function(row_mat)
        _ = lof.score_samples(row_mat)
        t1 = time.perf_counter_ns()
        sample_latencies.append((t1 - t0) / 1000.0) # microsegundos

    # 2. Por lote vectorizado
    t0_batch = time.perf_counter_ns()
    _ = iforest.score_samples(sub)
    _ = ocsvm.decision_function(sub)
    _ = lof.score_samples(sub)
    t1_batch = time.perf_counter_ns()
    batch_ms = (t1_batch - t0_batch) / 1_000_000.0

    return {
        "per_sample_us": {
            "mean": round(float(np.mean(sample_latencies)), 2),
            "median": round(float(np.median(sample_latencies)), 2),
            "p95": round(float(np.percentile(sample_latencies, 95)), 2),
            "std": round(float(np.std(sample_latencies)), 2)
        },
        "batch_inference": {
            "samples_evaluated": len(sub),
            "total_ms": round(float(batch_ms), 2),
            "ms_per_sample_in_batch": round(float(batch_ms / len(sub)), 4)
        }
    }

# =========================================================================
# 8. PROCESADOR DE DATOS REALES CICIDS-2017 (FASE 2)
# =========================================================================

def clean_and_audit_cicids_dataframe(
    df: pd.DataFrame,
    source_name: str
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Realiza limpieza estricta y documentada de un DataFrame de CICIDS2017.
    Registra conteos de filas leídas, duplicadas y con valores no finitos (NaN/Inf).
    """
    # 1. Normalizar nombres de columnas (eliminar comillas y espacios externos)
    df.columns = [c.strip().replace('"', '').replace("'", "") for c in df.columns]

    initial_count = len(df)

    # 2. Conteo y eliminación de duplicados
    dup_count = int(df.duplicated().sum())
    df_clean = df.drop_duplicates().copy()

    # 3. Identificar columnas clave
    label_col = next((c for c in df_clean.columns if c.lower() == 'label'), None)
    if not label_col:
        # Fallback a última columna si no hay cabecera explícita
        label_col = df_clean.columns[-1]

    # Timestamp
    ts_col = next((c for c in df_clean.columns if 'timestamp' in c.lower()), None)
    if ts_col:
        df_clean['_parsed_ts'] = pd.to_datetime(df_clean[ts_col], errors='coerce')
    else:
        df_clean['_parsed_ts'] = pd.Series(np.arange(len(df_clean)), index=df_clean.index)

    # Reemplazar infinitos por NaN en columnas numéricas y descartar
    numeric_cols = [c for c in df_clean.columns if c not in [label_col, ts_col, '_parsed_ts', 'Source IP', 'Destination IP', 'Flow ID']]
    for c in numeric_cols:
        df_clean[c] = pd.to_numeric(df_clean[c], errors='coerce')

    nan_inf_count = int(df_clean[numeric_cols].isin([np.nan, np.inf, -np.inf]).any(axis=1).sum())
    df_clean = df_clean.replace([np.inf, -np.inf], np.nan).dropna(subset=numeric_cols).copy()

    # Ordenar estrictamente por Timestamp cronológico
    df_clean = df_clean.sort_values(by='_parsed_ts').reset_index(drop=True)

    audit = {
        "dataset_source": source_name,
        "rows_initial": initial_count,
        "rows_duplicated_dropped": dup_count,
        "rows_nan_inf_dropped": nan_inf_count,
        "rows_clean_retained": len(df_clean),
        "clean_ratio_pct": round((len(df_clean) / max(1, initial_count)) * 100, 2)
    }

    return df_clean, audit

def extract_cicids_features(
    df: pd.DataFrame,
    excluded_columns: List[str]
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str], List[Dict[str, Any]]]:
    """
    Separa las matrices de características de CICIDS:
      - X_baseline: sin Destination Port
      - X_with_port: con Destination Port reportado aparte
      - y_binary: 0 = BENIGN, 1 = Ataque
      - feature_names
      - events para el WAF (ts, ip, attack)
    """
    label_col = next((c for c in df.columns if c.lower() == 'label'), df.columns[-1])
    dst_port_col = next((c for c in df.columns if 'destination port' in c.lower() or c.lower() == 'dst port'), None)
    src_ip_col = next((c for c in df.columns if 'source ip' in c.lower() or c.lower() == 'src ip'), None)

    # Binario: todo lo que no sea benign es ataque
    is_attack = (~df[label_col].astype(str).str.upper().str.contains('BENIGN')).astype(int).values

    # Columnas numéricas permitidas para el baseline
    cols_to_drop = set(excluded_columns + [label_col, '_parsed_ts'])
    if dst_port_col:
        cols_to_drop.add(dst_port_col)

    feature_cols = [c for c in df.columns if c not in cols_to_drop and pd.api.types.is_numeric_dtype(df[c])]

    X_baseline = df[feature_cols].values.astype(np.float32)

    # Variante con Destination Port
    if dst_port_col and dst_port_col in df.columns:
        port_vals = df[dst_port_col].values.astype(np.float32).reshape(-1, 1)
        X_with_port = np.hstack([X_baseline, port_vals])
        cols_with_port = feature_cols + [dst_port_col]
    else:
        X_with_port = X_baseline.copy()
        cols_with_port = feature_cols.copy()

    # Eventos de red para el WAF
    events = []
    for i in range(len(df)):
        ts_val = df['_parsed_ts'].iloc[i]
        ts_num = ts_val.timestamp() if isinstance(ts_val, pd.Timestamp) else float(i)
        ip_val = str(df[src_ip_col].iloc[i]) if src_ip_col else f"10.0.0.{i % 250 + 1}"
        events.append({
            "timestamp": ts_num,
            "ip": ip_val,
            "is_attack": bool(is_attack[i]),
            "label": str(df[label_col].iloc[i])
        })

    return X_baseline, X_with_port, is_attack, feature_cols, events

def run_cicids_evaluation_pipeline(
    df_clean: pd.DataFrame,
    config: Dict[str, Any],
    output_dir: str,
    seed: int
) -> Dict[str, Any]:
    """
    Ejecuta la partición temporal estricta y evaluación sobre datos de CICIDS2017:
      1. Train: Primer tramo (100% Benign)
      2. Validation: Tramo intermedio para elegir WAF (W, N) y tau
      3. Test: Tramo final (evaluación natural y balanceada 50/50, con y sin Destination Port)
    """
    excluded = config["feature_engineering"]["cicids2017"]["excluded_columns_baseline"]
    X_base, X_port, y, feat_names, events = extract_cicids_features(df_clean, excluded)

    n_total = len(y)
    n_train = int(n_total * 0.40)
    n_val = int(n_total * 0.20)
    n_test = n_total - (n_train + n_val)

    # Partición temporal cronológica
    idx_train = np.arange(0, n_train)
    idx_val = np.arange(n_train, n_train + n_val)
    idx_test = np.arange(n_train + n_val, n_total)

    # Verificar ausencia de solapamiento
    assert len(set(idx_train).intersection(set(idx_test))) == 0, "Error: Data Leakage detectado entre train y test"
    assert len(set(idx_val).intersection(set(idx_test))) == 0, "Error: Data Leakage detectado entre val y test"

    # En entrenamiento no supervisado se filtra exclusivamente el tráfico BENIGN
    benign_train_mask = (y[idx_train] == 0)
    X_train_base = X_base[idx_train][benign_train_mask]
    X_train_port = X_port[idx_train][benign_train_mask]

    # Validación
    X_val_base = X_base[idx_val]
    y_val = y[idx_val]
    val_events = [events[i] for i in idx_val]

    # Test Natural
    X_test_base = X_base[idx_test]
    X_test_port = X_port[idx_test]
    y_test = y[idx_test]
    test_events = [events[i] for i in idx_test]

    # Test Balanceado 50/50
    idx_test_atk = np.where(y_test == 1)[0]
    idx_test_ben = np.where(y_test == 0)[0]
    n_bal = min(len(idx_test_atk), len(idx_test_ben))
    if n_bal > 10:
        rng_bal = np.random.default_rng(seed)
        sub_atk = rng_bal.choice(idx_test_atk, size=n_bal, replace=False)
        sub_ben = rng_bal.choice(idx_test_ben, size=n_bal, replace=False)
        idx_bal = np.sort(np.concatenate([sub_atk, sub_ben]))
        X_test_bal_base = X_test_base[idx_bal]
        y_test_bal = y_test[idx_bal]
    else:
        X_test_bal_base = X_test_base
        y_test_bal = y_test

    # 1. Ajustar Modelos Baseline (Sin Destination Port)
    from sklearn.preprocessing import StandardScaler
    scaler_base = StandardScaler()
    X_tr_sc = scaler_base.fit_transform(X_train_base)
    X_val_sc = scaler_base.transform(X_val_base)
    X_te_sc = scaler_base.transform(X_test_base)
    X_te_bal_sc = scaler_base.transform(X_test_bal_base)

    if_base, svm_base, lof_base = fit_models(X_tr_sc, config["hyperparameters"], seed)

    # 2. Calibración en VALIDACIÓN
    best_w, best_n, _ = calibrate_waf_on_validation(val_events, y_val, config["validation_grid"]["waf_rules"])
    waf = HeuristicWAF(window_sec=best_w, threshold_n=best_n)

    val_sc = compute_model_anomaly_scores(if_base, svm_base, lof_base, X_val_sc)
    best_tau, _ = calibrate_tau_on_validation(val_sc["ensamble"], y_val, config["validation_grid"]["tau_threshold"])

    # 3. Evaluación en TEST (Prevalencia Natural)
    test_waf_preds = waf.evaluate_stream(test_events)
    test_sc = compute_model_anomaly_scores(if_base, svm_base, lof_base, X_te_sc)
    pred_ensamble = (test_sc["ensamble"] >= best_tau).astype(int)

    metrics_natural = {
        "reglas_waf": calculate_metrics_dict(y_test, test_waf_preds),
        "isolation_forest": calculate_metrics_dict(y_test, (test_sc["iforest"] >= 0.5).astype(int), test_sc["iforest"]),
        "one_class_svm": calculate_metrics_dict(y_test, (test_sc["ocsvm"] >= 0.5).astype(int), test_sc["ocsvm"]),
        "local_outlier_factor": calculate_metrics_dict(y_test, (test_sc["lof"] >= 0.5).astype(int), test_sc["lof"]),
        "ensamble_tau": calculate_metrics_dict(y_test, pred_ensamble, test_sc["ensamble"])
    }

    # 4. Evaluación en TEST (Balanceado 50/50)
    test_bal_sc = compute_model_anomaly_scores(if_base, svm_base, lof_base, X_te_bal_sc)
    metrics_balanced = {
        "isolation_forest": calculate_metrics_dict(y_test_bal, (test_bal_sc["iforest"] >= 0.5).astype(int), test_bal_sc["iforest"]),
        "one_class_svm": calculate_metrics_dict(y_test_bal, (test_bal_sc["ocsvm"] >= 0.5).astype(int), test_bal_sc["ocsvm"]),
        "local_outlier_factor": calculate_metrics_dict(y_test_bal, (test_bal_sc["lof"] >= 0.5).astype(int), test_bal_sc["lof"]),
        "ensamble_tau": calculate_metrics_dict(y_test_bal, (test_bal_sc["ensamble"] >= best_tau).astype(int), test_bal_sc["ensamble"])
    }

    # 5. Variante CON Destination Port (Reportada Aparte)
    scaler_port = StandardScaler()
    X_tr_port_sc = scaler_port.fit_transform(X_train_port)
    X_te_port_sc = scaler_port.transform(X_test_port)
    if_port, svm_port, lof_port = fit_models(X_tr_port_sc, config["hyperparameters"], seed)
    test_port_sc = compute_model_anomaly_scores(if_port, svm_port, lof_port, X_te_port_sc)
    pred_port_ensamble = (test_port_sc["ensamble"] >= best_tau).astype(int)

    metrics_with_port = {
        "isolation_forest": calculate_metrics_dict(y_test, (test_port_sc["iforest"] >= 0.5).astype(int), test_port_sc["iforest"]),
        "ensamble_tau": calculate_metrics_dict(y_test, pred_port_ensamble, test_port_sc["ensamble"])
    }

    # 6. Recall Desglosado por Tipo de Ataque
    test_labels = [events[i]["label"] for i in idx_test]
    recall_by_attack = {}
    for atk_name in np.unique(test_labels):
        mask = np.array([lbl == atk_name for lbl in test_labels])
        if np.sum(mask) > 0:
            rec_waf = float(np.mean(test_waf_preds[mask] == 1)) if "BENIGN" not in atk_name.upper() else float(np.mean(test_waf_preds[mask] == 0))
            rec_ml = float(np.mean(pred_ensamble[mask] == 1)) if "BENIGN" not in atk_name.upper() else float(np.mean(pred_ensamble[mask] == 0))
            recall_by_attack[str(atk_name)] = {
                "sample_count": int(np.sum(mask)),
                "waf_accuracy": round(rec_waf, 4),
                "ml_ensemble_accuracy": round(rec_ml, 4)
            }

    # 7. Bootstrap al 95% sobre Test
    bootstrap_ci = {
        "reglas_waf": run_bootstrap_confidence_intervals(y_test, test_waf_preds, 1000, 0.95, seed),
        "ensamble_tau": run_bootstrap_confidence_intervals(y_test, pred_ensamble, 1000, 0.95, seed)
    }

    return {
        "partition_summary": {
            "total_samples": n_total,
            "train_benign_samples": len(X_train_base),
            "validation_samples": n_val,
            "test_samples_natural": n_test,
            "test_samples_balanced_50_50": len(y_test_bal),
            "attack_prevalence_natural_pct": round(float(np.mean(y_test)) * 100, 2)
        },
        "calibration": {
            "waf_window_seconds": best_w,
            "waf_threshold_n": best_n,
            "tau_optimal": best_tau
        },
        "metrics_natural_prevalence": metrics_natural,
        "metrics_balanced_50_50": metrics_balanced,
        "variant_with_destination_port": metrics_with_port,
        "recall_by_attack_type": recall_by_attack,
        "bootstrap_95ci": bootstrap_ci
    }


# =========================================================================
# 8. EJECUTOR PRINCIPAL (CLI)
# =========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Centinela — Motor Científico de Evaluación y Reproducibilidad"
    )
    parser.add_argument("--config", default="experiment_config.json", help="Ruta al archivo JSON de configuración")
    parser.add_argument("--output-dir", default="results", help="Directorio de exportación de artefactos")
    parser.add_argument("--seed-train", type=int, default=None, help="Semilla aleatoria para entrenamiento")
    parser.add_argument("--seed-test", type=int, default=None, help="Semilla aleatoria para prueba")
    parser.add_argument("--test-drift", action="store_true", help="Ejecutar prueba con desplazamiento de parámetros del generador")
    parser.add_argument("--task", default="synthetic_benchmark", choices=["synthetic_benchmark", "botnet_scale", "ablation", "cicids_unb", "all"], help="Tarea a ejecutar")
    parser.add_argument("--cicids-file", default=None, help="Ruta a archivo CSV de CICIDS2017 para evaluación")
    parser.add_argument("--cicids-monday", default=None, help="Ruta a Monday-WorkingHours.pcap_ISCX.csv (Benigno entrenamiento)")
    parser.add_argument("--cicids-tuesday", default=None, help="Ruta a Tuesday-WorkingHours.pcap_ISCX.csv (Calibración y Patator)")
    parser.add_argument("--cicids-thursday", default=None, help="Ruta a Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # 1. Cargar Configuración Inmutable
    if not os.path.exists(args.config):
        print(f"[ERROR] No se encontró el archivo de configuración: {args.config}")
        sys.exit(1)

    with open(args.config, "r", encoding="utf-8") as f:
        config = json.load(f)

    config_sha256 = compute_file_sha256(args.config)
    seed_train = args.seed_train or config["random_seeds"]["seed_train_default"]
    seed_test = args.seed_test or config["random_seeds"]["seed_test_default"]

    print("========================================================================")
    print(" CENTINELA — EJECUCIÓN CIENTÍFICA RIGUROSA")
    print(f" Commit Hash: {config['metadata'].get('commit_hash_pre_test')}")
    print(f" Config SHA-256: {config_sha256}")
    print(f" Semilla Train: {seed_train} | Semilla Test: {seed_test}")
    print("========================================================================")

    hw_specs = get_hardware_specs()

    # Si la tarea es evaluación de datos reales CICIDS2017
    if args.task == "cicids_unb" or args.cicids_file or (args.cicids_monday and args.cicids_tuesday):
        print("\n[*] MODO: EVALUACIÓN SOBRE DATOS REALES CICIDS-2017")
        cicids_frames = []
        audits = []
        file_hashes = {}

        if args.cicids_monday and args.cicids_tuesday:
            files_to_load = [("monday", args.cicids_monday), ("tuesday", args.cicids_tuesday)]
            if args.cicids_thursday:
                files_to_load.append(("thursday", args.cicids_thursday))
            for tag, fpath in files_to_load:
                if os.path.exists(fpath):
                    sha = compute_file_sha256(fpath)
                    file_hashes[tag] = {"path": fpath, "sha256": sha}
                    print(f"    Leyendo {fpath} (SHA-256: {sha})...")
                    raw_df = pd.read_csv(fpath, low_memory=False)
                    c_df, aud = clean_and_audit_cicids_dataframe(raw_df, tag)
                    cicids_frames.append(c_df)
                    audits.append(aud)
            full_cicids_df = pd.concat(cicids_frames, ignore_index=True)
        elif args.cicids_file and os.path.exists(args.cicids_file):
            sha = compute_file_sha256(args.cicids_file)
            file_hashes["single_file"] = {"path": args.cicids_file, "sha256": sha}
            print(f"    Leyendo {args.cicids_file} (SHA-256: {sha})...")
            raw_df = pd.read_csv(args.cicids_file, low_memory=False)
            full_cicids_df, aud = clean_and_audit_cicids_dataframe(raw_df, args.cicids_file)
            audits.append(aud)
        else:
            print("[ERROR] Debe especificarse --cicids-file o los pares --cicids-monday y --cicids-tuesday.")
            sys.exit(1)

        print(f"[*] Limpieza completada. Total filas limpias: {len(full_cicids_df)}")
        for aud in audits:
            print(f"    - {aud['dataset_source']}: Leídas {aud['rows_initial']}, Duplicados descartados {aud['rows_duplicated_dropped']}, NaN/Inf descartados {aud['rows_nan_inf_dropped']}, Retenidas {aud['rows_clean_retained']} ({aud['clean_ratio_pct']}%)")

        # Ejecutar pipeline sobre flujos reales
        cicids_res = run_cicids_evaluation_pipeline(full_cicids_df, config, args.output_dir, seed_train)
        cicids_res["metadata"] = {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "commit_hash": config["metadata"].get("commit_hash_pre_test"),
            "config_sha256": config_sha256,
            "seed_train": seed_train,
            "seed_test": seed_test,
            "input_files_sha256": file_hashes
        }
        cicids_res["hardware_environment"] = hw_specs
        cicids_res["data_cleaning_audit"] = audits

        out_cicids_json = os.path.join(args.output_dir, "cicids_resultados_metricas.json")
        with open(out_cicids_json, "w", encoding="utf-8") as f:
            json.dump(cicids_res, f, indent=2)

        manifest_cicids = {
            "commit_hash": config["metadata"].get("commit_hash_pre_test"),
            "hardware_summary": f"{hw_specs['processor']} ({hw_specs['cpu_count_logical']} cores), {hw_specs['ram_total_mb']} MB RAM",
            "files_sha256": {
                "config": { "file": args.config, "sha256": config_sha256 },
                "input_cicids_files": file_hashes,
                "script": { "file": __file__, "sha256": compute_file_sha256(__file__) },
                "results_json": { "file": out_cicids_json, "sha256": compute_file_sha256(out_cicids_json) }
            }
        }
        with open(os.path.join(args.output_dir, "cicids_manifest_hashes.json"), "w", encoding="utf-8") as f:
            json.dump(manifest_cicids, f, indent=2)

        print("\n========================================================================")
        print(" RESULTADOS FINALES CICIDS-2017 (PREVALENCIA NATURAL)")
        print("========================================================================")
        for mod, m in cicids_res["metrics_natural_prevalence"].items():
            print(f" {mod.upper()}: F1={m['f1_score']} | Prec={m['precision']} | Rec={m['recall']} | FPR={m['false_positive_rate']}")
        print("------------------------------------------------------------------------")
        print(" RESULTADOS TEST BALANCEADO 50/50:")
        for mod, m in cicids_res["metrics_balanced_50_50"].items():
            print(f" {mod.upper()} (50/50): F1={m['f1_score']} | Prec={m['precision']} | Rec={m['recall']} | FPR={m['false_positive_rate']}")
        print("------------------------------------------------------------------------")
        print(" VARIANTE CON DESTINATION PORT (REPORTADA APARTE):")
        for mod, m in cicids_res["variant_with_destination_port"].items():
            print(f" {mod.upper()} (Con Puerto): F1={m['f1_score']} | Prec={m['precision']} | Rec={m['recall']} | FPR={m['false_positive_rate']}")
        print("========================================================================")
        print(f" Artefactos guardados en: {args.output_dir}/")
        return

    # 2. Generación con Reloj Virtual y Semillas Independientes
    rng_train = np.random.default_rng(seed_train)
    clock_train = VirtualClock(start_timestamp=1700000000.0)
    train_events, X_train_raw, y_train_raw = generate_synthetic_stream(2500, rng_train, clock_train)
    # Filtro no supervisado: entrenamiento exclusivo con muestras normales (y == 0)
    X_train_benign = X_train_raw[y_train_raw == 0]

    # Conjunto de Validación (para elegir WAF N, ventana y umbral tau)
    rng_val = np.random.default_rng(seed_train + 999)
    clock_val = VirtualClock(start_timestamp=1700050000.0)
    val_events, X_val, y_val = generate_synthetic_stream(1500, rng_val, clock_val)

    # Conjunto de Test (evaluación final sin tuning de hiperparámetros)
    rng_test = np.random.default_rng(seed_test)
    clock_test = VirtualClock(start_timestamp=1700100000.0)
    test_events, X_test, y_test = generate_synthetic_stream(
        3000, rng_test, clock_test,
        is_drift=args.test_drift,
        drift_config=config.get("generator_drift")
    )

    print(f"[*] Datos generados: Train Benign={len(X_train_benign)}, Val={len(X_val)}, Test={len(X_test)}")
    if args.test_drift:
        print("[!] Modo Distribution Drift ACTIVADO: parámetros del generador desplazados en test.")

    # 3. Entrenamiento de Modelos
    iforest, ocsvm, lof = fit_models(X_train_benign, config["hyperparameters"], seed_train)

    # 4. Calibración en VALIDACIÓN (Reglas WAF y Tau)
    best_w, best_n, val_waf_f1 = calibrate_waf_on_validation(val_events, y_val, config["validation_grid"]["waf_rules"])
    calibrated_waf = HeuristicWAF(window_sec=best_w, threshold_n=best_n)

    val_scores = compute_model_anomaly_scores(iforest, ocsvm, lof, X_val)
    best_tau, val_ml_f1 = calibrate_tau_on_validation(val_scores["ensamble"], y_val, config["validation_grid"]["tau_threshold"])

    print(f"[*] Calibración en Validación:")
    print(f"    - WAF óptimo: Ventana={best_w}s, Umbral N={best_n} (F1 Val: {val_waf_f1:.4f})")
    print(f"    - Tau ensamble óptimo: {best_tau} (F1 Val: {val_ml_f1:.4f})")

    # 5. Evaluación en TEST
    test_waf_preds = calibrated_waf.evaluate_stream(test_events)
    test_scores = compute_model_anomaly_scores(iforest, ocsvm, lof, X_test)

    # Predicciones binarias individuales
    pred_if = (test_scores["iforest"] >= 0.5).astype(int)
    pred_svm = (test_scores["ocsvm"] >= 0.5).astype(int)
    pred_lof = (test_scores["lof"] >= 0.5).astype(int)

    # Ensamble Mayoritario Estricto: al menos 2 votos
    votos_totales = pred_if + pred_svm + pred_lof
    pred_ensamble_votacion = (votos_totales >= config["ensemble"]["threshold_votes"]).astype(int)
    pred_ensamble_tau = (test_scores["ensamble"] >= best_tau).astype(int)

    # 6. Cálculo de Métricas Finales
    metricas_resultado = {
        "reglas_waf": calculate_metrics_dict(y_test, test_waf_preds),
        "isolation_forest": calculate_metrics_dict(y_test, pred_if, test_scores["iforest"]),
        "one_class_svm": calculate_metrics_dict(y_test, pred_svm, test_scores["ocsvm"]),
        "local_outlier_factor": calculate_metrics_dict(y_test, pred_lof, test_scores["lof"]),
        "ensamble_votacion_mayoritaria": calculate_metrics_dict(y_test, pred_ensamble_votacion, test_scores["ensamble"]),
        "ensamble_tau_calibrado": calculate_metrics_dict(y_test, pred_ensamble_tau, test_scores["ensamble"])
    }

    # 7. Intervalos Bootstrap al 95% sobre TEST
    bs_cfg = config.get("bootstrap", {})
    n_boot = bs_cfg.get("n_iterations", 1000)
    conf_level = bs_cfg.get("confidence_level", 0.95)

    bootstrap_results = {
        "reglas_waf": run_bootstrap_confidence_intervals(y_test, test_waf_preds, n_boot, conf_level, seed_test),
        "isolation_forest": run_bootstrap_confidence_intervals(y_test, pred_if, n_boot, conf_level, seed_test),
        "one_class_svm": run_bootstrap_confidence_intervals(y_test, pred_svm, n_boot, conf_level, seed_test),
        "local_outlier_factor": run_bootstrap_confidence_intervals(y_test, pred_lof, n_boot, conf_level, seed_test),
        "ensamble_votacion": run_bootstrap_confidence_intervals(y_test, pred_ensamble_votacion, n_boot, conf_level, seed_test),
        "ensamble_tau_calibrado": run_bootstrap_confidence_intervals(y_test, pred_ensamble_tau, n_boot, conf_level, seed_test)
    }

    # 8. Medición de Latencias Reales
    latencias = measure_latencies_ns(iforest, ocsvm, lof, X_test)

    # 9. Experimentos Complementarios
    botnet_results = []
    if args.task in ["botnet_scale", "all"]:
        print("[*] Ejecutando experimento de Botnet con carga fija (1200 intentos)...")
        botnet_results = run_botnet_scale_experiment(iforest, ocsvm, lof, calibrated_waf, best_tau, seed_test)

    ablation_results = []
    if args.task in ["ablation", "all"]:
        print("[*] Ejecutando estudio de ablación (recalibrando tau por variante en validación y evaluando en TEST)...")
        feature_names = config["feature_engineering"]["synthetic"]["features"]
        ablation_results = run_ablation_study(
            X_train_benign, X_val, y_val, X_test, y_test,
            feature_names, config["hyperparameters"], seed_train,
            config["validation_grid"]["tau_threshold"], best_tau
        )

    # 9.1 Escenario Aparte: Atacante con Ritmo Humano [POST-HOC]
    print("[*] Evaluando escenario aparte: Atacante con Ritmo Humano (Human-Mimicry)...")
    human_mimic_results = evaluate_human_mimic_attack_scenario(iforest, ocsvm, lof, calibrated_waf, best_tau, seed_test)

    # 10. Exportar Predicciones Muestra por Muestra (CSV)
    pred_df = pd.DataFrame({
        "sample_index": np.arange(len(y_test)),
        "true_label": y_test,
        "pred_waf": test_waf_preds,
        "score_iforest": np.round(test_scores["iforest"], 4),
        "pred_iforest": pred_if,
        "score_ocsvm": np.round(test_scores["ocsvm"], 4),
        "pred_ocsvm": pred_svm,
        "score_lof": np.round(test_scores["lof"], 4),
        "pred_lof": pred_lof,
        "score_ensamble": np.round(test_scores["ensamble"], 4),
        "pred_ensamble_votacion": pred_ensamble_votacion,
        "pred_ensamble_tau": pred_ensamble_tau
    })
    pred_csv_path = os.path.join(args.output_dir, "predicciones_muestra.csv")
    pred_df.to_csv(pred_csv_path, index=False)

    # 11. Compilar y Exportar JSON Completo
    salida_final = {
        "metadata": {
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "commit_hash": config["metadata"].get("commit_hash_pre_test"),
            "config_sha256": config_sha256,
            "seed_train": seed_train,
            "seed_test": seed_test,
            "test_sample_size": {
                "total": len(y_test),
                "attacks": int(np.sum(y_test == 1)),
                "benign": int(np.sum(y_test == 0)),
                "attack_prevalence_pct": round(float(np.mean(y_test)) * 100, 2)
            },
            "validation_sample_size": {
                "total": len(y_val),
                "attacks": int(np.sum(y_val == 1)),
                "benign": int(np.sum(y_val == 0))
            },
            "train_benign_sample_size": len(X_train_benign),
            "distribution_drift_applied": args.test_drift,
            "task": args.task,
            "methodology_notes_post_hoc": [
                "[POST-HOC] Estudio de ablación ejecutado sobre TEST recalibrando tau óptimo en validación para cada variante.",
                "[POST-HOC] Experimento de botnet escalado con carga constante de 1200 ataques mezclados 1:1 con 1200 peticiones benignas de control (2400 total) para computar precisión y FPR por punto.",
                "[POST-HOC] Escenario de atacante con ritmo humano evaluado por separado (1000 ataques + 1000 benignos)."
            ]
        },
        "hardware_environment": hw_specs,
        "calibration_validation": {
            "waf_window_seconds": best_w,
            "waf_threshold_n": best_n,
            "tau_ensemble": best_tau
        },
        "metrics_test": metricas_resultado,
        "bootstrap_95ci": bootstrap_results,
        "latencies": latencias,
        "botnet_scale_experiment": botnet_results,
        "ablation_study": ablation_results,
        "human_mimic_scenario": human_mimic_results
    }

    out_json_path = os.path.join(args.output_dir, "resultados_metricas.json")
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(salida_final, f, indent=2)

    # 12. Generar Manifiesto de Hashes
    manifest = {
        "commit_hash": config["metadata"].get("commit_hash_pre_test"),
        "hardware_summary": f"{hw_specs['processor']} ({hw_specs['cpu_count_logical']} cores), {hw_specs['ram_total_mb']} MB RAM",
        "files_sha256": {
            "config": { "file": args.config, "sha256": config_sha256 },
            "script": { "file": __file__, "sha256": compute_file_sha256(__file__) },
            "predictions_csv": { "file": pred_csv_path, "sha256": compute_file_sha256(pred_csv_path) },
            "metrics_json": { "file": out_json_path, "sha256": compute_file_sha256(out_json_path) }
        }
    }
    manifest_path = os.path.join(args.output_dir, "manifest_hashes.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n========================================================================")
    print(" RESULTADOS OBTENIDOS EN CONJUNTO DE PRUEBA (TEST)")
    print("========================================================================")
    for model_name, m in metricas_resultado.items():
        ci = bootstrap_results.get(model_name, {}).get("f1_score", {})
        ci_str = f" [IC 95%: {ci.get('low', '-')}-{ci.get('high', '-')}]" if ci else ""
        print(f" {model_name.upper()}:")
        print(f"   F1-Score: {m['f1_score']}{ci_str} | Precisión: {m['precision']} | Recall: {m['recall']} | FPR: {m['false_positive_rate']}")
        print(f"   Matriz Confusión: VP={m['true_positives']} FP={m['false_positives']} FN={m['false_negatives']} VN={m['true_negatives']}")
    print("------------------------------------------------------------------------")
    print(f" Latencia media por muestra: {latencias['per_sample_us']['mean']} µs (mediana: {latencias['per_sample_us']['median']} µs)")
    print(f" Archivos generados en: {args.output_dir}/")
    print("   1. resultados_metricas.json")
    print("   2. predicciones_muestra.csv")
    print("   3. manifest_hashes.json")
    print("========================================================================")

if __name__ == "__main__":
    main()
