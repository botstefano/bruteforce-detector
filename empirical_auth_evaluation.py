#!/usr/bin/env python3
"""
Evaluate real authentication events captured by Centinela.

This script does not generate events, users, attack records, timestamps, or labels.
It reads the CSV export from /api/dataset/capturado?formato=csv, reconstructs a
benign-only training baseline, fits scikit-learn novelty detectors, calibrates
thresholds on the temporal validation split, and evaluates once on the test split.

Python 3.10+
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


FEATURE_SCHEMA = "centinela-auth-features-v2"
FEATURE_COUNT = 5
WINDOW_SECONDS = 120.0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def parse_features(value: Any) -> np.ndarray:
    """Parse the Postgres float8[] CSV representation, e.g. {1,2,3,4,5}."""
    if isinstance(value, (list, tuple, np.ndarray)):
        raw = list(value)
    else:
        text = str(value or "").strip()
        if text.startswith("{") and text.endswith("}"):
            text = text[1:-1]
        elif text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        raw = [part.strip().strip('"') for part in text.split(",") if part.strip()]
    vector = np.asarray([float(item) for item in raw], dtype=np.float64)
    if vector.shape != (FEATURE_COUNT,) or not np.isfinite(vector).all():
        raise ValueError(f"Vector de características inválido: se esperaban {FEATURE_COUNT} números finitos.")
    return vector


def parse_timestamp(value: Any) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def js_round_two(value: float) -> float:
    # Match Math.round(value * 100) / 100 for non-negative feature values.
    return math.floor(value * 100.0 + 0.5) / 100.0


def build_benign_training_baseline(rows: list[dict[str, Any]]) -> np.ndarray:
    """
    Reconstruct features using only independently labeled benign training events.
    This avoids training contamination where a benign row's original live window
    included an attack that was identified and labeled only later.
    """
    ordered = sorted(rows, key=lambda row: row["_timestamp"])
    history: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
    vectors: list[list[float]] = []

    for row in ordered:
        timestamp = row["_timestamp"].timestamp()
        source = str(row.get("source_ip_hash") or "")
        user = str(row.get("user_key_hash") or "")
        if not source or not user:
            raise ValueError("Faltan identificadores seudonimizados para reconstruir el baseline.")

        queue = history[source]
        while queue and queue[0][0] < timestamp - WINDOW_SECONDS:
            queue.popleft()

        if not parse_bool(row["auth_success"]):
            queue.append((timestamp, user))

        timestamps = [item[0] for item in queue]
        unique_users = len({item[1] for item in queue})
        interval_mean = WINDOW_SECONDS
        interval_std = 0.0

        if len(timestamps) >= 2:
            intervals = np.diff(np.asarray(timestamps, dtype=np.float64))
            interval_mean = float(np.mean(intervals))
            interval_std = float(np.std(intervals, ddof=0))

        vectors.append([
            float(len(timestamps)),
            float(unique_users),
            js_round_two(interval_mean),
            js_round_two(interval_std),
            float(row["_timestamp"].hour),
        ])

    return np.asarray(vectors, dtype=np.float64)


def select_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Choose the F1-maximizing threshold on validation data only."""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    if len(thresholds) == 0:
        raise ValueError("No hay umbrales utilizables en el conjunto de validación.")
    p = precision[:-1]
    r = recall[:-1]
    f1 = np.divide(2 * p * r, p + r, out=np.zeros_like(p), where=(p + r) > 0)
    best_f1 = float(np.max(f1))
    candidates = np.flatnonzero(np.isclose(f1, best_f1))
    # Tie-break: higher precision, then higher threshold (more conservative).
    best = max(candidates, key=lambda idx: (float(p[idx]), float(thresholds[idx])))
    return float(thresholds[best])


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None = None) -> dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    output: dict[str, Any] = {
        "n": int(len(y_true)),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "specificity": float(tn / (tn + fp)) if (tn + fp) else None,
    }
    if scores is not None and len(np.unique(y_true)) == 2:
        output["roc_auc"] = float(roc_auc_score(y_true, scores))
        output["average_precision"] = float(average_precision_score(y_true, scores))
    else:
        output["roc_auc"] = None
        output["average_precision"] = None
    return output


def cluster_bootstrap_f1(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    groups: np.ndarray,
    seed: int,
    iterations: int = 1000,
) -> dict[str, Any] | None:
    unique_groups = np.unique(groups)
    if len(unique_groups) < 5:
        return None
    index_by_group = {group: np.flatnonzero(groups == group) for group in unique_groups}
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(iterations):
        sampled = rng.choice(unique_groups, size=len(unique_groups), replace=True)
        indexes = np.concatenate([index_by_group[group] for group in sampled])
        values.append(float(f1_score(y_true[indexes], y_pred[indexes], zero_division=0)))
    low, high = np.quantile(values, [0.025, 0.975])
    return {
        "method": "cluster bootstrap by campaign_id; source_ip_hash fallback",
        "iterations": iterations,
        "clusters": int(len(unique_groups)),
        "confidence_level": 0.95,
        "f1_ci_95": [float(low), float(high)],
    }


def latency_summary(values: list[Any]) -> dict[str, Any]:
    numeric = np.asarray(
        [float(value) for value in values if value not in (None, "") and math.isfinite(float(value))],
        dtype=np.float64,
    )
    if len(numeric) == 0:
        return {"n": 0, "mean_ms": None, "median_ms": None, "p95_ms": None}
    return {
        "n": int(len(numeric)),
        "mean_ms": float(np.mean(numeric)),
        "median_ms": float(np.median(numeric)),
        "p95_ms": float(np.quantile(numeric, 0.95)),
    }


def load_capture_csv(path: Path) -> list[dict[str, Any]]:
    required = {
        "event_id", "occurred_at", "source_ip_hash", "user_key_hash",
        "auth_success", "is_simulated", "ground_truth_label",
        "dataset_split", "feature_schema_version", "features",
    }
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV incompleto. Faltan columnas: {', '.join(sorted(missing))}")
        rows = list(reader)

    if not rows:
        raise ValueError("El CSV no contiene registros.")
    if any(parse_bool(row["is_simulated"]) for row in rows):
        raise ValueError("El CSV contiene filas marcadas como simuladas; no se evaluará este archivo.")

    experiment_ids = {row.get("experiment_id", "") for row in rows}
    experiment_ids.discard("")
    if len(experiment_ids) > 1:
        raise ValueError("El CSV mezcla varios experiment_id. Exporta un experimento cada vez.")

    for row in rows:
        if row["feature_schema_version"] != FEATURE_SCHEMA:
            raise ValueError(
                f"Se encontró {row['feature_schema_version']!r}; se requiere {FEATURE_SCHEMA!r}. "
                "Reinicia la captura con la versión actual del detector."
            )
        if row["dataset_split"] not in {"train", "validation", "test"}:
            raise ValueError("Hay eventos sin división temporal asignada. No se pueden usar en este protocolo.")
        if row["ground_truth_label"] not in {"unknown", "benign", "attack"}:
            raise ValueError("Se encontró una etiqueta de referencia desconocida.")
        row["_timestamp"] = parse_timestamp(row["occurred_at"])
        row["_features"] = parse_features(row["features"])
    return rows


def prepare_xy(rows: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
    labeled = [row for row in rows if row["ground_truth_label"] in {"benign", "attack"}]
    x = np.vstack([row["_features"] for row in labeled])
    y = np.asarray([1 if row["ground_truth_label"] == "attack" else 0 for row in labeled], dtype=np.int8)
    return x, y


def score_anomaly(model: Any, x: np.ndarray) -> np.ndarray:
    # All model scores are oriented so larger values mean more anomalous.
    if isinstance(model, IsolationForest):
        return -np.asarray(model.decision_function(x), dtype=np.float64)
    return -np.asarray(model.decision_function(x), dtype=np.float64)


def measure_per_sample_latency(model: Any, x: np.ndarray) -> dict[str, Any]:
    values = []
    for row in x:
        start = time.perf_counter_ns()
        model.decision_function(row.reshape(1, -1))
        values.append((time.perf_counter_ns() - start) / 1_000_000.0)
    return latency_summary(values)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluación empírica con eventos de autenticación capturados por Centinela."
    )
    parser.add_argument("--input", required=True, help="CSV exportado desde /api/dataset/capturado?formato=csv")
    parser.add_argument("--output-dir", default="empirical_results")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--bootstrap", type=int, default=1000)
    parser.add_argument("--min-train", type=int, default=50)
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = load_capture_csv(input_path)
    train_rows = [r for r in rows if r["dataset_split"] == "train" and r["ground_truth_label"] == "benign"]
    validation_rows = [r for r in rows if r["dataset_split"] == "validation" and r["ground_truth_label"] in {"benign", "attack"}]
    test_rows = [r for r in rows if r["dataset_split"] == "test" and r["ground_truth_label"] in {"benign", "attack"}]

    x_train = build_benign_training_baseline(train_rows)
    if len(x_train) < args.min_train:
        raise ValueError(f"Solo hay {len(x_train)} ventanas benignas train; mínimo requerido: {args.min_train}.")

    x_val, y_val = prepare_xy(validation_rows)
    x_test, y_test = prepare_xy(test_rows)
    if len(x_val) == 0 or len(np.unique(y_val)) != 2:
        raise ValueError("Validación necesita ejemplos etiquetados de ambas clases (benign y attack).")
    if len(x_test) == 0 or len(np.unique(y_test)) != 2:
        raise ValueError("Prueba necesita ejemplos etiquetados de ambas clases (benign y attack).")

    # Validation/test vectors are the exact feature arrays emitted by the live Node detector.
    val_groups = np.asarray([
        (r.get("campaign_id") or r.get("source_ip_hash") or r["event_id"])
        for r in validation_rows
    ])
    test_labeled_rows = [r for r in test_rows if r["ground_truth_label"] in {"benign", "attack"}]
    test_groups = np.asarray([
        (r.get("campaign_id") or r.get("source_ip_hash") or r["event_id"])
        for r in test_labeled_rows
    ])

    lof_neighbors = min(20, max(2, len(x_train) - 1))
    models: dict[str, Any] = {
        "isolation_forest": IsolationForest(
            n_estimators=args.n_estimators,
            contamination="auto",
            random_state=args.seed,
            n_jobs=-1,
        ),
        "one_class_svm": make_pipeline(
            StandardScaler(),
            OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
        ),
        "local_outlier_factor": make_pipeline(
            StandardScaler(),
            LocalOutlierFactor(
                n_neighbors=lof_neighbors,
                novelty=True,
                contamination="auto",
                n_jobs=-1,
            ),
        ),
    }

    results: dict[str, Any] = {}
    prediction_frame: dict[str, Any] = {
        "event_id": [r["event_id"] for r in test_labeled_rows],
        "occurred_at": [r["occurred_at"] for r in test_labeled_rows],
        "campaign_id": [r.get("campaign_id", "") for r in test_labeled_rows],
        "ground_truth_label": [r["ground_truth_label"] for r in test_labeled_rows],
    }

    for name, model in models.items():
        model.fit(x_train)
        val_scores = score_anomaly(model, x_val)
        threshold = select_threshold(y_val, val_scores)
        test_scores = score_anomaly(model, x_test)
        test_pred = (test_scores >= threshold).astype(np.int8)
        metrics = binary_metrics(y_test, test_pred, test_scores)
        bootstrap = cluster_bootstrap_f1(
            y_test, test_pred, test_groups, args.seed, args.bootstrap
        )
        metrics["f1_cluster_bootstrap_95ci"] = bootstrap
        metrics["threshold_selected_on_validation"] = threshold
        metrics["validation_f1_at_selected_threshold"] = float(
            f1_score(y_val, (val_scores >= threshold).astype(np.int8), zero_division=0)
        )
        metrics["offline_single_sample_latency"] = measure_per_sample_latency(model, x_test)
        results[name] = metrics
        prediction_frame[f"{name}_anomaly_score"] = test_scores
        prediction_frame[f"{name}_predicted_attack"] = test_pred

    # Evaluate the decisions actually emitted by the running Centinela implementation.
    runtime_fields = {
        "rules": "alerta_reglas",
        "isolation_forest_runtime": "alerta_iforest",
        "ml_primary_decision_runtime": "alerta_ml",
    }
    runtime_metrics: dict[str, Any] = {}
    for name, field in runtime_fields.items():
        if not any(field in row for row in test_labeled_rows):
            continue
        predictions = np.asarray([1 if parse_bool(row.get(field, "false")) else 0 for row in test_labeled_rows], dtype=np.int8)
        metrics = binary_metrics(y_test, predictions)
        metrics["f1_cluster_bootstrap_95ci"] = cluster_bootstrap_f1(
            y_test, predictions, test_groups, args.seed, args.bootstrap
        )
        runtime_metrics[name] = metrics
        prediction_frame[f"{name}_predicted_attack"] = predictions

    runtime_latency = {
        "rules": latency_summary([r.get("latency_rules_ms") for r in test_labeled_rows]),
        "ml": latency_summary([r.get("latency_ml_ms") for r in test_labeled_rows]),
        "total_detector_inference": latency_summary([r.get("latency_total_ms") for r in test_labeled_rows]),
    }

    counts = {
        "all_captured": len(rows),
        "unknown_excluded": sum(r["ground_truth_label"] == "unknown" for r in rows),
        "train_benign": len(train_rows),
        "validation_labeled": len(validation_rows),
        "validation_benign": sum(r["ground_truth_label"] == "benign" for r in validation_rows),
        "validation_attack": sum(r["ground_truth_label"] == "attack" for r in validation_rows),
        "test_labeled": len(test_rows),
        "test_benign": sum(r["ground_truth_label"] == "benign" for r in test_rows),
        "test_attack": sum(r["ground_truth_label"] == "attack" for r in test_rows),
    }

    input_hash = sha256_file(input_path)
    script_hash = sha256_file(Path(__file__).resolve())
    code_versions = sorted({r.get("detector_version", "") for r in rows if r.get("detector_version")})
    config_versions = sorted({r.get("config_version", "") for r in rows if r.get("config_version")})
    experiment_ids = sorted({r.get("experiment_id", "") for r in rows if r.get("experiment_id")})

    report = {
        "study": "centinela_observed_authentication_events",
        "data_source": "Authentication requests captured by Centinela and persisted in Supabase",
        "synthetic_rows_allowed": False,
        "feature_schema": FEATURE_SCHEMA,
        "feature_names": [
            "failed_attempts_in_120s",
            "distinct_user_keys_in_120s",
            "mean_interarrival_seconds",
            "std_interarrival_seconds",
            "utc_hour",
        ],
        "experiment_ids": experiment_ids,
        "code_versions": code_versions,
        "config_versions": config_versions,
        "counts": counts,
        "training_baseline": {
            "method": "Reconstructed from independently labeled benign train events only",
            "n": int(len(x_train)),
            "window_seconds": WINDOW_SECONDS,
        },
        "offline_sklearn_models": results,
        "centinela_runtime_decisions": {
            "metrics": runtime_metrics,
            "measured_inference_latency_ms": runtime_latency,
            "interpretation": (
                "These are the decisions made by the running Node application. The primary ML decision "
                "combines a 2-of-3 vote with an additional Isolation Forest trigger; it is not a pure "
                "majority-vote ensemble. The legacy TypeScript OCSVM and LOF components are approximate "
                "distance detectors, not canonical implementations; use the separately fitted "
                "scikit-learn models above for standard algorithm comparisons."
            ),
        },
        "protocol": {
            "temporal_split": "train / validation / test fixed before capture",
            "threshold_calibration": "F1 maximization on validation only; threshold then frozen",
            "final_evaluation": "held-out test split only",
            "unknown_labels": "excluded from classification metrics",
            "bootstrap": "cluster bootstrap by campaign_id, falling back to source_ip_hash",
            "seed": args.seed,
            "bootstrap_iterations": args.bootstrap,
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "artifacts": {
            "input_csv": str(input_path),
            "input_csv_sha256": input_hash,
            "analysis_script_sha256": script_hash,
            "source_commit": os.environ.get("GITHUB_SHA"),
        },
    }

    metrics_path = output_dir / "empirical_metrics.json"
    predictions_path = output_dir / "test_predictions.csv"
    manifest_path = output_dir / "empirical_manifest.json"

    with metrics_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
    pd.DataFrame(prediction_frame).to_csv(predictions_path, index=False)

    manifest = {
        "input_csv_sha256": input_hash,
        "analysis_script_sha256": script_hash,
        "metrics_json_sha256": sha256_file(metrics_path),
        "predictions_csv_sha256": sha256_file(predictions_path),
        "experiment_ids": experiment_ids,
        "data_counts": counts,
        "feature_schema": FEATURE_SCHEMA,
        "source_commit": os.environ.get("GITHUB_SHA"),
    }
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)

    print(json.dumps({
        "status": "ok",
        "metrics": str(metrics_path),
        "predictions": str(predictions_path),
        "manifest": str(manifest_path),
        "counts": counts,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(2)
