#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ueba.integration.daemon
=======================
Daemon de détection UEBA en temps réel — intégration Wazuh.

Surveille alerts.json en continu, applique l'ensemble des trois modèles ML
et écrit les alertes dans /var/log/ueba_alerts.json.

Utilisation :
    python -m ueba.integration.daemon
    python -m ueba.integration.daemon --config config/config.yaml --verbose
    make run-daemon

Auteur  : Assia — PFE Cires Technologies / Tanger Med Group
"""

import argparse
import json
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ueba.config import get_config, load_config
from ueba.features.parse_logs import (
    extract_raw_fields,
    group_by_session,
    build_features,
    add_zscores,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging(level: str, log_file: str | None = None) -> logging.Logger:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file, mode="a"))
        except IOError:
            pass

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )
    return logging.getLogger("ueba.daemon")

# ---------------------------------------------------------------------------
# Chargement des modèles
# ---------------------------------------------------------------------------

NUMERIC_FEATURES = [
    "hour", "is_night", "is_weekend",
    "nb_files_accessed", "nb_sensitive_files",
    "nb_failed_logins", "nb_processes",
    "bytes_sent", "new_ip",
    "sensitive_path_access",
    "z_score_files", "z_score_logins",
    "velocity", "entropy_commands",
]


class UEBAModels:
    """Conteneur pour les trois modèles ML et le StandardScaler."""

    def __init__(self, models_dir: str, log: logging.Logger):
        self.dir        = Path(models_dir)
        self.log        = log
        self.scaler     = self._load("scaler.pkl")
        self.iso_forest = self._load("isolation_forest.pkl")
        self.ocsvm      = self._load("one_class_svm.pkl")
        self.autoencoder, self.ae_threshold = self._load_autoencoder()

    def _load(self, filename: str):
        path = self.dir / filename
        if not path.exists():
            self.log.warning("Modèle introuvable : %s", path)
            return None
        model = joblib.load(path)
        self.log.info("Modèle chargé : %s", filename)
        return model

    def _load_autoencoder(self):
        ae    = self._load("autoencoder.pkl")
        thr   = 0.05
        tpath = self.dir / "ae_threshold.json"
        if tpath.exists():
            thr = json.loads(tpath.read_text()).get("threshold", thr)
        if ae is None:
            keras_path = self.dir / "autoencoder.keras"
            if keras_path.exists():
                try:
                    from tensorflow import keras
                    ae = keras.models.load_model(str(keras_path))
                    self.log.info("Autoencoder chargé depuis autoencoder.keras")
                except ImportError:
                    self.log.warning("TensorFlow absent — autoencoder désactivé")
        return ae, thr

    def is_ready(self) -> bool:
        return self.scaler is not None and any(
            m is not None for m in [self.iso_forest, self.ocsvm, self.autoencoder]
        )

# ---------------------------------------------------------------------------
# Prédiction et vote d'ensemble
# ---------------------------------------------------------------------------

def predict(models: UEBAModels, x: np.ndarray, threshold_votes: int = 2) -> dict:
    """
    Applique les 3 modèles et retourne le résultat du vote majoritaire.
    Convention scikit-learn : -1 = anomalie, 1 = normal.
    """
    result: dict = {
        "isolation_forest": None,
        "one_class_svm":    None,
        "autoencoder":      None,
        "votes":            0,
        "is_anomaly":       False,
        "confidence":       0.0,
    }
    X = x.reshape(1, -1)

    if models.iso_forest:
        pred  = models.iso_forest.predict(X)[0]
        score = models.iso_forest.decision_function(X)[0]
        result["isolation_forest"] = {"anomaly": pred == -1, "score": round(float(score), 4)}
        if pred == -1:
            result["votes"] += 1

    if models.ocsvm:
        pred  = models.ocsvm.predict(X)[0]
        score = models.ocsvm.decision_function(X)[0]
        result["one_class_svm"] = {"anomaly": pred == -1, "score": round(float(score), 4)}
        if pred == -1:
            result["votes"] += 1

    if models.autoencoder:
        try:
            recon = models.autoencoder.predict(X, verbose=0)
            mse   = float(np.mean(np.power(X - recon, 2)))
            anomaly = mse > models.ae_threshold
            result["autoencoder"] = {
                "anomaly": anomaly,
                "mse": round(mse, 6),
                "threshold": round(models.ae_threshold, 6),
            }
            if anomaly:
                result["votes"] += 1
        except Exception as e:
            logging.getLogger("ueba.daemon").warning("Autoencoder erreur : %s", e)

    nb_models = sum(1 for k in ["isolation_forest", "one_class_svm", "autoencoder"]
                    if result[k] is not None)
    if nb_models:
        result["is_anomaly"]  = result["votes"] >= threshold_votes
        result["confidence"]  = round(result["votes"] / nb_models, 2)

    return result

# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------

def to_scaled_vector(
    features: dict,
    scaler,
    df_history: pd.DataFrame,
) -> np.ndarray:
    """Prépare le vecteur de features normalisé pour la prédiction."""
    row     = pd.DataFrame([features])
    combined = pd.concat([df_history, row], ignore_index=True) if not df_history.empty else row
    combined = add_zscores(combined)
    last    = combined.iloc[-1]
    vec     = np.array([float(last.get(f, 0) or 0) for f in NUMERIC_FEATURES], dtype=np.float32)
    return scaler.transform(vec.reshape(1, -1))[0]

# ---------------------------------------------------------------------------
# Alertes
# ---------------------------------------------------------------------------

def _severity(votes: int, features: dict) -> str:
    high_risk = (
        features.get("nb_sensitive_files", 0) > 0
        or features.get("nb_failed_logins", 0) >= 5
        or features.get("is_night", 0)
    )
    if votes == 3 or (votes == 2 and high_risk):
        return "HIGH"
    if votes == 2:
        return "MEDIUM"
    return "LOW"


def emit_alert(features: dict, result: dict, output_path: str, log: logging.Logger) -> None:
    severity = _severity(result["votes"], features)
    alert = {
        "timestamp":          datetime.utcnow().isoformat() + "Z",
        "type":               "ueba_anomaly",
        "severity":           severity,
        "username":           features.get("username", "unknown"),
        "session_ts":         features.get("timestamp", ""),
        "confidence":         result["confidence"],
        "votes":              result["votes"],
        "models":             {
            "isolation_forest": result.get("isolation_forest"),
            "one_class_svm":    result.get("one_class_svm"),
            "autoencoder":      result.get("autoencoder"),
        },
        "indicators": {
            "is_night":           bool(features.get("is_night", 0)),
            "is_weekend":         bool(features.get("is_weekend", 0)),
            "nb_failed_logins":   features.get("nb_failed_logins", 0),
            "nb_sensitive_files": features.get("nb_sensitive_files", 0),
            "process_name":       features.get("process_name", ""),
            "bytes_sent":         features.get("bytes_sent", 0),
        },
    }

    colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[93m"}
    reset  = "\033[0m"
    log.warning(
        "%s[ALERTE %s] user=%s | confidence=%s | votes=%d/3%s",
        colors.get(severity, ""), severity,
        alert["username"], alert["confidence"], alert["votes"], reset,
    )
    try:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    except IOError as e:
        log.error("Impossible d'écrire l'alerte : %s", e)

# ---------------------------------------------------------------------------
# Surveillance du fichier (tail -f)
# ---------------------------------------------------------------------------

class AlertsWatcher:
    def __init__(self, filepath: str):
        self._path  = Path(filepath)
        self._file  = None
        self._inode = None
        self._pos   = 0

    def open(self) -> None:
        if self._path.exists():
            self._file  = open(self._path, "r", encoding="utf-8", errors="replace")
            self._inode = self._path.stat().st_ino
            self._file.seek(0, 2)
            self._pos   = self._file.tell()

    def read_new(self) -> list[dict]:
        alerts: list[dict] = []
        if self._path.exists():
            inode = self._path.stat().st_ino
            if self._file is None or inode != self._inode:
                if self._file:
                    self._file.close()
                self._file  = open(self._path, "r", encoding="utf-8", errors="replace")
                self._inode = inode
                self._pos   = 0

        if not self._file:
            return alerts

        self._file.seek(self._pos)
        for line in self._file:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        self._pos = self._file.tell()
        return alerts

    def close(self) -> None:
        if self._file:
            self._file.close()

# ---------------------------------------------------------------------------
# Boucle principale
# ---------------------------------------------------------------------------

def run(cfg: dict, verbose: bool = False) -> None:
    wazuh_cfg     = cfg.get("wazuh", {})
    paths_cfg     = cfg.get("paths", {})
    daemon_cfg    = cfg.get("daemon", {})
    detect_cfg    = cfg.get("detection", {})
    logging_cfg   = cfg.get("logging", {})

    log_level     = "DEBUG" if verbose else logging_cfg.get("level", "INFO")
    log           = _setup_logging(log_level)

    log.info("=" * 60)
    log.info("  UEBA Daemon — Détection Insider Threat & Malware")
    log.info("  Cires Technologies / Tanger Med Group — PFE 2024")
    log.info("=" * 60)

    models = UEBAModels(paths_cfg.get("models_dir", "models/"), log)
    if not models.is_ready():
        log.error("Aucun modèle valide. Lancez d'abord le notebook d'entraînement.")
        sys.exit(1)

    alerts_path    = wazuh_cfg.get("alerts_path", "/var/ossec/logs/alerts/alerts.json")
    session_min    = wazuh_cfg.get("session_minutes", 60)
    poll_seconds   = daemon_cfg.get("poll_seconds", 30)
    history_size   = daemon_cfg.get("history_size", 500)
    output_path    = paths_cfg.get("alert_output", "/var/log/ueba_alerts.json")
    vote_threshold = detect_cfg.get("ensemble_threshold", 2)

    history: list[dict] = []
    df_history = pd.DataFrame()

    watcher = AlertsWatcher(alerts_path)
    watcher.open()
    log.info("Surveillance : %s (polling %ds)", alerts_path, poll_seconds)

    running = [True]

    def _stop(sig, frame):
        log.info("Signal %s reçu — arrêt propre", sig)
        running[0] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    while running[0]:
        new_alerts = watcher.read_new()
        if new_alerts:
            raw = [e for a in new_alerts if (e := extract_raw_fields(a))]
            if raw:
                for session in group_by_session(raw, session_min):
                    features = build_features(session)
                    try:
                        x_scaled = to_scaled_vector(features, models.scaler, df_history)
                    except Exception as e:
                        log.error("Vecteur features invalide : %s", e)
                        continue

                    result = predict(models, x_scaled, vote_threshold)
                    log.info(
                        "Session user=%s | anomaly=%s | votes=%d/3 | conf=%s",
                        features["username"], result["is_anomaly"],
                        result["votes"], result["confidence"],
                    )
                    if result["is_anomaly"]:
                        emit_alert(features, result, output_path, log)

                    history.append(features)
                    if len(history) > history_size:
                        history = history[-history_size:]
                    df_history = pd.DataFrame(history)

        time.sleep(poll_seconds)

    watcher.close()
    log.info("Daemon arrêté.")

# ---------------------------------------------------------------------------
# Entrée CLI  (python -m ueba.integration.daemon ...)
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Daemon UEBA temps réel — intégration Wazuh",
    )
    parser.add_argument(
        "--config", "-c", default=None,
        help="Chemin vers config.yaml (défaut: config/config.yaml)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Mode DEBUG")
    args = parser.parse_args()

    cfg = load_config(args.config) if args.config else get_config()
    run(cfg, verbose=args.verbose)


if __name__ == "__main__":
    main()
