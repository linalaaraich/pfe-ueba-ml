#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wazuh_integration.py
====================
Daemon de détection UEBA en temps réel — intégration Wazuh.

Ce script tourne en continu sur VM1 (Ubuntu 24.04). Il surveille le fichier
alerts.json de Wazuh, extrait les features UEBA, et applique l'ensemble des
trois modèles ML pour détecter en temps réel :
  - Insider Threats (comportements anormaux internes)
  - Malwares (comportements réseau/processus suspects)
  - Compromission de compte (One-Class SVM)

Vote majoritaire : alerte levée si ≥ 2 modèles sur 3 détectent une anomalie.

Utilisation :
    python3 wazuh_integration.py --models ./models/

Prérequis :
    - Modèles exportés par le notebook : isolation_forest.pkl,
      one_class_svm.pkl, autoencoder.pkl, scaler.pkl
    - Fichier alerts.json accessible (chemin par défaut Wazuh)

Auteur  : Assia — PFE Cires Technologies / Tanger Med Group
Projet  : Système UEBA Portable — Détection Insider Threat & Malware
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# Import du parseur local
from parse_logs import (
    extract_raw_fields,
    group_by_session,
    build_features,
    add_zscores,
    load_alerts,
)

# ---------------------------------------------------------------------------
# Configuration du logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/ueba_detection.log", mode="a"),
    ],
)
log = logging.getLogger("ueba")


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

DEFAULT_ALERTS_PATH  = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_MODELS_DIR   = "./models"
DEFAULT_POLL_SECONDS = 30
ALERT_OUTPUT_PATH    = "/var/log/ueba_alerts.json"

# Features numériques utilisées par les modèles (ordre identique au notebook)
NUMERIC_FEATURES = [
    "hour", "is_night", "is_weekend",
    "nb_files_accessed", "nb_sensitive_files",
    "nb_failed_logins", "nb_processes",
    "bytes_sent", "new_ip",
    "sensitive_path_access",
    "z_score_files", "z_score_logins",
    "velocity", "entropy_commands",
]


# ---------------------------------------------------------------------------
# Chargement des modèles
# ---------------------------------------------------------------------------

class UEBAModels:
    """Conteneur pour les trois modèles ML et le scaler."""

    def __init__(self, models_dir: str):
        self.models_dir = Path(models_dir)
        self.scaler      = None
        self.iso_forest  = None
        self.ocsvm       = None
        self.autoencoder = None
        self._load()

    def _load(self):
        log.info(f"Chargement des modèles depuis : {self.models_dir}")

        self.scaler     = self._load_pkl("scaler.pkl")
        self.iso_forest = self._load_pkl("isolation_forest.pkl")
        self.ocsvm      = self._load_pkl("one_class_svm.pkl")

        # L'autoencoder peut être sauvegardé en .pkl (wrapped) ou .keras
        ae_pkl   = self.models_dir / "autoencoder.pkl"
        ae_keras = self.models_dir / "autoencoder.keras"
        if ae_pkl.exists():
            self.autoencoder = self._load_pkl("autoencoder.pkl")
        elif ae_keras.exists():
            try:
                from tensorflow import keras
                self.autoencoder = keras.models.load_model(str(ae_keras))
                log.info("Autoencoder chargé depuis autoencoder.keras")
            except ImportError:
                log.warning("TensorFlow non disponible — autoencoder désactivé")
        else:
            log.warning("Autoencoder introuvable — vote à 2 modèles")

    def _load_pkl(self, filename: str):
        path = self.models_dir / filename
        if not path.exists():
            log.warning(f"Modèle introuvable : {path}")
            return None
        model = joblib.load(path)
        log.info(f"Modèle chargé : {filename}")
        return model

    def is_ready(self) -> bool:
        return self.scaler is not None and (
            self.iso_forest is not None
            or self.ocsvm is not None
            or self.autoencoder is not None
        )


# ---------------------------------------------------------------------------
# Prédiction et vote d'ensemble
# ---------------------------------------------------------------------------

def predict_anomaly(models: UEBAModels, feature_vector: np.ndarray) -> dict:
    """
    Applique les trois modèles et retourne le résultat du vote majoritaire.

    Convention : -1 = anomalie, 1 = normal (scikit-learn)
    Pour l'autoencoder : erreur de reconstruction > seuil = anomalie

    Returns:
        dict avec les scores individuels et le verdict final
    """
    results = {
        "isolation_forest": None,
        "one_class_svm":    None,
        "autoencoder":      None,
        "votes_anomalie":   0,
        "is_anomaly":       False,
        "confidence":       0.0,
    }

    x = feature_vector.reshape(1, -1)

    # --- Isolation Forest ---
    if models.iso_forest:
        pred = models.iso_forest.predict(x)[0]
        score = models.iso_forest.decision_function(x)[0]
        results["isolation_forest"] = {
            "prediction": int(pred),
            "score": round(float(score), 4),
            "anomaly": pred == -1,
        }
        if pred == -1:
            results["votes_anomalie"] += 1

    # --- One-Class SVM ---
    if models.ocsvm:
        pred = models.ocsvm.predict(x)[0]
        score = models.ocsvm.decision_function(x)[0]
        results["one_class_svm"] = {
            "prediction": int(pred),
            "score": round(float(score), 4),
            "anomaly": pred == -1,
        }
        if pred == -1:
            results["votes_anomalie"] += 1

    # --- Autoencoder ---
    if models.autoencoder:
        try:
            reconstruction = models.autoencoder.predict(x, verbose=0)
            mse = float(np.mean(np.power(x - reconstruction, 2)))
            # Seuil chargé depuis fichier ou valeur par défaut
            threshold = _load_ae_threshold(models.models_dir)
            anomaly   = mse > threshold
            results["autoencoder"] = {
                "reconstruction_error": round(mse, 6),
                "threshold": round(threshold, 6),
                "anomaly": anomaly,
            }
            if anomaly:
                results["votes_anomalie"] += 1
        except Exception as e:
            log.warning(f"Autoencoder predict erreur : {e}")

    # Vote majoritaire (≥2/3)
    nb_models = sum(1 for k in ["isolation_forest", "one_class_svm", "autoencoder"]
                    if results[k] is not None)
    if nb_models > 0:
        threshold_vote = max(2, (nb_models // 2) + 1)
        results["is_anomaly"]  = results["votes_anomalie"] >= threshold_vote
        results["confidence"]  = round(results["votes_anomalie"] / nb_models, 2)

    return results


def _load_ae_threshold(models_dir: Path) -> float:
    """Charge le seuil de reconstruction de l'autoencoder depuis un fichier JSON."""
    threshold_file = models_dir / "ae_threshold.json"
    if threshold_file.exists():
        with open(threshold_file) as f:
            data = json.load(f)
            return float(data.get("threshold", 0.05))
    return 0.05  # Valeur par défaut conservative


# ---------------------------------------------------------------------------
# Préparation du vecteur de features
# ---------------------------------------------------------------------------

def prepare_feature_vector(session_features: dict, scaler, df_context: pd.DataFrame) -> np.ndarray:
    """
    Transforme un dictionnaire de features en vecteur numpy normalisé.

    Nécessite le DataFrame de contexte pour calculer les z-scores
    inter-sessions correctement.
    """
    # Ajouter la session courante au contexte pour le z-score
    new_row = pd.DataFrame([session_features])
    df_combined = pd.concat([df_context, new_row], ignore_index=True)
    df_combined = add_zscores(df_combined)

    # Extraire la dernière ligne (session courante)
    last_row = df_combined.iloc[-1]

    # Construire le vecteur dans l'ordre attendu par les modèles
    vector = []
    for feat in NUMERIC_FEATURES:
        val = last_row.get(feat, 0)
        vector.append(float(val) if pd.notna(val) else 0.0)

    x = np.array(vector, dtype=np.float32)
    x_scaled = scaler.transform(x.reshape(1, -1))[0]
    return x_scaled


# ---------------------------------------------------------------------------
# Écriture des alertes UEBA
# ---------------------------------------------------------------------------

def emit_alert(session_features: dict, prediction: dict) -> None:
    """Écrit une alerte UEBA au format JSON dans le fichier de log dédié."""
    alert = {
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "type":        "ueba_anomaly",
        "username":    session_features.get("username", "unknown"),
        "session_ts":  session_features.get("timestamp", ""),
        "confidence":  prediction["confidence"],
        "votes":       prediction["votes_anomalie"],
        "is_night":    bool(session_features.get("is_night", 0)),
        "is_weekend":  bool(session_features.get("is_weekend", 0)),
        "nb_failed_logins": session_features.get("nb_failed_logins", 0),
        "nb_sensitive_files": session_features.get("nb_sensitive_files", 0),
        "process_name": session_features.get("process_name", ""),
        "models": {
            "isolation_forest": prediction.get("isolation_forest"),
            "one_class_svm":    prediction.get("one_class_svm"),
            "autoencoder":      prediction.get("autoencoder"),
        },
        "severity": _compute_severity(prediction, session_features),
    }

    # Log console coloré
    severity = alert["severity"]
    color    = "\033[91m" if severity == "HIGH" else "\033[93m" if severity == "MEDIUM" else "\033[0m"
    reset    = "\033[0m"
    log.warning(
        f"{color}[ALERTE UEBA] user={alert['username']} | severity={severity} "
        f"| confidence={alert['confidence']} | votes={alert['votes']}{reset}"
    )

    # Écriture fichier
    try:
        with open(ALERT_OUTPUT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    except IOError as e:
        log.error(f"Impossible d'écrire l'alerte : {e}")


def _compute_severity(prediction: dict, features: dict) -> str:
    """Calcule la sévérité basée sur le nombre de votes et les features à risque."""
    votes = prediction["votes_anomalie"]
    high_risk = (
        features.get("nb_sensitive_files", 0) > 0
        or features.get("nb_failed_logins", 0) >= 5
        or features.get("is_night", 0) == 1
    )
    if votes == 3 or (votes == 2 and high_risk):
        return "HIGH"
    if votes == 2:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Surveillance en temps réel (tail -f style)
# ---------------------------------------------------------------------------

class AlertsWatcher:
    """
    Surveille alerts.json et traite les nouvelles lignes au fur et à mesure.
    Compatible avec la rotation de fichiers (logrotate).
    """

    def __init__(self, filepath: str):
        self.filepath   = Path(filepath)
        self._file      = None
        self._inode     = None
        self._pos       = 0

    def open(self):
        """Ouvre le fichier et se positionne en fin (on ne retraite pas l'historique)."""
        if self.filepath.exists():
            self._file  = open(self.filepath, "r", encoding="utf-8", errors="replace")
            self._inode = self.filepath.stat().st_ino
            self._file.seek(0, 2)  # Fin du fichier
            self._pos   = self._file.tell()
            log.info(f"Surveillance démarrée sur : {self.filepath}")
        else:
            log.warning(f"Fichier introuvable, attente de création : {self.filepath}")

    def read_new_lines(self) -> list[dict]:
        """Retourne les nouvelles alertes depuis le dernier appel."""
        new_alerts = []

        # Détection rotation de fichier
        if self.filepath.exists():
            current_inode = self.filepath.stat().st_ino
            if self._file is None or current_inode != self._inode:
                if self._file:
                    self._file.close()
                self._file  = open(self.filepath, "r", encoding="utf-8", errors="replace")
                self._inode = current_inode
                self._pos   = 0
                log.info("Rotation détectée — réouverture du fichier")

        if not self._file:
            return new_alerts

        self._file.seek(self._pos)
        for line in self._file:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                new_alerts.append(alert)
            except json.JSONDecodeError:
                pass
        self._pos = self._file.tell()

        return new_alerts

    def close(self):
        if self._file:
            self._file.close()


# ---------------------------------------------------------------------------
# Boucle principale du daemon
# ---------------------------------------------------------------------------

def run_daemon(
    alerts_path: str,
    models_dir:  str,
    poll_seconds: int,
    history_size: int = 500,
) -> None:
    """
    Boucle principale : surveille alerts.json et déclenche les prédictions.

    Args:
        alerts_path  : Chemin vers alerts.json de Wazuh
        models_dir   : Répertoire contenant les fichiers .pkl
        poll_seconds : Intervalle de polling en secondes
        history_size : Nombre de sessions historiques conservées pour les z-scores
    """
    log.info("=" * 60)
    log.info("  UEBA Daemon — Détection Insider Threat & Malware")
    log.info("  Cires Technologies / Tanger Med Group — PFE 2024")
    log.info("=" * 60)

    # Chargement des modèles
    models = UEBAModels(models_dir)
    if not models.is_ready():
        log.error("Aucun modèle valide chargé. Arrêt du daemon.")
        sys.exit(1)

    # Contexte historique pour les z-scores
    history_features: list[dict] = []
    df_history = pd.DataFrame(columns=NUMERIC_FEATURES + ["username"])

    # Surveillance du fichier
    watcher = AlertsWatcher(alerts_path)
    watcher.open()

    # Gestion du signal SIGTERM pour arrêt propre
    _running = [True]
    def _handle_signal(sig, frame):
        log.info("Signal reçu — arrêt du daemon UEBA")
        _running[0] = False
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    log.info(f"Daemon démarré — polling toutes les {poll_seconds}s")

    while _running[0]:
        new_raw_alerts = watcher.read_new_lines()

        if new_raw_alerts:
            log.debug(f"{len(new_raw_alerts)} nouvelles alertes reçues")

            # Extraction des événements bruts
            raw_events = []
            for alert in new_raw_alerts:
                ev = extract_raw_fields(alert)
                if ev:
                    raw_events.append(ev)

            # Groupement en sessions
            if raw_events:
                sessions = group_by_session(raw_events, session_minutes=30)

                for session in sessions:
                    features = build_features(session)

                    # Préparer le vecteur normalisé
                    try:
                        x_scaled = prepare_feature_vector(
                            features, models.scaler, df_history
                        )
                    except Exception as e:
                        log.error(f"Erreur préparation vecteur : {e}")
                        continue

                    # Prédiction
                    prediction = predict_anomaly(models, x_scaled)

                    # Log systématique
                    log.info(
                        f"Session user={features['username']} | "
                        f"anomaly={prediction['is_anomaly']} | "
                        f"votes={prediction['votes_anomalie']} | "
                        f"conf={prediction['confidence']}"
                    )

                    # Alerte si anomalie détectée
                    if prediction["is_anomaly"]:
                        emit_alert(features, prediction)

                    # Mise à jour de l'historique
                    history_features.append(features)
                    if len(history_features) > history_size:
                        history_features = history_features[-history_size:]
                    df_history = pd.DataFrame(history_features)

        time.sleep(poll_seconds)

    watcher.close()
    log.info("Daemon UEBA arrêté proprement.")


# ---------------------------------------------------------------------------
# Point d'entrée CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Daemon UEBA temps réel — intégration Wazuh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--alerts",
        default=DEFAULT_ALERTS_PATH,
        help=f"Chemin vers alerts.json (défaut: {DEFAULT_ALERTS_PATH})",
    )
    parser.add_argument(
        "--models",
        default=DEFAULT_MODELS_DIR,
        help=f"Répertoire des modèles .pkl (défaut: {DEFAULT_MODELS_DIR})",
    )
    parser.add_argument(
        "--poll",
        type=int,
        default=DEFAULT_POLL_SECONDS,
        help=f"Intervalle de polling en secondes (défaut: {DEFAULT_POLL_SECONDS})",
    )
    parser.add_argument(
        "--history",
        type=int,
        default=500,
        help="Nombre de sessions historiques pour les z-scores (défaut: 500)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Mode verbeux (DEBUG)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    run_daemon(
        alerts_path  = args.alerts,
        models_dir   = args.models,
        poll_seconds = args.poll,
        history_size = args.history,
    )


if __name__ == "__main__":
    main()
