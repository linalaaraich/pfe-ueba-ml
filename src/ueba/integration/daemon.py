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
import hashlib
import json
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ueba.config import get_config, load_config
from ueba.features.parse_logs import (
    NUMERIC_FEATURES,
    extract_raw_fields,
    group_by_session,
    build_features,
    add_zscores,
)
from ueba.features.baseline import apply_baseline_zscores, load_baseline

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

# NUMERIC_FEATURES est importé depuis ueba.features.parse_logs (source unique) :
# l'ordre des features DOIT être identique côté entraînement et côté service,
# sinon le scaler/les modèles (positionnels) reçoivent des vecteurs corrompus.


class UEBAModels:
    """Conteneur pour les trois modèles ML et le StandardScaler."""

    def __init__(self, models_dir: str, log: logging.Logger):
        self.dir        = Path(models_dir)
        self.log        = log
        self.scaler     = self._load("scaler.pkl")
        self.iso_forest = self._load("isolation_forest.pkl")
        self.ocsvm      = self._load("one_class_svm.pkl")
        self.autoencoder, self.ae_threshold = self._load_autoencoder()
        # Baseline FIGÉE par utilisateur (z-scores cohérents train↔serve, pas de
        # démarrage à froid). Absente → repli sur l'ancien calcul glissant.
        self.baseline   = load_baseline(self.dir / "baseline.json")
        if self.baseline:
            self.log.info("Baseline figée chargée : baseline.json")
        else:
            self.log.warning(
                "baseline.json absent — z-scores calculés sur la fenêtre "
                "glissante (instables au démarrage). Exportez la baseline "
                "depuis le notebook pour des prédictions fiables."
            )

    def _load(self, filename: str):
        path = self.dir / filename
        if not path.exists():
            self.log.warning("Modèle introuvable : %s", path)
            return None
        model = joblib.load(path)
        self.log.info("Modèle chargé : %s", filename)
        return model

    def _load_autoencoder(self):
        # Le modèle Keras est rechargé au format natif .keras (jamais via pickle :
        # joblib/pickle n'est pas fiable pour Keras 3). predict() ci-dessous attend
        # un modèle Keras brut qui renvoie des reconstructions, pas un wrapper.
        thr   = 0.05
        tpath = self.dir / "ae_threshold.json"
        if tpath.exists():
            try:
                thr = json.loads(tpath.read_text()).get("threshold", thr)
            except (OSError, json.JSONDecodeError, AttributeError) as e:
                self.log.warning("ae_threshold.json illisible (%s) — seuil par défaut %.3f", e, thr)
        ae = None
        keras_path = self.dir / "autoencoder.keras"
        if keras_path.exists():
            try:
                from tensorflow import keras
                ae = keras.models.load_model(str(keras_path))
                self.log.info("Autoencoder chargé depuis autoencoder.keras")
            except Exception as e:
                # ImportError (TF absent) MAIS AUSSI erreur de chargement (skew de
                # version Keras Colab↔VM, fichier corrompu) → dégrader proprement,
                # ne jamais planter le démarrage du daemon.
                self.log.warning("Autoencoder non chargé (%s) — désactivé", e)
        else:
            self.log.warning("Modèle introuvable : %s", keras_path)
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
    log = logging.getLogger("ueba.daemon")
    result: dict = {
        "isolation_forest": None,
        "one_class_svm":    None,
        "autoencoder":      None,
        "votes":            0,
        "expected_models":  0,   # modèles chargés (censés voter)
        "evaluated_models": 0,   # modèles ayant effectivement voté
        "degraded":         False,
        "is_anomaly":       False,
        "confidence":       0.0,
    }
    X = x.reshape(1, -1)

    # Chaque modèle est gardé individuellement : une erreur d'un modèle NE DOIT
    # PAS planter le daemon (cf. RC-4) ni passer inaperçue (cf. ancien bug : un
    # autoencoder en échec transformait le vote ≥2/3 en ET 2/2 silencieux avec
    # confidence=1.0). On distingue "censé voter" de "a voté".
    if models.iso_forest is not None:
        result["expected_models"] += 1
        try:
            pred  = models.iso_forest.predict(X)[0]
            score = models.iso_forest.decision_function(X)[0]
            result["isolation_forest"] = {"anomaly": pred == -1, "score": round(float(score), 4)}
            result["evaluated_models"] += 1
            if pred == -1:
                result["votes"] += 1
        except Exception as e:
            log.error("Isolation Forest a échoué (modèle ignoré pour ce vote) : %s", e)

    if models.ocsvm is not None:
        result["expected_models"] += 1
        try:
            pred  = models.ocsvm.predict(X)[0]
            score = models.ocsvm.decision_function(X)[0]
            result["one_class_svm"] = {"anomaly": pred == -1, "score": round(float(score), 4)}
            result["evaluated_models"] += 1
            if pred == -1:
                result["votes"] += 1
        except Exception as e:
            log.error("One-Class SVM a échoué (modèle ignoré pour ce vote) : %s", e)

    if models.autoencoder is not None:
        result["expected_models"] += 1
        try:
            recon = models.autoencoder.predict(X, verbose=0)
            mse   = float(np.mean(np.power(X - recon, 2)))
            anomaly = mse > models.ae_threshold
            result["autoencoder"] = {
                "anomaly": anomaly,
                "mse": round(mse, 6),
                "threshold": round(models.ae_threshold, 6),
            }
            result["evaluated_models"] += 1
            if anomaly:
                result["votes"] += 1
        except Exception as e:
            log.error("Autoencoder a échoué (modèle ignoré pour ce vote) : %s", e)

    # Dégradation = des modèles chargés n'ont pas pu voter → surfacé bruyamment,
    # jamais masqué. Confiance rapportée sur le nombre de modèles AYANT voté.
    result["degraded"] = result["evaluated_models"] < result["expected_models"]
    if result["degraded"]:
        log.error(
            "VOTE DÉGRADÉ : %d/%d modèles ont voté — décision peu fiable",
            result["evaluated_models"], result["expected_models"],
        )
    if result["evaluated_models"]:
        result["is_anomaly"] = result["votes"] >= threshold_votes
        result["confidence"] = round(result["votes"] / result["evaluated_models"], 2)

    return result

# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------

def to_scaled_vector(
    features: dict,
    scaler,
    df_history: pd.DataFrame,
    baseline: "dict | None" = None,
) -> np.ndarray:
    """
    Prépare le vecteur de features normalisé pour la prédiction.

    Si une baseline FIGÉE est fournie, les z-scores sont calculés à partir d'elle
    (cohérents avec l'entraînement, fiables dès la 1re session — fin du démarrage
    à froid, audit RC-1). Sinon, repli sur l'ancien calcul par fenêtre glissante.
    """
    row = pd.DataFrame([features])
    if baseline:
        row = apply_baseline_zscores(row, baseline)
        last = row.iloc[-1]
    else:
        combined = pd.concat([df_history, row], ignore_index=True) if not df_history.empty else row
        combined = add_zscores(combined)
        last = combined.iloc[-1]
    vec = np.array([float(last.get(f, 0) or 0) for f in NUMERIC_FEATURES], dtype=np.float32)
    # NaN/inf → 0 : `float(nan or 0)` vaut nan (nan est truthy), ce qui ferait
    # planter scaler/predict → vote dégradé silencieux. On neutralise.
    vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)
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
        "timestamp":          datetime.now(timezone.utc).isoformat(),
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
        "%s[ALERTE %s] user=%s | confidence=%s | votes=%d/%d%s",
        colors.get(severity, ""), severity,
        alert["username"], alert["confidence"], alert["votes"],
        result.get("expected_models", 3), reset,
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
    """
    Suit alerts.json comme `tail -f`, en mode BINAIRE (offsets en octets fiables).

    - Position PERSISTÉE (state_path) → après un redémarrage, on reprend là où
      on s'était arrêté au lieu de sauter à la fin : plus de "fenêtre aveugle"
      pendant laquelle un attaquant actif serait invisible (RC-4 / issue #7).
      Au tout premier démarrage (pas d'état), on saute à la fin pour ne pas
      rejouer tout l'historique.
    - Lignes PARTIELLES : si le dernier bloc lu ne se termine pas par '\\n'
      (écriture en cours par Wazuh), on NE consomme pas la ligne incomplète et
      on n'avance pas l'offset au-delà — elle sera relue entière au prochain
      poll (issue #8 : une alerte n'est plus jamais perdue à la frontière).
    - Rotation détectée par changement d'inode.
    """

    _FP_LEN = 64   # octets de tête servant d'empreinte anti-rotation

    def __init__(self, filepath: str, state_path: "str | None" = None):
        self._path  = Path(filepath)
        self._state = Path(state_path) if state_path else None
        self._file  = None
        self._inode = None
        self._pos   = 0
        self._head  = ""   # empreinte des _FP_LEN premiers octets

    def _prefix_fp(self, pos: int) -> str:
        """Empreinte (sha1) du PRÉFIXE DÉJÀ CONSOMMÉ (min(_FP_LEN, pos) octets).

        On empreinte les octets AVANT `pos` : une simple extension (append) ne
        les modifie jamais, mais une RÉÉCRITURE (copytruncate puis ré-alimenté,
        ou réécriture pendant un arrêt) les change. Ainsi on détecte la rotation
        même quand le fichier regrossit au-delà de l'ancien offset entre deux
        polls — sans faux positif sur la croissance normale d'un petit fichier
        (le bug de la 1re version, qui empreintait les 64 premiers octets bruts)."""
        n = min(self._FP_LEN, max(int(pos), 0))
        if n <= 0:
            return ""
        try:
            with open(self._path, "rb") as f:
                return hashlib.sha1(f.read(n)).hexdigest()
        except OSError:
            return ""

    def _load_state(self) -> "dict | None":
        if not self._state or not self._state.exists():
            return None
        try:
            return json.loads(self._state.read_text())
        except (OSError, json.JSONDecodeError):
            return None

    def _persist(self) -> None:
        if not self._state:
            return
        try:
            self._state.parent.mkdir(parents=True, exist_ok=True)
            self._state.write_text(json.dumps(
                {"inode": self._inode, "pos": self._pos, "head": self._head}))
        except OSError:
            pass  # best-effort : ne jamais planter le daemon pour l'état

    def open(self) -> None:
        if not self._path.exists():
            return
        self._file   = open(self._path, "rb")
        self._inode  = self._path.stat().st_ino
        size         = self._path.stat().st_size
        saved        = self._load_state()
        saved_pos    = int(saved.get("pos", 0)) if saved else 0
        same_inode   = bool(saved and saved.get("inode") == self._inode)
        # même fichier = même inode + préfixe consommé inchangé + pas de truncate
        same_file = (
            same_inode
            and saved_pos <= size
            and saved.get("head") == self._prefix_fp(saved_pos)
        )
        if same_file:
            self._pos = saved_pos                       # reprise sans fenêtre aveugle
        elif same_inode and "head" not in saved:
            self._pos = min(saved_pos, size)            # état hérité (sans empreinte)
        elif same_inode:
            self._pos = 0                               # réécrit/tronqué pendant l'arrêt
        else:
            self._pos = size                            # 1er démarrage → fin (pas d'histo)
        self._head = self._prefix_fp(self._pos)
        self._persist()

    def read_new(self) -> list[dict]:
        alerts: list[dict] = []
        if self._path.exists():
            st = self._path.stat()
            inode = st.st_ino
            if self._file is None or inode != self._inode:
                if self._file:
                    self._file.close()
                self._file  = open(self._path, "rb")
                self._inode = inode
                self._pos   = 0    # nouveau fichier après rotation → depuis le début
            elif st.st_size < self._pos:
                # copytruncate (logrotate) : même inode, fichier tronqué sous l'offset
                self._pos = 0
            elif self._pos > 0 and self._prefix_fp(self._pos) != self._head:
                # copytruncate PUIS regrossi au-delà de l'ancien offset entre deux
                # polls : le préfixe consommé a changé ⇒ fichier RÉÉCRIT → relire
                # depuis 0 (sinon perte silencieuse d'alertes).
                self._pos = 0

        if not self._file:
            return alerts

        self._file.seek(self._pos)
        data = self._file.read()
        if not data:
            return alerts

        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            return alerts  # aucune ligne complète encore : on attend (#8)

        complete = data[: last_nl + 1]
        self._pos += len(complete)  # n'avance que sur les octets complets
        for raw in complete.split(b"\n"):
            raw = raw.strip()
            if not raw:
                continue
            try:
                alerts.append(json.loads(raw.decode("utf-8", "replace")))
            except json.JSONDecodeError:
                pass
        self._head = self._prefix_fp(self._pos)   # empreinte du préfixe consommé
        self._persist()
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
    log.info("  Cires Technologies / Tanger Med Group — PFE")
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

    # État de lecture persisté sous models_dir (répertoire inscriptible déjà
    # utilisé par le daemon) → reprise après redémarrage sans fenêtre aveugle.
    state_path = str(Path(paths_cfg.get("models_dir", "models/")) / ".watch_state.json")
    watcher = AlertsWatcher(alerts_path, state_path=state_path)
    watcher.open()
    log.info("Surveillance : %s (polling %ds, état: %s)", alerts_path, poll_seconds, state_path)

    running = [True]

    def _stop(sig, frame):
        log.info("Signal %s reçu — arrêt propre", sig)
        running[0] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    while running[0]:
        new_alerts = watcher.read_new()
        if new_alerts:
            # Défense en profondeur : une alerte hostile/malformée ne doit jamais
            # tuer la boucle (en plus des gardes dans extract_raw_fields).
            raw = []
            for a in new_alerts:
                try:
                    e = extract_raw_fields(a)
                except Exception as exc:
                    log.error("Alerte ignorée (extraction impossible) : %s", exc)
                    continue
                if e:
                    raw.append(e)
            if raw:
                for session in group_by_session(raw, session_min):
                    features = build_features(session)
                    try:
                        x_scaled = to_scaled_vector(features, models.scaler, df_history, models.baseline)
                    except Exception as e:
                        log.error("Vecteur features invalide : %s", e)
                        continue

                    result = predict(models, x_scaled, vote_threshold)
                    log.info(
                        "Session user=%s | anomaly=%s | votes=%d/%d | conf=%s",
                        features["username"], result["is_anomaly"],
                        result["votes"], result["expected_models"], result["confidence"],
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
