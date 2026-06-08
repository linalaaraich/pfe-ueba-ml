"""
config.py — Chargement centralisé de config/config.yaml.

Retourne des valeurs par défaut si config.yaml est introuvable
(utile en Colab ou environnements sans le fichier de config).

Usage :
    from ueba.config import get_config
    cfg = get_config()
    alerts_path = cfg["wazuh"]["alerts_path"]
"""

import copy
from pathlib import Path
from typing import Any

import yaml

# Valeurs par défaut si config.yaml est absent
_DEFAULTS: dict[str, Any] = {
    "wazuh": {
        "alerts_path":    "/var/ossec/logs/alerts/alerts.json",
        "session_minutes": 60,
    },
    "paths": {
        "models_dir":   "models/",
        "data_dir":     "data/",
        "alert_output": "/var/log/ueba_alerts.json",
    },
    "behavior": {
        "sensitive_path":   "C:\\Sensitive\\",
        "work_hour_start":  9,
        "work_hour_end":    18,
    },
    "detection": {
        # Synchronisé avec config/config.yaml (source unique) : valeurs abaissées
        # pour maîtriser les faux positifs (cf. audit DATASET_HEALTH.md).
        "contamination":            0.01,
        "ocsvm_nu":                 0.01,
        "ocsvm_gamma":              0.01,
        "ae_latent_dim":            4,
        "ae_threshold_percentile":  99.0,
        "ae_threshold_sigma":       3.0,
        "ensemble_threshold":       2,
    },
    "daemon": {
        "poll_seconds": 30,
        "history_size": 500,
    },
    "logging": {
        "level": "INFO",
    },
}


def _find_config() -> Path | None:
    """Remonte l'arborescence depuis ce fichier pour trouver config/config.yaml."""
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "config" / "config.yaml"
        if candidate.exists():
            return candidate
    return None


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """
    Charge et retourne la configuration YAML.
    Retourne les valeurs par défaut si le fichier est introuvable.
    """
    # deepcopy : ne jamais renvoyer une référence vers _DEFAULTS (une mutation
    # côté appelant corromprait le défaut global pour tout le process).
    target = Path(path) if path else _find_config()
    if target and Path(target).exists():
        try:
            with open(target, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
            # yaml.safe_load renvoie None pour un fichier vide / commentaires seuls
            return loaded if isinstance(loaded, dict) else copy.deepcopy(_DEFAULTS)
        except (OSError, yaml.YAMLError):
            return copy.deepcopy(_DEFAULTS)   # docstring : ne lève jamais
    return copy.deepcopy(_DEFAULTS)


# Singleton chargé à la première utilisation
_cfg: dict | None = None


def get_config(path: str | Path | None = None) -> dict[str, Any]:
    """Retourne la configuration (singleton). Ne lève jamais d'exception."""
    global _cfg
    if _cfg is None:
        _cfg = load_config(path)
    return _cfg
