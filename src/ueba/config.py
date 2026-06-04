"""
config.py — Chargement centralisé de config/config.yaml.

Usage :
    from ueba.config import get_config
    cfg = get_config()
    alerts_path = cfg["wazuh"]["alerts_path"]
"""

from pathlib import Path
from typing import Any

import yaml

# Recherche config.yaml en remontant depuis ce fichier jusqu'à la racine du projet
def _find_config() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "config" / "config.yaml"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "config/config.yaml introuvable. "
        "Assurez-vous de lancer les scripts depuis la racine du projet."
    )


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Charge et retourne la configuration YAML."""
    config_path = Path(path) if path else _find_config()
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# Singleton chargé à la première utilisation
_cfg: dict | None = None


def get_config(path: str | Path | None = None) -> dict[str, Any]:
    """Retourne la configuration (singleton)."""
    global _cfg
    if _cfg is None:
        _cfg = load_config(path)
    return _cfg
