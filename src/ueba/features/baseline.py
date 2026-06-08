"""
ueba.features.baseline
======================
Baseline comportementale FIGÉE par utilisateur — corrige l'audit RC-1.

PROBLÈME (vérifié dans l'audit)
-------------------------------
Les z-scores (`z_score_files`, `z_score_logins`) — le signal de « portabilité »
du projet — étaient recalculés sur une POPULATION DIFFÉRENTE selon le contexte :
  - entraînement : 300 sessions normales,
  - test         : normal + attaques mélangés (la même session normale obtenait
                   alors un z-score différent),
  - service      : fenêtre glissante VIDE au démarrage (z-scores nuls/instables).
Le scaler et les modèles, eux, sont positionnels et figés à l'entraînement →
ils recevaient des vecteurs hors-distribution au test et au démarrage à froid.

SOLUTION
--------
Calculer μ/σ par utilisateur UNE SEULE FOIS sur les données normales
d'entraînement, FIGER ces stats dans `models/baseline.json`, puis les réutiliser
À L'IDENTIQUE partout (notebook ET daemon) pour calculer les z-scores. Un repli
global couvre les utilisateurs jamais vus. Plus de dérive train/test/serve, plus
de démarrage à froid.

NB : on utilise l'écart-type de POPULATION (ddof=0), plus stable sur petits
échantillons ; la cohérence est garantie car ce module est l'unique source.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

# (colonne source -> nom de la feature z-score). Doit rester cohérent avec
# parse_logs.DATASET_COLUMNS / NUMERIC_FEATURES.
ZSCORE_SOURCES = [
    ("nb_files_accessed", "z_score_files"),
    ("nb_failed_logins",  "z_score_logins"),
]


def compute_baseline(df: pd.DataFrame) -> dict:
    """μ/σ par utilisateur (+ repli global) sur les colonnes sources des z-scores."""
    baseline: dict = {"per_user": {}, "global": {}}
    for col, _zcol in ZSCORE_SOURCES:
        if col not in df.columns:
            continue
        for user, grp in df.groupby("username")[col]:
            std = float(grp.std(ddof=0)) if len(grp) > 0 else 0.0
            baseline["per_user"].setdefault(str(user), {})[col] = {
                "mean": float(grp.mean()),
                "std":  std if std > 0 else 0.0,
            }
        gstd = float(df[col].std(ddof=0))
        baseline["global"][col] = {
            "mean": float(df[col].mean()),
            "std":  gstd if gstd > 0 else 0.0,
        }
    return baseline


def _z(x: float, stats: dict) -> float:
    mean = stats.get("mean", 0.0)
    std = stats.get("std", 0.0)
    return float((x - mean) / std) if std > 0 else 0.0


def apply_baseline_zscores(df: pd.DataFrame, baseline: dict) -> pd.DataFrame:
    """
    Calcule les z-scores avec la baseline FIGÉE (pas la population courante).
    Utilisateur inconnu → repli global. std=0 → z=0 (jamais de division par 0).
    Résultat : pour une session donnée, le z-score est INVARIANT au reste du lot.
    """
    df = df.copy()
    per_user = baseline.get("per_user", {})
    global_stats = baseline.get("global", {})
    for col, zcol in ZSCORE_SOURCES:
        if col not in df.columns:
            df[zcol] = 0.0
            continue
        zvals = []
        for _, row in df.iterrows():
            user = str(row.get("username", ""))
            stats = per_user.get(user, {}).get(col) or global_stats.get(col, {})
            zvals.append(round(_z(float(row[col]), stats), 4))
        df[zcol] = zvals
    return df


def save_baseline(baseline: dict, path: "str | Path") -> None:
    Path(path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(path: "str | Path") -> "dict | None":
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def calibrate_ae_threshold(val_errors, percentile: float = 99.0,
                           fallback_mean: "float | None" = None,
                           fallback_std: "float | None" = None,
                           sigma: float = 3.0) -> float:
    """
    Seuil de l'autoencodeur calibré pour MAÎTRISER les faux positifs.

    Corrige l'audit (FP élevés) : `μ + kσ` sur les erreurs d'ENTRAÎNEMENT
    sous-estime le seuil car les erreurs de reconstruction sont fortement
    ASYMÉTRIQUES (μ+3σ ≠ 99,7e percentile → ~5-8 % de FP). On calibre plutôt sur
    le PERCENTILE des erreurs d'un set de VALIDATION (non vu par les poids) :
    un percentile p borne directement le taux de FP à ~(100−p) % et reflète la
    généralisation (l'AE sur-apprend sur peu de données).

    Repli sur μ+σ (entraînement) si la validation est trop petite (< 20 points).
    """
    val_errors = np.asarray(val_errors, dtype=float)
    # Écarter NaN/inf : sinon np.percentile renvoie NaN, et au service
    # `mse > NaN` est toujours False ⇒ autoencodeur muet sans alerte (bug).
    val_errors = val_errors[np.isfinite(val_errors)]
    if val_errors.size >= 20:
        return float(np.percentile(val_errors, percentile))
    if (fallback_mean is not None and fallback_std is not None
            and np.isfinite(fallback_mean) and np.isfinite(fallback_std)):
        return float(fallback_mean + sigma * fallback_std)
    return float(np.percentile(val_errors, percentile)) if val_errors.size else 0.0


def feature_health(df: pd.DataFrame, features: list[str]) -> dict:
    """
    Rapport de santé des features : repère celles constantes / quasi-toujours
    nulles (ex. `bytes_sent`, mort sur données réelles car Sysmon EID 3 ne porte
    pas de compteur d'octets — audit RC-2). À lancer sur le VRAI dataset pour
    décider quelles features retirer/re-sourcer.
    """
    report: dict = {}
    for f in features:
        if f not in df.columns:
            report[f] = {"present": False}
            continue
        col = df[f]
        nonzero = float((col != 0).mean()) if len(col) else 0.0
        report[f] = {
            "present": True,
            "nonzero_frac": round(nonzero, 4),
            "nunique": int(col.nunique(dropna=True)),
            "dead": bool(col.nunique(dropna=True) <= 1 or nonzero == 0.0),
        }
    return report
