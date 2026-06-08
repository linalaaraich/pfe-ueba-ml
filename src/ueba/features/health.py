"""
ueba.features.health
====================
Diagnostic de SANTÉ d'un dataset UEBA — répond à « mes données sont-elles
saines ? » avant d'incriminer les modèles.

Vérifie : volume, features constantes/mortes, quasi-constantes, NaN, doublons,
redondance (corrélations), équilibre des classes, et — si des labels existent —
la SÉPARABILITÉ normal vs attaque (une séparabilité triviale = des métriques
flatteuses mais trompeuses, audit RC-2).

CLI :
    python -m ueba.features.health data/dataset.csv
    python -m ueba.features.health data/dataset.csv --label label
"""
from __future__ import annotations

import argparse
import sys

import numpy as np
import pandas as pd

try:
    from ueba.features.parse_logs import NUMERIC_FEATURES
except Exception:  # pragma: no cover - fallback si exécuté hors package
    NUMERIC_FEATURES = []

NEAR_CONSTANT_STD = 1e-9
HIGH_CORR = 0.95


def audit_dataframe(df: pd.DataFrame, features: list[str] | None = None,
                    label_col: str | None = None) -> dict:
    """Retourne un rapport de santé structuré (dict) pour `df`."""
    features = [f for f in (features or NUMERIC_FEATURES) if f in df.columns]
    n = len(df)
    rep: dict = {"n_rows": n, "n_features": len(features), "features": {}}

    # ── Par feature ──────────────────────────────────────────────
    constant, near_constant, dead, has_nan = [], [], [], []
    for f in features:
        col = pd.to_numeric(df[f], errors="coerce")
        std = float(col.std(ddof=0)) if n else 0.0
        nonzero = float((col != 0).mean()) if n else 0.0
        nunq = int(col.nunique(dropna=True))
        nan_frac = float(col.isna().mean()) if n else 0.0
        info = {
            "mean": round(float(col.mean()), 4) if n else 0.0,
            "std": round(std, 6),
            "min": round(float(col.min()), 4) if n else 0.0,
            "max": round(float(col.max()), 4) if n else 0.0,
            "nonzero_frac": round(nonzero, 4),
            "nunique": nunq,
            "nan_frac": round(nan_frac, 4),
        }
        rep["features"][f] = info
        if nunq <= 1:
            constant.append(f)
        elif std < NEAR_CONSTANT_STD:
            near_constant.append(f)
        if nunq <= 1 or nonzero == 0.0:
            dead.append(f)
        if nan_frac > 0:
            has_nan.append(f)

    rep["constant_features"] = constant
    rep["near_constant_features"] = near_constant
    rep["dead_features"] = dead
    rep["features_with_nan"] = has_nan

    # ── Doublons ─────────────────────────────────────────────────
    if features and n:
        dup = int(df[features].duplicated().sum())
        rep["duplicate_rows"] = dup
        rep["duplicate_frac"] = round(dup / n, 4)

    # ── Redondance (corrélations fortes) ─────────────────────────
    rep["high_correlations"] = []
    nonconst = [f for f in features if f not in constant]
    if len(nonconst) >= 2 and n >= 3:
        corr = df[nonconst].apply(pd.to_numeric, errors="coerce").corr().abs()
        for i, a in enumerate(nonconst):
            for b in nonconst[i + 1:]:
                r = corr.loc[a, b]
                if pd.notna(r) and r >= HIGH_CORR:
                    rep["high_correlations"].append({"a": a, "b": b, "r": round(float(r), 3)})

    # ── Labels / séparabilité ────────────────────────────────────
    if label_col and label_col in df.columns:
        counts = df[label_col].value_counts().to_dict()
        rep["label_counts"] = {str(k): int(v) for k, v in counts.items()}
        is_attack = (pd.to_numeric(df[label_col], errors="coerce") > 0)
        if is_attack.any() and (~is_attack).any():
            sep = []
            for f in nonconst:
                col = pd.to_numeric(df[f], errors="coerce")
                mu_n, mu_a = col[~is_attack].mean(), col[is_attack].mean()
                # Écart en σ INTRA-CLASSE (Cohen's d), pas σ globale : sinon une
                # feature binaire 0/1 qui sépare PARFAITEMENT plafonne ~2σ et
                # n'est jamais détectée comme triviale. σ poolée → ∞ si parfait.
                sd_n = float(col[~is_attack].std(ddof=0))
                sd_a = float(col[is_attack].std(ddof=0))
                pooled = ((sd_n ** 2 + sd_a ** 2) / 2) ** 0.5
                if pooled > 0:
                    d = abs(mu_a - mu_n) / pooled
                else:  # variance intra-classe nulle : séparation parfaite si μ diffèrent
                    d = float("inf") if mu_a != mu_n else 0.0
                sep.append({"feature": f,
                            "separation_sigma": round(d, 2) if d != float("inf") else 999.99})
            sep.sort(key=lambda x: -x["separation_sigma"])
            rep["separability_top"] = sep[:8]
            # Séparabilité triviale : Cohen's d > 3 (écart énorme, y c. binaire parfait)
            trivial = [s for s in sep if s["separation_sigma"] > 3.0]
            rep["trivially_separable_features"] = [s["feature"] for s in trivial]

    return rep


def verdict(rep: dict) -> list[str]:
    """Transforme le rapport en avertissements lisibles."""
    w = []
    if rep["n_rows"] < 100:
        w.append(f"VOLUME FAIBLE : {rep['n_rows']} sessions — modèles sous-entraînés "
                 "(viser >> quelques centaines).")
    if rep.get("dead_features"):
        w.append(f"FEATURES MORTES (constantes/toujours nulles) : {rep['dead_features']} "
                 "— inutiles aux modèles, à retirer ou re-sourcer.")
    if rep.get("constant_features"):
        w.append(f"FEATURES CONSTANTES à l'entraînement : {rep['constant_features']} "
                 "— variance nulle : n'apportent aucun signal, faussent l'échelle.")
    if rep.get("features_with_nan"):
        w.append(f"NaN présents : {rep['features_with_nan']}.")
    if rep.get("duplicate_frac", 0) > 0.3:
        w.append(f"DOUBLONS élevés : {rep['duplicate_frac']:.0%} des lignes identiques "
                 "— diversité comportementale insuffisante.")
    for hc in rep.get("high_correlations", []):
        w.append(f"REDONDANCE : {hc['a']} ~ {hc['b']} (r={hc['r']}).")
    if rep.get("trivially_separable_features"):
        w.append("SÉPARABILITÉ TRIVIALE : "
                 f"{rep['trivially_separable_features']} séparent normal/attaque à >3σ "
                 "— des métriques quasi-parfaites mesurent le GÉNÉRATEUR, pas le modèle (RC-2).")
    if not w:
        w.append("Aucun problème majeur détecté par les heuristiques.")
    return w


def main():
    ap = argparse.ArgumentParser(description="Diagnostic de santé d'un dataset UEBA")
    ap.add_argument("csv", help="Chemin vers dataset.csv")
    ap.add_argument("--label", default="label", help="Colonne de label (défaut: label)")
    args = ap.parse_args()
    df = pd.read_csv(args.csv)
    rep = audit_dataframe(df, label_col=args.label if args.label in df.columns else None)
    print(f"=== Santé du dataset : {args.csv} ===")
    print(f"Sessions: {rep['n_rows']}  |  Features analysées: {rep['n_features']}")
    if "label_counts" in rep:
        print(f"Classes: {rep['label_counts']}")
    print("\nAvertissements :")
    for line in verdict(rep):
        print(f"  - {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
