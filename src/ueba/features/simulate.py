#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ueba.features.simulate
=====================
Générateur de **comportement normal réaliste, multi-profils** — produit le
« long flux de normal » dont les modèles non supervisés ont besoin comme
baseline, SANS machine cloud 24/7.

Pourquoi pas l'ancien générateur ?
----------------------------------
L'audit de santé a montré que l'ancien normal synthétique avait **6 features
constantes** (`is_night`, `is_weekend`, `new_ip`, `sensitive_path_access`
toujours = 0) et un seul profil → ~10-20 % de faux positifs sur du normal
hors-échantillon. Ici, on corrige :
  - **plusieurs profils** (bureau, finance, RH, IT/admin, dev) aux baselines
    DIFFÉRENTES (heures, volumes, accès sensibles) ;
  - **variabilité réaliste** : un peu de travail légitime de nuit/week-end, IP
    nouvelles occasionnelles, accès sensibles selon le rôle, quelques échecs de
    login (fautes de frappe) → AUCUNE feature constante ;
  - timestamps répartis sur plusieurs semaines.

Tout est labellisé `label=0` (normal). Les ATTAQUES viennent d'OTRF
(`ueba.features.otrf`). Combiné : baseline réaliste + attaques réelles.

CLI :
    python -m ueba.features.simulate --users 8 --days 30 --output data/dataset.csv
"""
from __future__ import annotations

import argparse
import math
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from ueba.features.parse_logs import (
    _entropy,
    DATASET_COLUMNS,
    WORK_HOUR_START,
    WORK_HOUR_END,
)
from ueba.features.baseline import apply_baseline_zscores, compute_baseline

# ── Profils de rôle : chaque rôle a des plages de comportement distinctes ──
# files=(moy, σ) fichiers/session ; proc=(moy, σ) processus ; bytes=(moy, σ) ;
# p_sensitive=proba d'accéder à C:\Sensitive ; p_night/p_weekend=proba de session
# hors heures/week-end ; p_new_ip=proba d'IP nouvelle ; cmds=répertoire de commandes.
PROFILES = {
    "bureau": {
        "files": (12, 6), "proc": (8, 3), "bytes": (40_000, 25_000),
        "p_sensitive": 0.05, "sens_n": (1, 2), "p_night": 0.03, "p_weekend": 0.04,
        "p_new_ip": 0.04, "work": (9, 18),
        "cmds": ["explorer.exe", "outlook.exe", "winword.exe", "excel.exe",
                 "chrome.exe", "teams.exe"],
    },
    "finance": {
        "files": (35, 15), "proc": (10, 4), "bytes": (120_000, 60_000),
        "p_sensitive": 0.6, "sens_n": (2, 8), "p_night": 0.05, "p_weekend": 0.06,
        "p_new_ip": 0.05, "work": (8, 18),
        "cmds": ["excel.exe", "explorer.exe", "sap.exe", "outlook.exe", "acrobat.exe"],
    },
    "rh": {
        "files": (25, 10), "proc": (9, 3), "bytes": (80_000, 40_000),
        "p_sensitive": 0.5, "sens_n": (1, 5), "p_night": 0.03, "p_weekend": 0.03,
        "p_new_ip": 0.04, "work": (9, 17),
        "cmds": ["explorer.exe", "winword.exe", "outlook.exe", "chrome.exe"],
    },
    "it_admin": {
        "files": (18, 12), "proc": (25, 12), "bytes": (200_000, 120_000),
        "p_sensitive": 0.4, "sens_n": (1, 6), "p_night": 0.18, "p_weekend": 0.15,
        "p_new_ip": 0.12, "work": (8, 19),
        "cmds": ["powershell.exe", "cmd.exe", "mmc.exe", "explorer.exe",
                 "putty.exe", "rdpclip.exe", "services.exe"],
    },
    "dev": {
        "files": (40, 20), "proc": (30, 15), "bytes": (150_000, 90_000),
        "p_sensitive": 0.1, "sens_n": (1, 3), "p_night": 0.12, "p_weekend": 0.1,
        "p_new_ip": 0.08, "work": (9, 20),
        "cmds": ["code.exe", "git.exe", "python.exe", "node.exe", "cmd.exe",
                 "chrome.exe", "docker.exe"],
    },
}


def _make_user(uid: int, role: str, rng: random.Random) -> dict:
    """Instancie un utilisateur : rôle + petit décalage individuel (baseline propre)."""
    p = PROFILES[role]
    jitter = rng.uniform(0.8, 1.2)
    return {
        "username": f"user_{role}_{uid:02d}",
        "role": role,
        "files_mu": p["files"][0] * jitter, "files_sd": p["files"][1],
        "proc_mu": p["proc"][0] * jitter, "proc_sd": p["proc"][1],
        "bytes_mu": p["bytes"][0] * jitter, "bytes_sd": p["bytes"][1],
        "p_sensitive": p["p_sensitive"], "sens_n": p["sens_n"],
        "p_night": p["p_night"], "p_weekend": p["p_weekend"], "p_new_ip": p["p_new_ip"],
        "work": p["work"], "cmds": p["cmds"],
    }


def _pos_int(rng, mu, sd, lo=0):
    return max(lo, int(round(rng.gauss(mu, sd))))


def simulate_session(user: dict, day: datetime, rng: random.Random,
                     weekend: bool = False) -> dict:
    """Génère UNE session normale réaliste pour `user` le jour `day`."""
    # On tire D'ABORD l'heure, puis is_night en est DÉRIVÉ avec la règle
    # canonique (identique à parse_logs.build_features : hour < START ou >= END).
    # Sinon le modèle apprendrait une relation hour↔is_night absente au service.
    if rng.random() < user["p_night"]:
        # session planifiée hors heures ouvrées
        hour = rng.choice([h for h in range(24)
                           if h < WORK_HOUR_START or h >= WORK_HOUR_END])
    else:
        lo, hi = WORK_HOUR_START, WORK_HOUR_END - 1     # heures ouvrées strictes
        hour = min(hi, max(lo, int(rng.gauss((lo + hi) / 2, 2))))
    is_night = int(hour < WORK_HOUR_START or hour >= WORK_HOUR_END)
    ts = day.replace(hour=hour, minute=rng.randint(0, 59), second=0, microsecond=0)

    nb_files = _pos_int(rng, user["files_mu"], user["files_sd"])
    duration = max(1.0, rng.gauss(45, 25))
    nb_proc = _pos_int(rng, user["proc_mu"], user["proc_sd"], lo=1)

    sensitive = rng.random() < user["p_sensitive"]
    nb_sens = rng.randint(*user["sens_n"]) if sensitive else 0
    nb_sens = min(nb_sens, nb_files)

    # quelques commandes tirées du répertoire du rôle → entropie réaliste
    k = max(1, min(len(user["cmds"]), nb_proc))
    cmds = [rng.choice(user["cmds"]) for _ in range(k)]

    failed = 0
    r = rng.random()
    if r < 0.06:
        failed = 1
    elif r < 0.08:
        failed = rng.randint(2, 3)

    return {
        "timestamp": ts.isoformat(),
        "username": user["username"],
        "hour": hour,
        "is_night": is_night,
        "is_weekend": int(weekend),
        "nb_files_accessed": nb_files,
        "nb_sensitive_files": nb_sens,
        "nb_failed_logins": failed,
        "nb_processes": nb_proc,
        "bytes_sent": _pos_int(rng, user["bytes_mu"], user["bytes_sd"]),
        "new_ip": int(rng.random() < user["p_new_ip"]),
        "sensitive_path_access": int(nb_sens > 0),
        "process_name": cmds[0],
        "command_line": cmds[0],
        "velocity": round(nb_files / duration, 4),
        "entropy_commands": round(_entropy(cmds), 4),
        "session_duration_min": round(duration, 2),
        "label": 0,
    }


def simulate_dataset(n_users: int = 8, days: int = 30, sessions_per_day: float = 2.0,
                     start: datetime | None = None, seed: int = 42) -> pd.DataFrame:
    """Construit un dataset normal multi-profils sur `days` jours."""
    rng = random.Random(seed)
    start = start or datetime(2024, 1, 1, 9, 0)

    roles = list(PROFILES)
    users = [_make_user(i, roles[i % len(roles)], rng) for i in range(n_users)]

    rows = []
    for d in range(days):
        day = start + timedelta(days=d)
        is_wknd = day.weekday() >= 5
        for u in users:
            if is_wknd:
                # week-end : peu de monde, selon p_weekend du rôle
                if rng.random() < u["p_weekend"]:
                    rows.append(simulate_session(u, day, rng, weekend=True))
            else:
                n = max(0, int(round(rng.gauss(sessions_per_day, 1.0))))
                for _ in range(n):
                    rows.append(simulate_session(u, day, rng, weekend=False))

    df = pd.DataFrame(rows)
    # z-scores via la baseline figée (ddof=0) — cohérent avec l'entraînement ET
    # le service (le daemon utilise apply_baseline_zscores). Évite l'écart ddof
    # de l'ancien add_zscores (ddof=1) sur le CSV.
    df = apply_baseline_zscores(df, compute_baseline(df))
    cols = [c for c in DATASET_COLUMNS if c in df.columns] + ["label"]
    return df[[c for c in cols if c in df.columns]]


def main():
    ap = argparse.ArgumentParser(description="Génère un dataset NORMAL multi-profils (baseline UEBA)")
    ap.add_argument("--users", type=int, default=8)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--sessions-per-day", type=float, default=2.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", "-o", default="data/dataset.csv")
    args = ap.parse_args()

    df = simulate_dataset(args.users, args.days, args.sessions_per_day, seed=args.seed)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"[OK] {len(df)} sessions normales ({args.users} profils, {args.days} j) → {args.output}")
    print(f"[OK] Utilisateurs : {df['username'].nunique()} | "
          f"nuit={df['is_night'].mean():.1%} week-end={df['is_weekend'].mean():.1%} "
          f"sensible={df['sensitive_path_access'].mean():.1%} new_ip={df['new_ip'].mean():.1%}")
    print("    → USE_REAL_DATA = True dans le notebook pour l'utiliser.")


if __name__ == "__main__":
    main()
