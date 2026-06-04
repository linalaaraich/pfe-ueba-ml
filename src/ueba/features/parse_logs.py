#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ueba.features.parse_logs
========================
Extraction et transformation des features UEBA depuis alerts.json de Wazuh.

Pipeline :
    alerts.json  →  événements bruts  →  sessions utilisateur  →  features UEBA  →  dataset.csv

Utilisation CLI :
    python -m ueba.features.parse_logs /var/ossec/logs/alerts/alerts.json
    python -m ueba.features.parse_logs /var/ossec/logs/alerts/alerts.json --output data/dataset.csv

Auteur  : Assia — PFE Cires Technologies / Tanger Med Group
"""

import argparse
import json
import math
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from scipy import stats

try:
    from ueba.config import get_config
    _cfg = get_config()
except Exception:
    _cfg = {}

# ---------------------------------------------------------------------------
# Constantes (surchargées par config.yaml si disponible)
# ---------------------------------------------------------------------------

# Défaut SANS double backslash : l'ancien r"C:\Sensitive\\" (deux backslashes)
# ne matchait JAMAIS un vrai chemin si config.yaml était absent → feature
# nb_sensitive_files toujours 0 (cf. audit). config.yaml reste prioritaire.
SENSITIVE_PATH   = _cfg.get("behavior", {}).get("sensitive_path", r"C:\Sensitive")
WORK_HOUR_START  = _cfg.get("behavior", {}).get("work_hour_start", 9)
WORK_HOUR_END    = _cfg.get("behavior", {}).get("work_hour_end", 18)

WINDOWS_EVENT_IDS = {
    "login_success": ["4624"],
    "login_failed":  ["4625"],
    "logout":        ["4634"],
    "process":       ["4688", "1"],   # Security + Sysmon
    "file_access":   ["4663", "11"],  # Security + Sysmon
    "registry":      ["13"],
    "network":       ["3"],
    "dns":           ["22"],
}

# Ordre final des colonnes exportées dans dataset.csv
DATASET_COLUMNS = [
    "timestamp", "username",
    "hour", "is_night", "is_weekend",
    "nb_files_accessed", "nb_sensitive_files",
    "nb_failed_logins", "nb_processes",
    "bytes_sent", "new_ip",
    "sensitive_path_access",
    "process_name", "command_line",
    "z_score_files", "z_score_logins",
    "velocity", "entropy_commands",
    "session_duration_min",
]

# Les 14 features NUMÉRIQUES réellement consommées par les modèles ML, DANS
# L'ORDRE. Les scalers/modèles sont positionnels : c'est l'invariant le plus
# critique du projet (un réordonnancement corrompt silencieusement toutes les
# prédictions). SOURCE UNIQUE — importée par le notebook ET le daemon pour
# qu'ils ne puissent jamais diverger (cf. audit RC-3, test de contrat).
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
# I/O
# ---------------------------------------------------------------------------

def load_alerts(filepath: str) -> list[dict]:
    """Charge alerts.json (NDJSON ou JSON array)."""
    alerts: list[dict] = []
    path = Path(filepath)

    if not path.exists():
        print(f"[ERREUR] Fichier introuvable : {filepath}", file=sys.stderr)
        return alerts

    content = path.read_text(encoding="utf-8", errors="replace").strip()

    if content.startswith("["):
        try:
            alerts = json.loads(content)
            print(f"[INFO] {len(alerts)} alertes chargées (JSON array)")
            return alerts
        except json.JSONDecodeError:
            pass

    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"[WARN] Ligne {i} invalide, ignorée.", file=sys.stderr)

    print(f"[INFO] {len(alerts)} alertes chargées (NDJSON)")
    return alerts

# ---------------------------------------------------------------------------
# Extraction des champs bruts
# ---------------------------------------------------------------------------

def _get_nested(d: dict, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is None:
            return default
    return d


def _parse_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _parse_timestamp(value) -> Optional[datetime]:
    """
    Parse un timestamp Wazuh de façon robuste.

    Gère : valeurs non-string (→ None), suffixe 'Z', et — important pour VM1
    (Ubuntu 22.04 → Python 3.10) — les offsets sans ':' (ex. '+0000') et les
    fractions de seconde, que `datetime.fromisoformat` rejette avant 3.11.

    Retourne un datetime NAÏF (tzinfo retiré, heure murale conservée) pour
    éviter le mélange aware/naïf qui faisait planter `group_by_session`
    (TypeError: can't compare offset-naive and offset-aware datetimes).
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None

    ts = None
    try:
        ts = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        # Repli compatible Python 3.10 (strptime %z accepte '+0000' et '+00:00')
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                ts = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if ts is None:
        return None
    if ts.tzinfo is not None:
        ts = ts.replace(tzinfo=None)
    return ts


def extract_raw_fields(alert: dict) -> Optional[dict]:
    """Extrait les champs bruts d'une alerte Wazuh. Retourne None si inutilisable."""
    if not isinstance(alert, dict):
        return None

    ts = _parse_timestamp(alert.get("timestamp") or _get_nested(alert, "@timestamp"))
    if ts is None:
        return None

    # Garde-fous : un champ peut être présent mais non-dict (entrée malformée
    # ou hostile) — sans ces gardes, .get() lève AttributeError et, dans le
    # daemon, fait planter toute la boucle (vecteur de DoS confirmé).
    data    = alert.get("data")  if isinstance(alert.get("data"),  dict) else {}
    rule    = alert.get("rule")  if isinstance(alert.get("rule"),  dict) else {}
    agent   = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    win     = data.get("win")    if isinstance(data.get("win"),    dict) else {}
    sysmon  = win.get("system")    if isinstance(win.get("system"),    dict) else {}
    evtdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}

    event_id = (
        str(sysmon.get("eventID", ""))
        or str(_get_nested(data, "win", "system", "eventID") or "")
        or str(data.get("id", ""))
        or ""
    ).strip()

    username = str(
        evtdata.get("subjectUserName")
        or evtdata.get("targetUserName")
        or data.get("srcuser")
        or _get_nested(alert, "predecoder", "user")
        or "unknown"
    ).strip().lower()

    return {
        "timestamp":    ts,
        "username":     username,
        "event_id":     event_id,
        "rule_id":      str(rule.get("id", "")),
        "agent_name":   agent.get("name", ""),
        "src_ip":       data.get("srcip") or evtdata.get("ipAddress") or "",
        "file_path":    evtdata.get("targetFilename") or evtdata.get("objectName") or "",
        "process_name": (
            evtdata.get("image")
            or evtdata.get("parentImage")
            or data.get("process", {}).get("name", "")
            or ""
        ),
        "command_line": evtdata.get("commandLine") or "",
        "bytes_sent":   _parse_int(data.get("bytes_sent") or 0),
        "dst_ip":       evtdata.get("destinationIp") or "",
    }

# ---------------------------------------------------------------------------
# Sessions utilisateur
# ---------------------------------------------------------------------------

def group_by_session(raw_events: list[dict], session_minutes: int = 60) -> list[dict]:
    """Regroupe les événements en sessions (coupure si inactivité > session_minutes)."""
    # Défense en profondeur : normaliser tout timestamp aware en naïf avant
    # de comparer/trier, sinon un mélange aware/naïf lève
    # "can't compare offset-naive and offset-aware datetimes". Les événements
    # issus de extract_raw_fields sont déjà naïfs (no-op ici).
    for ev in raw_events:
        t = ev.get("timestamp")
        if getattr(t, "tzinfo", None) is not None:
            ev["timestamp"] = t.replace(tzinfo=None)
    events = sorted(raw_events, key=lambda e: (e["username"], e["timestamp"]))
    sessions: list[dict] = []
    current: dict = {}

    for ev in events:
        user, ts = ev["username"], ev["timestamp"]
        gap = (ts - current.get("last_ts", ts)).total_seconds() if current else 0
        if not current or current["username"] != user or gap > session_minutes * 60:
            if current:
                sessions.append(current)
            current = _new_session(user, ts)
        _update_session(current, ev)

    if current:
        sessions.append(current)
    return sessions


def _new_session(username: str, ts: datetime) -> dict:
    return {
        "username": username, "start_ts": ts, "last_ts": ts,
        "ips_seen": set(), "first_ip": None,
        "file_paths": [], "process_names": [], "command_lines": [],
        "bytes_sent_total": 0, "failed_logins": 0,
        "login_count": 0, "logout_count": 0,
    }


def _update_session(s: dict, ev: dict) -> None:
    s["last_ts"] = ev["timestamp"]
    eid = ev["event_id"]

    if eid in WINDOWS_EVENT_IDS["login_success"]:
        s["login_count"] += 1
        ip = ev.get("src_ip", "")
        if ip:
            s["first_ip"] = s["first_ip"] or ip
            s["ips_seen"].add(ip)
    if eid in WINDOWS_EVENT_IDS["login_failed"]:
        s["failed_logins"] += 1
    if eid in WINDOWS_EVENT_IDS["logout"]:
        s["logout_count"] += 1
    if eid in WINDOWS_EVENT_IDS["file_access"]:
        if ev.get("file_path"):
            s["file_paths"].append(ev["file_path"])
    if eid in WINDOWS_EVENT_IDS["process"]:
        if ev.get("process_name"):
            s["process_names"].append(ev["process_name"])
        if ev.get("command_line"):
            s["command_lines"].append(ev["command_line"])
    if eid in WINDOWS_EVENT_IDS["network"]:
        s["bytes_sent_total"] += ev.get("bytes_sent", 0)

# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def _entropy(values: list[str]) -> float:
    """Entropie de Shannon sur une liste de chaînes."""
    if not values:
        return 0.0
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def build_features(session: dict) -> dict:
    """Construit le vecteur de features UEBA pour une session."""
    ts   = session["start_ts"]
    hour = ts.hour
    wday = ts.weekday()

    nb_files     = len(session["file_paths"])
    nb_sensitive = sum(
        1 for p in session["file_paths"]
        if SENSITIVE_PATH.lower() in p.lower()
    )
    nb_processes  = len(session["process_names"])
    duration_min  = max(
        (session["last_ts"] - session["start_ts"]).total_seconds() / 60, 1
    )
    new_ip_flag = int(len(session["ips_seen"]) > 1)

    return {
        "timestamp":            ts.isoformat(),
        "username":             session["username"],
        "hour":                 hour,
        "is_night":             int(hour < WORK_HOUR_START or hour >= WORK_HOUR_END),
        "is_weekend":           int(wday >= 5),
        "nb_files_accessed":    nb_files,
        "nb_sensitive_files":   nb_sensitive,
        "nb_failed_logins":     session["failed_logins"],
        "nb_processes":         nb_processes,
        "bytes_sent":           session["bytes_sent_total"],
        "new_ip":               new_ip_flag,
        "sensitive_path_access": int(nb_sensitive > 0),
        "process_name":         session["process_names"][0] if session["process_names"] else "",
        "command_line":         session["command_lines"][0]  if session["command_lines"]  else "",
        "velocity":             round(nb_files / duration_min, 4),
        "entropy_commands":     round(_entropy(session["command_lines"]), 4),
        "session_duration_min": round(duration_min, 2),
    }


def add_zscores(df: pd.DataFrame) -> pd.DataFrame:
    """Z-scores par utilisateur (baseline personnalisée)."""
    df = df.copy()
    for col, zcol in [("nb_files_accessed", "z_score_files"),
                      ("nb_failed_logins",  "z_score_logins")]:
        if col in df.columns:
            df[zcol] = (
                df.groupby("username")[col]
                .transform(
                    lambda x: stats.zscore(x, ddof=1)
                    if len(x) > 1
                    else pd.Series([0.0] * len(x), index=x.index)
                )
                .fillna(0.0)
                .round(4)
            )
        else:
            df[zcol] = 0.0
    return df

# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------

def parse_alerts_to_dataframe(
    filepath: str,
    session_minutes: int = 60,
) -> pd.DataFrame:
    """
    Pipeline complet : alerts.json → DataFrame de features UEBA.

    Args:
        filepath        : Chemin vers alerts.json
        session_minutes : Coupure de session en minutes

    Returns:
        pd.DataFrame avec toutes les features UEBA
    """
    print(f"\n{'='*60}")
    print("  UEBA Parser — Extraction des features depuis Wazuh")
    print(f"{'='*60}\n")

    alerts = load_alerts(filepath)
    if not alerts:
        print("[ERREUR] Aucune alerte chargée.", file=sys.stderr)
        return pd.DataFrame()

    raw_events = [e for a in alerts if (e := extract_raw_fields(a))]
    print(f"[INFO] {len(raw_events)} événements valides extraits")

    if not raw_events:
        return pd.DataFrame()

    sessions = group_by_session(raw_events, session_minutes)
    print(f"[INFO] {len(sessions)} sessions utilisateur construites")

    df = pd.DataFrame([build_features(s) for s in sessions])
    df = add_zscores(df)

    # Réordonner les colonnes
    cols = [c for c in DATASET_COLUMNS if c in df.columns]
    df   = df[cols]

    print(f"\n[OK] DataFrame : {df.shape[0]} sessions × {df.shape[1]} features")
    print(f"[OK] Utilisateurs : {df['username'].unique().tolist()}")
    return df

# ---------------------------------------------------------------------------
# Entrée CLI  (python -m ueba.features.parse_logs ...)
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parse Wazuh alerts.json → dataset.csv (features UEBA)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python -m ueba.features.parse_logs /var/ossec/logs/alerts/alerts.json\n"
            "  python -m ueba.features.parse_logs alerts.json --output data/dataset.csv\n"
        ),
    )
    parser.add_argument("filepath", help="Chemin vers alerts.json")
    parser.add_argument(
        "--output", "-o",
        default="data/dataset.csv",
        help="Fichier CSV de sortie (défaut: data/dataset.csv)",
    )
    parser.add_argument(
        "--session-min", type=int, default=60,
        help="Durée de coupure de session en minutes (défaut: 60)",
    )
    parser.add_argument(
        "--config", default=None,
        help="Chemin vers config.yaml (optionnel)",
    )
    args = parser.parse_args()

    df = parse_alerts_to_dataframe(args.filepath, args.session_min)
    if df.empty:
        print("[ERREUR] Aucune donnée extraite.", file=sys.stderr)
        sys.exit(1)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)

    print(f"\n{'='*60}")
    print(f"  Export : {args.output}")
    print(f"{'='*60}")
    print(f"  Sessions    : {len(df)}")
    print(f"  Features    : {len(df.columns)}")
    print(f"  Utilisateurs: {df['username'].unique().tolist()}")
    print(f"  Période     : {df['timestamp'].min()}  →  {df['timestamp'].max()}")
    print(f"\n  Charger dans le notebook :")
    print(f"    df = pd.read_csv('{args.output}')")


if __name__ == "__main__":
    main()
