#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_logs.py
=============
Extraction et transformation des features UEBA depuis alerts.json de Wazuh.

Ce module lit le fichier alerts.json produit par Wazuh, puis construit
un DataFrame de sessions utilisateur enrichi de toutes les features
nécessaires au pipeline ML (Isolation Forest, One-Class SVM, Autoencoder).

Architecture : VM1 (Ubuntu 24.04) — Wazuh Manager
Chemin par défaut : /var/ossec/logs/alerts/alerts.json

Auteur  : Assia — PFE Cires Technologies / Tanger Med Group
Projet  : Système UEBA Portable — Détection Insider Threat & Malware
"""

import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from scipy import stats


# ---------------------------------------------------------------------------
# Constantes métier
# ---------------------------------------------------------------------------

# Identifiants d'événements Windows surveillés
WINDOWS_EVENT_IDS = {
    "login_success": ["4624"],
    "login_failed":  ["4625"],
    "logout":        ["4634"],
    "process":       ["4688", "1"],   # 4688 = Security, 1 = Sysmon
    "file_access":   ["4663", "11"],  # 4663 = Security, 11 = Sysmon FileCreate
    "registry":      ["13"],          # Sysmon RegSetValue
    "network":       ["3"],           # Sysmon NetworkConnect
    "dns":           ["22"],          # Sysmon DnsQuery
}

# Chemin sensible à surveiller (Insider Threat)
SENSITIVE_PATH = r"C:\\Sensitive\\"

# Plages horaires de travail normales
WORK_HOUR_START = 9
WORK_HOUR_END   = 18


# ---------------------------------------------------------------------------
# Chargement des alertes
# ---------------------------------------------------------------------------

def load_alerts(filepath: str) -> list[dict]:
    """
    Charge le fichier alerts.json de Wazuh.

    Wazuh écrit un JSON par ligne (format NDJSON), pas un tableau JSON.
    La fonction gère aussi le cas où le fichier est un JSON array standard.
    """
    alerts = []
    path = Path(filepath)

    if not path.exists():
        print(f"[ERREUR] Fichier introuvable : {filepath}", file=sys.stderr)
        return alerts

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read().strip()

    # Tentative JSON array
    if content.startswith("["):
        try:
            alerts = json.loads(content)
            print(f"[INFO] {len(alerts)} alertes chargées (format JSON array)")
            return alerts
        except json.JSONDecodeError:
            pass

    # Format NDJSON (une alerte par ligne)
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"[WARN] Ligne {i} invalide, ignorée.", file=sys.stderr)

    print(f"[INFO] {len(alerts)} alertes chargées (format NDJSON)")
    return alerts


# ---------------------------------------------------------------------------
# Extraction des champs bruts
# ---------------------------------------------------------------------------

def _get_nested(d: dict, *keys, default=None):
    """Accès sécurisé à une clé imbriquée."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is None:
            return default
    return d


def extract_raw_fields(alert: dict) -> Optional[dict]:
    """
    Extrait les champs bruts d'une alerte Wazuh.

    Retourne None si l'alerte ne contient pas d'horodatage utilisable.
    """
    timestamp_str = alert.get("timestamp") or _get_nested(alert, "@timestamp")
    if not timestamp_str:
        return None

    try:
        # Wazuh utilise ISO 8601 avec offset (ex. 2024-01-15T14:23:05.123+0000)
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except ValueError:
        return None

    data    = alert.get("data", {})
    rule    = alert.get("rule", {})
    agent   = alert.get("agent", {})
    sysmon  = data.get("win", {}).get("system", {}) or {}
    evtdata = data.get("win", {}).get("eventdata", {}) or {}

    # Event ID (plusieurs chemins possibles selon la source)
    event_id = (
        str(sysmon.get("eventID", ""))
        or str(_get_nested(data, "win", "system", "eventID") or "")
        or str(data.get("id", ""))
        or ""
    ).strip()

    # Utilisateur
    username = (
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
        "rule_desc":    rule.get("description", ""),
        "agent_name":   agent.get("name", ""),
        "src_ip":       data.get("srcip") or evtdata.get("ipAddress") or "",
        "file_path":    evtdata.get("targetFilename") or evtdata.get("objectName") or "",
        "process_name": evtdata.get("image") or evtdata.get("parentImage") or data.get("process", {}).get("name", "") or "",
        "command_line": evtdata.get("commandLine") or "",
        "bytes_sent":   _parse_int(evtdata.get("destinationPort") or data.get("bytes_sent") or 0),
        "dst_ip":       evtdata.get("destinationIp") or "",
        "dst_port":     _parse_int(evtdata.get("destinationPort") or 0),
        "registry_key": evtdata.get("targetObject") or "",
        "dns_query":    evtdata.get("queryName") or "",
    }


def _parse_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Groupement par session utilisateur
# ---------------------------------------------------------------------------

def group_by_session(raw_events: list[dict], session_minutes: int = 60) -> list[dict]:
    """
    Regroupe les événements en sessions utilisateur.

    Une session est définie comme une séquence d'événements du même
    utilisateur sans interruption de plus de `session_minutes` minutes.
    """
    # Tri chronologique
    events = sorted(raw_events, key=lambda e: (e["username"], e["timestamp"]))

    sessions = []
    current_session: dict = {}

    for ev in events:
        user = ev["username"]
        ts   = ev["timestamp"]

        if (
            not current_session
            or current_session["username"] != user
            or (ts - current_session["last_ts"]).total_seconds() > session_minutes * 60
        ):
            if current_session:
                sessions.append(current_session)
            current_session = _new_session(user, ts)

        _update_session(current_session, ev)

    if current_session:
        sessions.append(current_session)

    return sessions


def _new_session(username: str, ts: datetime) -> dict:
    return {
        "username":         username,
        "start_ts":         ts,
        "last_ts":          ts,
        "events":           [],
        "ips_seen":         set(),
        "first_ip":         None,
        "file_paths":       [],
        "process_names":    [],
        "command_lines":    [],
        "bytes_sent_total": 0,
        "failed_logins":    0,
        "login_count":      0,
        "logout_count":     0,
    }


def _update_session(session: dict, ev: dict) -> None:
    session["last_ts"] = ev["timestamp"]
    session["events"].append(ev)

    eid = ev["event_id"]

    # Logins réussis
    if eid in WINDOWS_EVENT_IDS["login_success"]:
        session["login_count"] += 1
        ip = ev.get("src_ip", "")
        if ip:
            if session["first_ip"] is None:
                session["first_ip"] = ip
            session["ips_seen"].add(ip)

    # Logins échoués
    if eid in WINDOWS_EVENT_IDS["login_failed"]:
        session["failed_logins"] += 1

    # Déconnexions
    if eid in WINDOWS_EVENT_IDS["logout"]:
        session["logout_count"] += 1

    # Accès fichiers
    if eid in WINDOWS_EVENT_IDS["file_access"]:
        path = ev.get("file_path", "")
        if path:
            session["file_paths"].append(path)

    # Processus
    if eid in WINDOWS_EVENT_IDS["process"]:
        pname = ev.get("process_name", "")
        cmd   = ev.get("command_line", "")
        if pname:
            session["process_names"].append(pname)
        if cmd:
            session["command_lines"].append(cmd)

    # Réseau
    if eid in WINDOWS_EVENT_IDS["network"]:
        session["bytes_sent_total"] += ev.get("bytes_sent", 0)


# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

def compute_entropy(values: list[str]) -> float:
    """Entropie de Shannon normalisée sur une liste de chaînes."""
    if not values:
        return 0.0
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def build_features(session: dict) -> dict:
    """
    Construit le vecteur de features UEBA pour une session.

    Toutes les features sont SIEM-agnostiques : elles reposent sur des
    comportements relatifs (z-scores, entropie, ratios) plutôt que sur
    des valeurs absolues spécifiques à Wazuh.
    """
    ts    = session["start_ts"]
    hour  = ts.hour
    wday  = ts.weekday()   # 0 = lundi, 6 = dimanche

    nb_files     = len(session["file_paths"])
    nb_sensitive = sum(1 for p in session["file_paths"] if SENSITIVE_PATH.lower() in p.lower())
    nb_processes = len(session["process_names"])

    duration_min = max(
        (session["last_ts"] - session["start_ts"]).total_seconds() / 60,
        1  # Évite division par zéro
    )

    # IP nouvelle détectée (autre que la première IP de session)
    known_ips  = session["ips_seen"]
    new_ip_flag = int(len(known_ips) > 1)

    return {
        # --- Temporel ---
        "hour":        hour,
        "is_night":    int(hour < WORK_HOUR_START or hour >= WORK_HOUR_END),
        "is_weekend":  int(wday >= 5),

        # --- Fichiers ---
        "nb_files_accessed":  nb_files,
        "nb_sensitive_files": nb_sensitive,
        "sensitive_path_access": int(nb_sensitive > 0),

        # --- Authentification ---
        "nb_failed_logins": session["failed_logins"],

        # --- Processus ---
        "nb_processes": nb_processes,
        "process_name": session["process_names"][0] if session["process_names"] else "",
        "command_line": session["command_lines"][0]  if session["command_lines"]  else "",

        # --- Réseau ---
        "bytes_sent":  session["bytes_sent_total"],
        "new_ip":      new_ip_flag,

        # --- Vélocité ---
        "velocity": round(nb_files / duration_min, 4),

        # --- Entropie des commandes ---
        "entropy_commands": round(compute_entropy(session["command_lines"]), 4),

        # --- Métadonnées de session ---
        "session_duration_min": round(duration_min, 2),
        "username":  session["username"],
        "timestamp": ts.isoformat(),
    }


# ---------------------------------------------------------------------------
# Z-scores inter-sessions
# ---------------------------------------------------------------------------

def add_zscores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ajoute les z-scores de nb_files_accessed et nb_failed_logins.

    Les z-scores sont calculés par utilisateur pour capturer les déviations
    comportementales individuelles (baseline personnalisée).
    """
    for col, zcol in [("nb_files_accessed", "z_score_files"),
                       ("nb_failed_logins",  "z_score_logins")]:
        df[zcol] = df.groupby("username")[col].transform(
            lambda x: stats.zscore(x, ddof=1) if len(x) > 1 else pd.Series([0.0] * len(x), index=x.index)
        )
        df[zcol] = df[zcol].fillna(0.0).round(4)

    return df


# ---------------------------------------------------------------------------
# Point d'entrée principal
# ---------------------------------------------------------------------------

def parse_alerts_to_dataframe(filepath: str, session_minutes: int = 60) -> pd.DataFrame:
    """
    Pipeline complet : alerts.json → DataFrame de features UEBA.

    Args:
        filepath       : Chemin vers alerts.json
        session_minutes: Durée maximale d'inactivité pour découper les sessions

    Returns:
        DataFrame avec toutes les features UEBA
    """
    print(f"\n{'='*60}")
    print("  UEBA Parser — Extraction des features depuis Wazuh")
    print(f"{'='*60}\n")

    # 1. Chargement
    alerts = load_alerts(filepath)
    if not alerts:
        print("[ERREUR] Aucune alerte chargée. Vérifiez le fichier.", file=sys.stderr)
        return pd.DataFrame()

    # 2. Extraction des champs bruts
    raw_events = []
    for alert in alerts:
        extracted = extract_raw_fields(alert)
        if extracted:
            raw_events.append(extracted)

    print(f"[INFO] {len(raw_events)} événements valides extraits")

    if not raw_events:
        return pd.DataFrame()

    # 3. Groupement en sessions
    sessions = group_by_session(raw_events, session_minutes)
    print(f"[INFO] {len(sessions)} sessions utilisateur construites")

    # 4. Feature engineering
    features_list = [build_features(s) for s in sessions]
    df = pd.DataFrame(features_list)

    # 5. Z-scores
    df = add_zscores(df)

    # Réordonner les colonnes pour correspondre à la spec du projet
    ordered_cols = [
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
    existing_cols = [c for c in ordered_cols if c in df.columns]
    df = df[existing_cols]

    print(f"\n[OK] DataFrame UEBA construit : {df.shape[0]} sessions × {df.shape[1]} features")
    print(f"[OK] Utilisateurs détectés : {df['username'].unique().tolist()}")
    return df


# ---------------------------------------------------------------------------
# CLI rapide
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Parse Wazuh alerts.json → dataset.csv prêt pour le pipeline ML UEBA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Export par défaut vers dataset.csv
  python3 parse_logs.py /var/ossec/logs/alerts/alerts.json

  # Export vers un nom personnalisé, sessions de 30 min
  python3 parse_logs.py /var/ossec/logs/alerts/alerts.json -o mon_dataset.csv --session-min 30
        """,
    )
    parser.add_argument(
        "filepath",
        help="Chemin vers alerts.json (ex: /var/ossec/logs/alerts/alerts.json)",
    )
    parser.add_argument(
        "--output", "-o",
        default="dataset.csv",
        help="Fichier CSV de sortie (défaut: dataset.csv)",
    )
    parser.add_argument(
        "--session-min",
        type=int,
        default=60,
        help="Durée maximale d'inactivité pour couper une session en minutes (défaut: 60)",
    )
    args = parser.parse_args()

    df = parse_alerts_to_dataframe(args.filepath, args.session_min)

    if df.empty:
        print("\n[ERREUR] Aucune donnée extraite — vérifiez le fichier alerts.json.", file=sys.stderr)
        sys.exit(1)

    df.to_csv(args.output, index=False)

    print(f"\n{'='*60}")
    print(f"  Dataset exporté : {args.output}")
    print(f"{'='*60}")
    print(f"  Sessions   : {len(df)}")
    print(f"  Features   : {len(df.columns)}")
    print(f"  Utilisateurs: {df['username'].nunique()} — {df['username'].unique().tolist()}")
    print(f"  Période    : {df['timestamp'].min()}  →  {df['timestamp'].max()}")
    print(f"\n  Colonnes exportées :")
    for col in df.columns:
        print(f"    - {col}")
    print(f"\n  Statistiques clés :")
    print(df[["nb_files_accessed", "nb_failed_logins", "nb_processes",
              "bytes_sent", "velocity", "entropy_commands"]].describe().round(3).to_string())
    print(f"\n[OK] Prêt à charger dans le notebook : pd.read_csv('{args.output}')")
