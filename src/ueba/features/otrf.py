#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ueba.features.otrf
=================
Adaptateur pour les jeux de données **OTRF Security-Datasets** (ex-Mordor) :
télémétrie Windows / Sysmon réelle au format JSON d'événements ATT&CK.

Pourquoi ce module ?
--------------------
Les datasets OTRF sont des événements Windows/Sysmon « à plat » (clés au niveau
racine : `EventID`, `Image`, `CommandLine`, `TargetFilename`, `SubjectUserName`,
`@timestamp`, …), alors que `parse_logs.extract_raw_fields` attend la structure
IMBRIQUÉE de Wazuh (`data.win.system.eventID`, `data.win.eventdata.image`, …).
Ce module convertit un événement OTRF vers LE MÊME dict d'événement brut, puis
réutilise tel quel le reste du pipeline (`group_by_session` → `build_features` →
z-scores). Résultat : on entraîne/évalue sur de la VRAIE télémétrie Windows sans
machine cloud 24/7.

Récupérer un dataset :
    https://github.com/OTRF/Security-Datasets  (dossier datasets/atomic ou compound)
    ex. un .json (souvent NDJSON, parfois .gz) d'événements Sysmon/Security.

CLI :
    python -m ueba.features.otrf chemin/vers/dataset.json --output data/dataset.csv
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import Optional

import pandas as pd

from ueba.features.parse_logs import (
    _parse_timestamp,
    add_zscores,
    build_features,
    group_by_session,
    DATASET_COLUMNS,
)


def _get_ci(event: dict, *keys: str):
    """Récupère la 1re clé présente (insensible à la casse — les datasets OTRF
    varient : `EventID`/`event_id`, `Image`/`image`, etc.)."""
    lower = {k.lower(): v for k, v in event.items()} if isinstance(event, dict) else {}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, ""):
            return v
    return None


def _otrf_timestamp(event: dict):
    """OTRF : `@timestamp` (ISO) ou Sysmon `UtcTime` (« YYYY-MM-DD HH:MM:SS.mmm »)."""
    raw = _get_ci(event, "@timestamp", "EventTime", "UtcTime", "TimeCreated", "timestamp")
    if isinstance(raw, str) and " " in raw and "T" not in raw:
        raw = raw.replace(" ", "T", 1)   # UtcTime → ISO-like
    return _parse_timestamp(raw)


def extract_otrf_event(event: dict) -> Optional[dict]:
    """
    Convertit un événement OTRF/Sysmon « à plat » vers le dict brut attendu par
    le pipeline (mêmes clés que parse_logs.extract_raw_fields). None si inutilisable.
    """
    if not isinstance(event, dict):
        return None
    ts = _otrf_timestamp(event)
    if ts is None:
        return None

    event_id = str(_get_ci(event, "EventID", "event_id", "Id") or "").strip()

    # Sysmon `User` = "DOMAINE\\utilisateur" → on garde l'utilisateur, en minuscule
    user_raw = (
        _get_ci(event, "SubjectUserName", "TargetUserName", "User", "AccountName")
        or "unknown"
    )
    username = str(user_raw).split("\\")[-1].strip().lower()

    return {
        "timestamp":    ts,
        "username":     username,
        "event_id":     event_id,
        "rule_id":      "",
        "agent_name":   str(_get_ci(event, "Hostname", "Computer", "host") or ""),
        "src_ip":       str(_get_ci(event, "IpAddress", "SourceIp", "SourceIsIpv6") or ""),
        "file_path":    str(_get_ci(event, "TargetFilename", "ObjectName") or ""),
        "process_name": str(_get_ci(event, "Image", "NewProcessName", "ProcessName") or ""),
        "command_line": str(_get_ci(event, "CommandLine") or ""),
        # Sysmon EID 3 ne porte PAS de compteur d'octets → bytes_sent reste 0
        # (cf. audit RC-2 ; vérifier sur vos données et re-sourcer si besoin).
        "bytes_sent":   0,
        "dst_ip":       str(_get_ci(event, "DestinationIp") or ""),
    }


def _read_json_records(filepath: str) -> list[dict]:
    """Lit un fichier OTRF : NDJSON ou tableau JSON, éventuellement gzip (.gz)."""
    path = Path(filepath)
    if not path.exists():
        print(f"[ERREUR] Fichier introuvable : {filepath}", file=sys.stderr)
        return []
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        content = fh.read().strip()

    if not content:
        return []
    if content.startswith("["):
        try:
            data = json.loads(content)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass
    records = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"[WARN] Ligne {i} invalide, ignorée.", file=sys.stderr)
    return records


def parse_otrf_to_dataframe(filepath: str, session_minutes: int = 60) -> pd.DataFrame:
    """Pipeline complet : dataset OTRF → DataFrame de features UEBA."""
    records = _read_json_records(filepath)
    print(f"[INFO] {len(records)} événements OTRF chargés")
    raw = [e for r in records if (e := extract_otrf_event(r))]
    print(f"[INFO] {len(raw)} événements valides extraits")
    if not raw:
        return pd.DataFrame()

    sessions = group_by_session(raw, session_minutes)
    print(f"[INFO] {len(sessions)} sessions construites")
    df = pd.DataFrame([build_features(s) for s in sessions])
    df = add_zscores(df)
    cols = [c for c in DATASET_COLUMNS if c in df.columns]
    df = df[cols]
    print(f"[OK] DataFrame : {df.shape[0]} sessions × {df.shape[1]} colonnes")
    if "username" in df.columns:
        print(f"[OK] Utilisateurs : {df['username'].unique().tolist()[:10]}")
    return df


def main():
    ap = argparse.ArgumentParser(
        description="OTRF/Mordor Security-Datasets → dataset.csv (features UEBA)",
    )
    ap.add_argument("filepath", help="Dataset OTRF (.json / .json.gz / NDJSON)")
    ap.add_argument("--output", "-o", default="data/dataset.csv")
    ap.add_argument("--session-min", type=int, default=60)
    args = ap.parse_args()

    df = parse_otrf_to_dataframe(args.filepath, args.session_min)
    if df.empty:
        print("[ERREUR] Aucune donnée extraite — vérifiez le format/les champs.",
              file=sys.stderr)
        sys.exit(1)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"\n[OK] Écrit : {args.output}  ({len(df)} sessions)")
    print("    → mettez USE_REAL_DATA = True dans le notebook pour l'utiliser.")


if __name__ == "__main__":
    main()
