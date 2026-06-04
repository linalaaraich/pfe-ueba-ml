#!/usr/bin/env bash
# =============================================================
# export_dataset.sh — Exporte dataset.csv depuis alerts.json
# Usage : ./scripts/export_dataset.sh [alerts_path] [output]
# =============================================================
set -euo pipefail

ALERTS="${1:-/var/ossec/logs/alerts/alerts.json}"
OUTPUT="${2:-data/dataset.csv}"

cd "$(dirname "$0")/.."

echo "[UEBA] Export dataset depuis : $ALERTS"
python3 -m ueba.features.parse_logs "$ALERTS" --output "$OUTPUT"
echo "[UEBA] Dataset prêt : $OUTPUT"
