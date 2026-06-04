#!/usr/bin/env bash
# =============================================================
# run_daemon.sh — Lance le daemon UEBA en temps réel
# Usage : ./scripts/run_daemon.sh [--verbose]
# =============================================================
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[UEBA] Démarrage du daemon de détection..."
echo "[UEBA] Logs : /var/log/ueba_detection.log"
echo "[UEBA] Alertes : /var/log/ueba_alerts.json"
echo ""

exec python3 -m ueba.integration.daemon --config config/config.yaml "$@"
