#!/usr/bin/env bash
# ==============================================================================
# Mneti — Nakuru County Referral and Teaching Hospital (NCRTH)
# Unified Startup and Orchestration Script
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON_BIN="$VENV_DIR/bin/python3"
PORT=${PORT:-5000}

echo ""
echo "=================================================================="
echo "   Mneti: Network Asset Discovery & Physical Location System     "
echo "   Nakuru County Referral & Teaching Hospital (NCRTH)            "
echo "=================================================================="
echo ""

# 1. Check / Initialize Virtual Environment
if [ ! -f "$PYTHON_BIN" ]; then
    echo "[*] Setting up virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install flask scapy requests psutil
fi

# 2. Seed Database with Realistic Hospital Inventory if not present
if [ ! -f "$SCRIPT_DIR/server/mneti.db" ] || [ "$1" == "--seed" ]; then
    echo "[*] Initializing and seeding NCRTH hospital assets database..."
    "$PYTHON_BIN" "$SCRIPT_DIR/server/seed.py"
fi

echo ""
echo "------------------------------------------------------------------"
echo " ✅ Server Starting on http://0.0.0.0:$PORT"
echo " 🌐 Dashboard: http://localhost:$PORT"
echo "------------------------------------------------------------------"
echo " Quick Simulation & Testing Commands (in another terminal):"
echo "   • Run Client Agent Check-in:"
echo "       $PYTHON_BIN client/agent.py --once"
echo "   • Trigger IP Collision Attack:"
echo "       $PYTHON_BIN simulation/test_conflict.py"
echo "   • Restore Genuine Workstation MAC:"
echo "       $PYTHON_BIN simulation/test_conflict.py --restore"
echo "------------------------------------------------------------------"
echo ""

# 3. Launch Flask Server
exec "$PYTHON_BIN" "$SCRIPT_DIR/server/app.py"
