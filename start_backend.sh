#!/usr/bin/env bash
# ============================================================
# CPEDS-X Backend - one-click start (macOS/Linux)
# ============================================================
set -e
cd "$(dirname "$0")/backend"

echo "[CPEDS-X] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

echo "[CPEDS-X] Installing dependencies (first run only)..."
python -m pip install --upgrade pip >/dev/null
pip install -r requirements.txt

echo "[CPEDS-X] Starting FastAPI on http://localhost:8000 (docs at /docs)"
uvicorn main:app --reload --port 8000
