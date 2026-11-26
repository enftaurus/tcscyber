#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# ScanForge — Local Development Launcher Script (dev.sh)
# ══════════════════════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔬 [ScanForge] Initialising development environment..."

# 0. Kill existing uvicorn on port 8000 if running
if lsof -ti:8000 >/dev/null 2>&1; then
    echo "🧹 Freeing port 8000 from previous background process..."
    fuser -k 8000/tcp >/dev/null 2>&1 || pkill -f uvicorn >/dev/null 2>&1 || true
    sleep 1
fi

# 1. Virtual Environment Check & Setup
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "📦 Creating virtual environment at .venv..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# 2. Install / Verify Dependencies
echo "📥 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r backend/requirements.txt -r backend/requirements-dev.txt

# 3. Generate Synthetic PE Samples
echo "⚡ Generating synthetic demo PE samples..."
python3 backend/samples/generate_samples.py

# 4. Banner & Server Launch
echo "======================================================================"
echo " 🔬 ScanForge Static PE Threat Analysis Platform"
echo "======================================================================"
echo " 🌐 Web UI:   http://localhost:8000/app"
echo " 📡 API Base: http://localhost:8000"
echo " 🩺 Health:   http://localhost:8000/health"
echo "======================================================================"
echo " Starting Uvicorn development server with live reload..."
echo ""

cd "$SCRIPT_DIR/backend"
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload
