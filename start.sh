#!/bin/bash
# ThreatLens — Development Start Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait 2>/dev/null
    echo "Stopped."
}
trap cleanup EXIT INT TERM

echo "================================="
echo "  ThreatLens Development Server"
echo "================================="

# Backend
echo "[1/2] Starting Backend on :8000..."
cd "$SCRIPT_DIR/backend"
if [ ! -d "venv" ]; then
    echo "  Creating Python venv..."
    python3 -m venv venv
    . venv/bin/activate
    pip install -r requirements.txt
else
    . venv/bin/activate
fi
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
sleep 2

# Frontend
echo "[2/2] Starting Frontend on :5000..."
cd "$SCRIPT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    echo "  Installing npm dependencies..."
    npm install
fi
npx vite --host 0.0.0.0 --port 5000 &
FRONTEND_PID=$!
sleep 1

echo ""
echo "================================="
echo "  ThreatLens running:"
echo "  - API:      http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo "  - UI:       http://localhost:5000"
echo "================================="
echo "Press Ctrl+C to stop."

wait
