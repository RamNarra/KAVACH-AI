#!/usr/bin/env bash
# KAVACH AI Backend Startup Script
# Use this instead of running uvicorn with --reload to avoid the
# "OS file watch limit reached" crash caused by the venv having 40k+ files.
# If you want hot-reload during development, run:
#   echo 524288 | sudo tee /proc/sys/fs/inotify/max_user_watches
# then use: ./start.sh --dev

set -e
cd "$(dirname "$0")"

if [[ "$1" == "--dev" ]]; then
    echo "[kavach] Starting in DEV mode with hot-reload..."
    exec venv/bin/uvicorn main:app \
        --host 0.0.0.0 \
        --port 8080 \
        --reload \
        --reload-dir . \
        --reload-exclude "venv" \
        --reload-exclude "tools"
else
    echo "[kavach] Starting backend (no hot-reload)..."
    exec venv/bin/uvicorn main:app \
        --host 0.0.0.0 \
        --port 8080 \
        --workers 1
fi
