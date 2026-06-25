#!/usr/bin/env bash
# Move to the project root directory regardless of invocation path
cd "$(dirname "$0")/.."
# ============================================================
# KAVACH AI — Sequential Backend & Services Starter Script
# ============================================================

set -e

# ANSI styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ensure we clean up background processes on exit
trap cleanup INT TERM EXIT

cleanup() {
  echo -e "\n${RED}🛑 Stopping KAVACH AI Backend & Services...${NC}"
  if [ -n "$SOCAT_PID" ]; then
    kill "$SOCAT_PID" 2>/dev/null || true
  fi
  if [ -n "$BACKEND_PID" ]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  exit 0
}

echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}🛡️  Starting KAVACH AI Backend & Automated Services...${NC}"
echo -e "${BLUE}============================================================${NC}"

# 1. Load Root Environment Variables
if [ -f ".env" ]; then
    echo -e "  Loading environment variables from root .env..."
    cp .env backend/.env
    export $(grep -v '^#' .env | xargs)
else
    echo -e "${RED}❌ Error: Root '.env' file not found. Please create it first.${NC}"
    exit 1
fi

# 2. Check for active emulators and launch the socat port bridge automatically
echo -e "\n${YELLOW}[Step 1/3] Detecting running emulators for port bridge...${NC}"
ADB_BIN="adb"
if ! command -v adb &>/dev/null; then
    if [ -f "/home/p4cketsn1ff3r/Android/Sdk/platform-tools/adb" ]; then
        ADB_BIN="/home/p4cketsn1ff3r/Android/Sdk/platform-tools/adb"
    fi
fi

EMU_PORT=""
if "$ADB_BIN" devices | grep -E "127.0.0.1:6562|device" | grep "6562" &>/dev/null; then
    echo -e "  📱 Genymotion emulator detected on port ${GREEN}6562${NC}."
    EMU_PORT="6562"
elif "$ADB_BIN" devices | grep -E "127.0.0.1:5555|device" | grep "5555" &>/dev/null; then
    echo -e "  📱 Standard AOSP emulator detected on port ${GREEN}5555${NC}."
    EMU_PORT="5555"
elif "$ADB_BIN" devices | grep -E "emulator-5554" &>/dev/null; then
    echo -e "  📱 Standard AOSP emulator detected on serial ${GREEN}emulator-5554${NC}."
    EMU_PORT="5555"
fi

if [ -n "$EMU_PORT" ]; then
    # Kill any existing socat listening on port 5556
    SOCAT_PID_OLD=$(pgrep -f "socat tcp-listen:5556" || true)
    if [ -n "$SOCAT_PID_OLD" ]; then
        echo -e "  ⚠️ Terminating old port bridge (PID: $SOCAT_PID_OLD)..."
        kill -9 "$SOCAT_PID_OLD" || true
        sleep 1
    fi
    
    echo -e "  🔗 Activating TCP Port Bridge (Host 5556 -> Emulator $EMU_PORT)..."
    socat tcp-listen:5556,fork,reuseaddr tcp:127.0.0.1:$EMU_PORT >/dev/null 2>&1 &
    SOCAT_PID=$!
    echo -e "  ✓ Port bridge started successfully (PID: $SOCAT_PID)."
else
    echo -e "  ${RED}⚠️ No active emulators found (Checked ports 6562, 5555).${NC}"
    echo -e "  Dynamic analysis runs will skip/fail unless an emulator is booted and bridged."
fi

# 3. Start MobSF Docker Container
echo -e "\n${YELLOW}[Step 2/3] Launching MobSF Docker service...${NC}"
chmod +x scripts/start_mobsf.sh
./scripts/start_mobsf.sh

# 4. Start FastAPI Backend
echo -e "\n${YELLOW}[Step 3/3] Starting FastAPI Backend on port 8080...${NC}"

# Kill any existing backend process bound to port 8080 to prevent bind address collisions
BACKEND_PID_OLD=$(lsof -t -i:8080 || true)
if [ -n "$BACKEND_PID_OLD" ]; then
    echo -e "  ⚠️ Terminating old backend instance (PID: $BACKEND_PID_OLD)..."
    kill -9 $BACKEND_PID_OLD 2>/dev/null || true
    sleep 1
fi

cd backend
if [ -d "venv" ]; then
    source venv/bin/activate
fi
uvicorn main:app --host 0.0.0.0 --port 8080 &
BACKEND_PID=$!
echo -e "  ✓ FastAPI backend started successfully (PID: $BACKEND_PID)."
cd ..

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}🎉 KAVACH AI Backend & Services are Online!${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "  - Backend API:  ${BLUE}http://localhost:8080${NC}"
echo -e "  - MobSF Panel:  ${BLUE}http://localhost:8000${NC}"
echo -e "Press ${YELLOW}Ctrl+C${NC} to shut down all backend services cleanly."
echo -e "${BLUE}============================================================${NC}"

wait
