#!/usr/bin/env bash
# Move to the project root directory regardless of invocation path
cd "$(dirname "$0")/.."
# ============================================================
# KAVACH AI — MobSF Android Emulator & ADB TCP Bridge
# ============================================================

set -e

# ANSI styling
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Determine Android SDK Home
ANDROID_HOME="${ANDROID_HOME:-/home/p4cketsn1ff3r/Android/Sdk}"
EMULATOR_BIN="$ANDROID_HOME/emulator/emulator"
ADB_BIN="$ANDROID_HOME/platform-tools/adb"
AVD_NAME="kavach_sandbox"

echo -e "${BLUE}============================================================${NC}"
echo -e "${GREEN}📱 Initializing MobSF Android Emulator & Port Bridge...${NC}"
echo -e "${BLUE}============================================================${NC}"

# Check prerequisites
if [ ! -f "$EMULATOR_BIN" ]; then
    echo -e "${RED}❌ Error: Emulator binary not found at $EMULATOR_BIN${NC}"
    exit 1
fi
if [ ! -f "$ADB_BIN" ]; then
    echo -e "${RED}❌ Error: ADB binary not found at $ADB_BIN${NC}"
    exit 1
fi
if ! command -v socat &>/dev/null; then
    echo -e "${RED}❌ Error: socat utility is not installed.${NC}"
    exit 1
fi

# 1. Start Emulator if not already running
echo -e "\n${YELLOW}[Step 1/4] Checking Android AVD status...${NC}"
EMU_RUNNING=0
if "$ADB_BIN" devices | grep -E "emulator-|127.0.0.1:55" &>/dev/null; then
    echo -e "  ✓ Emulator is already detected by ADB."
    EMU_RUNNING=1
else
    # Check process list just in case
    if pgrep -f "$AVD_NAME" &>/dev/null; then
        echo -e "  ✓ Emulator process is running but not yet connected to ADB."
        EMU_RUNNING=1
    fi
fi

if [ $EMU_RUNNING -eq 0 ]; then
    echo -e "  🚀 Starting AVD '$AVD_NAME' headlessly in background..."
    "$EMULATOR_BIN" -avd "$AVD_NAME" \
        -no-window \
        -no-audio \
        -no-boot-anim \
        -gpu swiftshader \
        -memory 3072 \
        -partition-size 4096 \
        -no-snapshot-save > /dev/null 2>&1 &
    
    echo -e "  ⌛ Waiting for emulator to start boot sequence..."
    sleep 5
fi

# 2. Wait for boot completion
echo -e "\n${YELLOW}[Step 2/4] Waiting for Android OS boot completion...${NC}"
BOOT_TIMEOUT=180
ELAPSED=0
BOOTED=0

while [ $ELAPSED -lt $BOOT_TIMEOUT ]; do
    BOOT_PROP=$("$ADB_BIN" shell getprop sys.boot_completed 2>/dev/null || true)
    if [ "${BOOT_PROP:0:1}" = "1" ]; then
        BOOTED=1
        break
    fi
    echo -n "."
    sleep 3
    ELAPSED=$((ELAPSED + 3))
done

if [ $BOOTED -eq 1 ]; then
    echo -e "\n  ✓ Emulator booted successfully!"
else
    echo -e "\n${RED}❌ Error: Emulator boot timed out or failed.${NC}"
    exit 1
fi

# 3. Setup root access & Frida-server
echo -e "\n${YELLOW}[Step 3/4] Initializing Root Access and Frida-Server...${NC}"
echo -e "  Enabling ADB root..."
"$ADB_BIN" root
sleep 2

# Check if frida-server is running
FRIDA_RUNNING=0
if "$ADB_BIN" shell pidof frida-server &>/dev/null; then
    echo -e "  ✓ frida-server is already running on the emulator."
    FRIDA_RUNNING=1
fi

if [ $FRIDA_RUNNING -eq 0 ]; then
    echo -e "  Starting frida-server..."
    "$ADB_BIN" shell "setenforce 0" || true
    # Run frida-server in the background on the device
    "$ADB_BIN" shell "nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &" || true
    sleep 2
    if "$ADB_BIN" shell pidof frida-server &>/dev/null; then
        echo -e "  ✓ frida-server started successfully."
    else
        echo -e "  ${RED}⚠️ Warning: Could not verify if frida-server is running.${NC}"
    fi
fi

# 4. Start socat port bridge on the host
echo -e "\n${YELLOW}[Step 4/4] Activating TCP Port Bridge (5556 -> 127.0.0.1:5555)...${NC}"
# Kill existing socat on port 5556 to avoid bind address collisions
if lsof -i :5556 &>/dev/null; then
    echo -e "  ⚠️ Port 5556 is currently in use. Checking if it's socat..."
    SOCAT_PID=$(pgrep -f "socat tcp-listen:5556" || true)
    if [ -n "$SOCAT_PID" ]; then
        echo -e "  Terminating old socat process (PID: $SOCAT_PID)..."
        kill -9 "$SOCAT_PID" || true
        sleep 1
    else
        echo -e "  ${RED}❌ Error: Port 5556 is in use by another process. Cannot start bridge.${NC}"
        exit 1
    fi
fi

echo -e "  Launching socat bridge..."
socat tcp-listen:5556,fork,reuseaddr tcp:127.0.0.1:5555 > /dev/null 2>&1 &
BRIDGE_PID=$!

sleep 1
if pgrep -p $BRIDGE_PID &>/dev/null || ps -p $BRIDGE_PID &>/dev/null; then
    echo -e "  ✓ socat port bridge is active (PID: $BRIDGE_PID)."
else
    # fallback check in case of shell wrapping
    if lsof -i :5556 &>/dev/null; then
        echo -e "  ✓ socat port bridge is active and listening on port 5556."
    else
        echo -e "  ${RED}❌ Error: Failed to start socat bridge.${NC}"
        exit 1
    fi
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}🎉 MobSF Android & TCP Bridge Setup Complete!${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "  - Emulator status: ${GREEN}Online & Rooted${NC}"
echo -e "  - ADB Host Port:   ${GREEN}5556 (bridged to Docker gateway)${NC}"
echo -e "  - Frida Server:    ${GREEN}Running${NC}"
echo -e "\nYou can now start/restart your MobSF docker container."
echo -e "${BLUE}============================================================${NC}"
