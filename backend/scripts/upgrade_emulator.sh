#!/usr/bin/env bash
# upgrade_emulator.sh — Automate upgrading Kavach Sandbox AVD to Android 14 (API 34).
set -euo pipefail

# Configure Android SDK paths
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

echo "=== Upgrading Kavach Sandbox to Android 14 (API 34) ==="

# 1. Download Android 14 x86_64 Google APIs system image
echo "[1/3] Downloading Android 14 Google APIs system image..."
sdkmanager "system-images;android-34;google_apis;x86_64"

# 2. Delete existing AVD if it exists
echo "[2/3] Checking and deleting old kavach_sandbox AVD..."
avdmanager delete avd -n kavach_sandbox || true

# 3. Create the new AVD
echo "[3/3] Creating new kavach_sandbox AVD with API 34..."
echo "no" | avdmanager create avd \
  -n kavach_sandbox \
  -k "system-images;android-34;google_apis;x86_64" \
  --force

echo "=== Upgrade Complete! ==="
echo "You can now start KAVACH AI. The sandbox will boot using Android 14 (API 34) with optimized ARM64 translation."
