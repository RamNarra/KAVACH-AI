#!/usr/bin/env bash
# upgrade_emulator.sh — Automate upgrading Kavach Sandbox AVD to Android 11 (API 30) for native ARM translation and adb root compatibility.
set -euo pipefail

# Configure Android SDK paths
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

echo "=== Configuring Kavach Sandbox to Android 11 (API 30) ==="

# 1. Download Android 11 x86_64 Google APIs system image
echo "[1/3] Downloading Android 11 Google APIs system image..."
sdkmanager "system-images;android-30;google_apis;x86_64"

# 2. Delete existing AVD if it exists
echo "[2/3] Checking and deleting old kavach_sandbox AVD..."
avdmanager delete avd -n kavach_sandbox || true

# 3. Create the new AVD
echo "[3/3] Creating new kavach_sandbox AVD with API 30..."
echo "no" | avdmanager create avd \
  -n kavach_sandbox \
  -k "system-images;android-30;google_apis;x86_64" \
  --force

echo "=== Setup Complete! ==="
echo "You can now start KAVACH AI. The sandbox will boot using Android 11 (API 30) with native ARM translation and adb root compatibility."
