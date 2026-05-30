import os
import time
import subprocess
import logging
import threading
from typing import Dict, Any

# Configure logger
logger = logging.getLogger("kavach-bootstrap")
logger.setLevel(logging.INFO)

# Setup SDK environment
ANDROID_HOME = "/home/p4cketsn1ff3r/Android/Sdk"
os.environ["ANDROID_HOME"] = ANDROID_HOME
os.environ["PATH"] = f"{ANDROID_HOME}/cmdline-tools/latest/bin:{ANDROID_HOME}/platform-tools:{ANDROID_HOME}/emulator:{os.environ.get('PATH', '')}"

ADB_PATH = os.path.join(ANDROID_HOME, "platform-tools", "adb")
EMULATOR_PATH = os.path.join(ANDROID_HOME, "emulator", "emulator")

# Shared state
sandbox_status = "UNAVAILABLE"
error_message = None
emulator_running = False
adb_connected = False
frida_server_running = False

status_lock = threading.Lock()

def get_status_dict() -> Dict[str, Any]:
    with status_lock:
        return {
            "sandbox_status": sandbox_status,
            "emulator_running": emulator_running,
            "adb_connected": adb_connected,
            "frida_server_running": frida_server_running,
            "error_message": error_message
        }

def update_status(status: str, emu: bool, adb: bool, frida_srv: bool, err: str = None):
    global sandbox_status, emulator_running, adb_connected, frida_server_running, error_message
    with status_lock:
        sandbox_status = status
        emulator_running = emu
        adb_connected = adb
        frida_server_running = frida_srv
        error_message = err

def is_emulator_running_adb() -> bool:
    try:
        res = subprocess.run([ADB_PATH, "devices"], capture_output=True, text=True, timeout=20)
        for line in res.stdout.splitlines():
            if "emulator-" in line:
                return True
    except Exception:
        pass
    return False

def is_emulator_online_adb() -> bool:
    try:
        res = subprocess.run([ADB_PATH, "devices"], capture_output=True, text=True, timeout=20)
        for line in res.stdout.splitlines():
            if "emulator-" in line and "device" in line:
                return True
    except Exception:
        pass
    return False

def check_frida_server_running() -> bool:
    try:
        # Check if frida-server-16 is running on the target emulator
        res = subprocess.run([ADB_PATH, "shell", "ps -A | grep frida-server-16"], capture_output=True, text=True, timeout=20)
        if "frida-server-16" in res.stdout:
            return True
    except Exception:
        pass
    return False

def start_frida_server() -> bool:
    try:
        logger.info("[sandbox] frida-server-16 not detected. Attempting to start...")
        # 1. Run adb root
        subprocess.run([ADB_PATH, "root"], capture_output=True, timeout=20)
        
        # 2. Try standard nohup startup using Popen to avoid blocking host processes
        subprocess.Popen(
            [ADB_PATH, "shell", "nohup /data/local/tmp/frida-server-16 < /dev/null > /dev/null 2>&1 &"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        
        if check_frida_server_running():
            logger.info("[sandbox] frida-server-16 started successfully via adb root.")
            return True
            
        # 3. Fallback to su -c
        logger.warning("[sandbox] frida-server-16 failed to launch as root. Trying su -c fallback...")
        subprocess.Popen(
            [ADB_PATH, "shell", "su -c 'nohup /data/local/tmp/frida-server-16 < /dev/null > /dev/null 2>&1 &'"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        
        if check_frida_server_running():
            logger.info("[sandbox] frida-server-16 started successfully via su -c fallback.")
            return True
            
    except Exception as e:
        logger.error(f"[sandbox] Error launching frida-server: {e}")
    return False

def bootstrap_worker():
    logger.info("[sandbox] starting background sandbox bootstrap sequence...")
    update_status("BOOTING", False, False, False, None)

    try:
        # 1. Check if ADB is accessible
        if not os.path.exists(ADB_PATH):
            logger.error(f"[sandbox] adb binary not found at path: {ADB_PATH}")
            update_status("UNAVAILABLE", False, False, False, "ADB binary missing")
            return
            
        # 2. Check if emulator is already running
        logger.info("[sandbox] checking adb devices...")
        emu_already_running = is_emulator_running_adb()
        
        if not emu_already_running:
            # Check if emulator binary exists
            if not os.path.exists(EMULATOR_PATH):
                logger.error(f"[sandbox] emulator binary not found at path: {EMULATOR_PATH}")
                update_status("UNAVAILABLE", False, False, False, "Emulator binary missing")
                return

            logger.info("[sandbox] emulator not running, launching kavach_sandbox...")
            # Spawn emulator in background
            subprocess.Popen(
                [EMULATOR_PATH, "-avd", "kavach_sandbox", "-no-window", "-no-audio"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            logger.info("[sandbox] emulator process already active. Skipping duplicate launch.")
            
        # Wait for boot completion (timeout of 75 seconds)
        booted = False
        start_time = time.time()
        logger.info("[sandbox] waiting for boot completion (75s timeout)...")
        while time.time() - start_time < 75:
            # First wait for device to show up as online in adb
            if is_emulator_online_adb():
                # Check boot completed property
                res = subprocess.run([ADB_PATH, "shell", "getprop sys.boot_completed"], capture_output=True, text=True, timeout=20)
                if "1" in res.stdout:
                    booted = True
                    break
            time.sleep(3)
            
        if not booted:
            logger.error("[sandbox] emulator boot timed out after 75 seconds.")
            update_status("ERROR", emu_already_running, is_emulator_online_adb(), False, "Emulator boot timed out")
            return
        
        logger.info("[sandbox] emulator booted successfully.")
        emu_run = True
        adb_conn = True

        # 3. Check and start Frida Server
        frida_running = check_frida_server_running()
        if not frida_running:
            frida_running = start_frida_server()
            
        if frida_running:
            logger.info("[sandbox] frida-server-16 is running.")
            logger.info("[sandbox] dynamic sandbox READY.")
            update_status("READY", emu_run, adb_conn, True, None)
        else:
            logger.error("[sandbox] frida-server-16 failed to start.")
            update_status("ERROR", emu_run, adb_conn, False, "Frida server failed to start")

    except Exception as e:
        logger.error(f"[sandbox] Bootstrap crashed: {e}")
        update_status("ERROR", False, False, False, str(e))

def start_bootstrap_async():
    t = threading.Thread(target=bootstrap_worker, daemon=True)
    t.start()
