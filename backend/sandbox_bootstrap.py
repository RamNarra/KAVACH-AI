import os
import time
import subprocess
import logging
import threading
from typing import Dict, Any, Optional

from toolchain import configure_android_env, resolve_adb, resolve_emulator

logger = logging.getLogger("kavach-bootstrap")
logger.setLevel(logging.INFO)

configure_android_env()

ANDROID_HOME = os.environ.get("ANDROID_HOME")
ADB_PATH = resolve_adb()
EMULATOR_PATH = resolve_emulator()
SANDBOX_AVD = os.environ.get("SANDBOX_AVD", "kavach_sandbox")
FRIDA_REMOTE_PATH = os.environ.get("FRIDA_SERVER_PATH", "/data/local/tmp/frida-server-16")

sandbox_status = "UNAVAILABLE"
error_message = None
emulator_running = False
adb_connected = False
frida_server_running = False
_bootstrap_started = False

status_lock = threading.Lock()


def get_status_dict() -> Dict[str, Any]:
    with status_lock:
        return {
            "sandbox_status": sandbox_status,
            "emulator_running": emulator_running,
            "adb_connected": adb_connected,
            "frida_server_running": frida_server_running,
            "error_message": error_message,
        }


def update_status(status: str, emu: bool, adb: bool, frida_srv: bool, err: Optional[str] = None):
    global sandbox_status, emulator_running, adb_connected, frida_server_running, error_message
    with status_lock:
        sandbox_status = status
        emulator_running = emu
        adb_connected = adb
        frida_server_running = frida_srv
        error_message = err


def _adb_run(args: list, timeout: float = 20) -> subprocess.CompletedProcess:
    return subprocess.run([ADB_PATH, *args], capture_output=True, text=True, timeout=timeout)


def is_emulator_running_adb() -> bool:
    try:
        res = _adb_run(["devices"])
        return any("emulator-" in line for line in res.stdout.splitlines())
    except Exception:
        return False


def is_emulator_online_adb() -> bool:
    try:
        res = _adb_run(["devices"])
        return any("emulator-" in line and "device" in line for line in res.stdout.splitlines())
    except Exception:
        return False


def is_package_manager_responsive() -> bool:
    try:
        res = _adb_run(["shell", "pm", "path", "android"], timeout=5)
        if "Can't find service" in res.stdout or "Broken pipe" in res.stdout or "Can't find service" in res.stderr:
            return False
        return "package:" in res.stdout or res.returncode == 0
    except Exception:
        return False


def kill_stale_emulator():
    logger.warning("[sandbox] Stale/unresponsive emulator detected. Force-killing to restart...")
    try:
        subprocess.run(["pkill", "-9", "-f", "kavach_sandbox"], capture_output=True)
        subprocess.run(["pkill", "-9", "-f", "qemu-system-x86_64-headless"], capture_output=True)
        avd_dir = os.path.expanduser(f"~/.android/avd/{SANDBOX_AVD}.avd")
        for lock in ["hardware-qemu.ini.lock", "multiinstance.lock"]:
            lock_path = os.path.join(avd_dir, lock)
            if os.path.exists(lock_path):
                try:
                    os.remove(lock_path)
                    logger.info(f"[sandbox] Cleared lock file: {lock_path}")
                except Exception:
                    pass
        time.sleep(2)
    except Exception as e:
        logger.error(f"[sandbox] Error killing stale emulator: {e}")


def check_frida_server_running() -> bool:
    try:
        pidof = _adb_run(["shell", "pidof", os.path.basename(FRIDA_REMOTE_PATH)])
        if pidof.stdout.strip():
            return True
        ps = _adb_run(["shell", "sh", "-c", "ps -A 2>/dev/null | grep -E 'frida-server' || true"])
        return "frida-server" in ps.stdout
    except Exception:
        return False


def start_frida_server() -> bool:
    binary = FRIDA_REMOTE_PATH
    name = os.path.basename(binary)
    try:
        logger.info("[sandbox] frida-server not detected — attempting start...")
        _adb_run(["root"], timeout=15)
        _adb_run(["shell", "setenforce", "0"], timeout=10)

        launch = (
            f"setenforce 0 2>/dev/null; "
            f"killall {name} 2>/dev/null; killall frida-server 2>/dev/null; "
            f"{binary} -D"
        )
        subprocess.Popen(
            [ADB_PATH, "shell", launch],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)

        if check_frida_server_running():
            logger.info("[sandbox] frida-server started.")
            return True

        logger.warning("[sandbox] root launch failed — trying su -c fallback...")
        subprocess.Popen(
            [ADB_PATH, "shell", f"su -c 'setenforce 0; {binary} -D'"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)
        return check_frida_server_running()
    except Exception as exc:
        logger.error(f"[sandbox] Error launching frida-server: {exc}")
        return False


def ensure_sandbox_ready(force_bootstrap: bool = False) -> Dict[str, Any]:
    """Best-effort heal: promote to READY when emulator + frida are actually up."""
    global _bootstrap_started
    online = is_emulator_online_adb()
    
    if online:
        _adb_run(["shell", "setenforce", "0"], timeout=5)
        try:
            _adb_run(["shell", "wm", "dismiss-keyguard"], timeout=10)
        except Exception:
            pass
        boot_res = _adb_run(["shell", "getprop", "sys.boot_completed"], timeout=5)
        is_booted = "1" in boot_res.stdout or is_package_manager_responsive()
        if is_booted:
            pm_ready = False
            for _ in range(30):
                if is_package_manager_responsive():
                    pm_ready = True
                    break
                time.sleep(2)
            if not pm_ready:
                logger.warning("[sandbox] Emulator is online and booted but package manager is unresponsive after 60s. Force-killing to heal...")
                kill_stale_emulator()
                online = False
                _bootstrap_started = False
            
    frida = check_frida_server_running() if online else False

    if online and frida:
        update_status("READY", True, True, True, None)
        return get_status_dict()

    if online and not frida:
        if start_frida_server():
            update_status("READY", True, True, True, None)
            return get_status_dict()
        update_status("ERROR", True, True, False, "Frida server failed to start")
        return get_status_dict()

    # Self-healing: if emulator is offline, reset bootstrap state to allow launching it
    if not online:
        _bootstrap_started = False

    if force_bootstrap and not _bootstrap_started:
        start_bootstrap_async()
    return get_status_dict()


def bootstrap_worker():
    global _bootstrap_started
    logger.info("[sandbox] starting background sandbox bootstrap sequence...")
    update_status("BOOTING", False, False, False, None)

    try:
        if not os.path.exists(ADB_PATH):
            logger.error(f"[sandbox] adb binary not found at path: {ADB_PATH}")
            update_status("UNAVAILABLE", False, False, False, "ADB binary missing")
            return

        logger.info("[sandbox] checking adb devices...")
        emu_already_running = is_emulator_running_adb()
        if emu_already_running:
            boot_res = _adb_run(["shell", "getprop", "sys.boot_completed"], timeout=5)
            is_booted = "1" in boot_res.stdout
            if is_booted:
                pm_ready = False
                for _ in range(8):
                    if is_package_manager_responsive():
                        pm_ready = True
                        break
                    time.sleep(2)
                if not pm_ready:
                    logger.warning("[sandbox] Stuck emulator detected in bootstrap (package manager unresponsive after 15s). Restarting...")
                    kill_stale_emulator()
                    emu_already_running = False

        if not emu_already_running:
            if not EMULATOR_PATH or not os.path.exists(EMULATOR_PATH):
                logger.error("[sandbox] emulator binary not found")
                update_status("UNAVAILABLE", False, False, False, "Emulator binary missing")
                return

            # Auto-detect or default to optimized 'swiftshader' software renderer.
            # This avoids host Mesa CPU synchronization overheads on Intel TigerLake systems, while allowing full overrides.
            gpu_mode = os.environ.get("SANDBOX_GPU_MODE", "swiftshader")
            logger.info(f"[sandbox] launching AVD {SANDBOX_AVD} with gpu_mode='{gpu_mode}'...")
            subprocess.Popen(
                [
                    EMULATOR_PATH,
                    "-avd",
                    SANDBOX_AVD,
                    "-no-window",
                    "-no-audio",
                    "-no-boot-anim",
                    "-gpu",
                    gpu_mode,
                    "-memory",
                    "3072",
                    "-partition-size",
                    "4096",
                    "-no-snapshot-save",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        boot_timeout = int(os.environ.get("SANDBOX_BOOT_TIMEOUT_SECS", "120"))
        booted = False
        start_time = time.time()
        logger.info(f"[sandbox] waiting for boot completion ({boot_timeout}s timeout)...")
        while time.time() - start_time < boot_timeout:
            if is_emulator_online_adb():
                try:
                    _adb_run(["shell", "wm", "dismiss-keyguard"], timeout=10)
                except Exception:
                    pass
                res = _adb_run(["shell", "getprop", "sys.boot_completed"])
                if "1" in res.stdout or is_package_manager_responsive():
                    booted = True
                    break
            time.sleep(3)

        if not booted:
            logger.error("[sandbox] emulator boot timed out.")
            update_status("ERROR", emu_already_running, is_emulator_online_adb(), False, "Emulator boot timed out")
            return

        logger.info("[sandbox] emulator booted successfully.")
        _adb_run(["root"], timeout=10)
        _adb_run(["shell", "setenforce", "0"], timeout=10)

        # Loop and verify package manager is fully responsive before launching Frida or reporting READY
        pm_ready = False
        logger.info("[sandbox] verifying package manager service is responsive...")
        for _ in range(15):
            if is_package_manager_responsive():
                pm_ready = True
                break
            time.sleep(2)
        if not pm_ready:
            logger.error("[sandbox] Package manager service did not become responsive after boot.")
            update_status("ERROR", True, True, False, "Package manager unresponsive")
            return

        frida_running = check_frida_server_running() or start_frida_server()

        if frida_running:
            # Kill high-CPU bloatware GMS services so the guest has headroom for
            # APK install and Frida injection. These restart automatically later.
            _kill_bloatware_services()
            logger.info("[sandbox] dynamic sandbox READY.")
            update_status("READY", True, True, True, None)
        else:
            logger.error("[sandbox] frida-server failed to start.")
            update_status("ERROR", True, True, False, "Frida server failed to start")

    except Exception as exc:
        logger.error(f"[sandbox] Bootstrap crashed: {exc}")
        update_status("ERROR", False, False, False, str(exc))


# Packages that hammer the CPU on fresh boots — permanently disable them in the sandbox.
_BLOATWARE_PKGS = [
    "com.google.android.googlequicksearchbox",  # Google Search Box
    "com.google.android.apps.messaging",        # Google Messages
    "com.google.android.as",                    # Android System Intelligence
    "com.google.android.apps.wellbeing",        # Digital Wellbeing
    "com.google.android.apps.photos",           # Google Photos
    "com.google.android.apps.youtube.music",    # YT Music
    "com.google.android.youtube",               # YouTube
    "com.google.android.gm",                    # Gmail
    "com.google.android.apps.maps",             # Google Maps
    "com.google.android.apps.docs",             # Google Docs
    "com.google.android.projection.gearhead",   # Android Auto
    "com.google.android.apps.wallpaper",        # Wallpapers
    "com.google.android.feedback",              # Feedback
    "com.google.android.music",                 # Play Music
    "com.google.android.videos",                # Play Movies
    "com.google.android.settings.intelligence", # Settings Search Indexer
]

def _kill_bloatware_services():
    """Disable known CPU-hungry and memory-heavy bloatware packages permanently inside the sandbox."""
    for pkg in _BLOATWARE_PKGS:
        try:
            # pm disable-user completely stops it from running or being triggered by background events
            _adb_run(["shell", "pm", "disable-user", "--user", "0", pkg], timeout=10)
            logger.info(f"[sandbox] permanently disabled bloatware: {pkg}")
        except Exception as e:
            logger.debug(f"[sandbox] could not disable {pkg}: {e}")


def start_bootstrap_async():
    global _bootstrap_started
    with status_lock:
        if _bootstrap_started:
            return
        _bootstrap_started = True
    threading.Thread(target=bootstrap_worker, daemon=True).start()
