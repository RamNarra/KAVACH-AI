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
FRIDA_REMOTE_PATH = os.environ.get("FRIDA_SERVER_PATH", "/data/local/tmp/frida-server")

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
        return any(("emulator-" in line or "127.0.0.1:" in line or "localhost:" in line) for line in res.stdout.splitlines())
    except Exception:
        return False


def is_emulator_online_adb() -> bool:
    try:
        res = _adb_run(["devices"])
        return any((("emulator-" in line or "127.0.0.1:" in line or "localhost:" in line) and "device" in line) for line in res.stdout.splitlines())
    except Exception:
        return False


def is_package_manager_responsive() -> bool:
    try:
        res = _adb_run(["shell", "pm", "path", "android"], timeout=5)
        return "package:" in res.stdout
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
        # Check if binary exists on device, and push it if missing (e.g. after fresh AVD recreation)
        exists_check = _adb_run(["shell", "ls", binary])
        if "No such file" in exists_check.stdout or "No such file" in exists_check.stderr or not exists_check.stdout.strip():
            logger.info("[sandbox] frida-server binary missing on device, pushing from host...")
            local_frida = os.getenv("KAVACH_LOCAL_FRIDA_PATH")
            if not local_frida:
                home = os.path.expanduser("~")
                local_frida = os.path.join(home, "Android/Sdk/frida-server-17.15.3-android-x86_64")
            if os.path.exists(local_frida):
                push_res = _adb_run(["push", local_frida, binary], timeout=30)
                _adb_run(["shell", "chmod", "755", binary], timeout=10)
                logger.info(f"[sandbox] frida-server pushed to device: {push_res.stdout.strip()}")
            else:
                logger.error(f"[sandbox] Local frida-server binary not found at {local_frida}. Cannot push!")
                return False

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
    """Quick, non-blocking state check to return sandbox status. Defer boots to background thread."""
    global _bootstrap_started
    online = is_emulator_online_adb()
    
    if not online:
        # If the emulator is offline, reset bootstrap state and trigger boot asynchronously if requested
        with status_lock:
            global sandbox_status
            if sandbox_status == "READY":
                sandbox_status = "UNAVAILABLE"
        _bootstrap_started = False
        if force_bootstrap:
            start_bootstrap_async()
        return get_status_dict()

    # If the emulator is online, verify if zygote and package manager are responsive yet
    pm_responsive = is_package_manager_responsive()
    if not pm_responsive:
        # Still booting. Let the background thread handle the cold boot wait.
        # Do NOT block the request handler or run any force-kill loops here!
        return get_status_dict()
            
    # If package manager is responsive, check if Frida is running
    frida = check_frida_server_running()

    if frida:
        update_status("READY", True, True, True, None)
        return get_status_dict()

    # Try to start Frida server (returns True if it was successfully started/verified)
    if start_frida_server():
        # Clean up known heavy background services to optimize memory and CPU
        _kill_bloatware_services()
        update_status("READY", True, True, True, None)
    else:
        update_status("ERROR", True, True, False, "Frida server failed to start")

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

        boot_timeout = int(os.environ.get("SANDBOX_BOOT_TIMEOUT_SECS", "300"))
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
_BLOATWARE_PKGS = []

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
