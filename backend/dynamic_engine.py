import os
import time
import datetime
import subprocess
import logging
import zipfile
import frida
from typing import Dict, List, Any, Optional

from frida_hooks import build_frida_script, select_packs_from_signals
from redaction import deduplicate_events, redact_events

# Configure logger
logger = logging.getLogger("kavach-dynamic")
logger.setLevel(logging.INFO)

from toolchain import configure_android_env, resolve_adb

configure_android_env()
ADB_PATH = resolve_adb()

# (Frida hook scripts are now assembled dynamically via frida_hooks.py)

# ABI folder names that appear inside APK lib/ directory
_ALL_KNOWN_ABIS = {"arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64", "mips", "mips64"}

def get_apk_native_abis(apk_path: str) -> Optional[set]:
    """
    Inspect the APK zip file to determine which native ABI folders exist under lib/.
    Returns a set of ABI strings (e.g. {'arm64-v8a', 'x86'}) or None if the APK
    has no native libraries at all.
    """
    try:
        found = set()
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    if len(parts) >= 3:
                        abi = parts[1]  # lib/<abi>/libfoo.so
                        if abi in _ALL_KNOWN_ABIS:
                            found.add(abi)
        return found if found else None
    except Exception as e:
        logger.warning(f"[ABI check] Could not inspect APK for native libs: {e}")
        return None


def get_emulator_supported_abis() -> set:
    """
    Ask the running emulator which ABIs it can execute.
    Uses ro.product.cpu.abilist (comma-separated, preferred list).
    Falls back to ro.product.cpu.abi for older images.
    """
    try:
        result = subprocess.run(
            [ADB_PATH, "shell", "getprop", "ro.product.cpu.abilist"],
            capture_output=True, text=True, timeout=20
        )
        abilist = result.stdout.strip()
        if abilist:
            return {a.strip() for a in abilist.split(",") if a.strip()}
        # Older images only have ro.product.cpu.abi
        result2 = subprocess.run(
            [ADB_PATH, "shell", "getprop", "ro.product.cpu.abi"],
            capture_output=True, text=True, timeout=20
        )
        abi = result2.stdout.strip()
        return {abi} if abi else set()
    except Exception as e:
        logger.warning(f"[ABI check] Could not query emulator ABI list: {e}")
        return set()


def check_abi_compatibility(apk_path: str) -> Optional[Dict[str, Any]]:
    """
    Returns None if the APK is compatible (or has no native libs).
    Returns a structured UNSUPPORTED_ABI result dict if incompatible.
    """
    apk_abis = get_apk_native_abis(apk_path)
    if not apk_abis:
        # Pure Java/Kotlin APK — no native libs, always compatible
        return None

    emulator_abis = get_emulator_supported_abis()
    if not emulator_abis:
        # Could not determine emulator ABI — let install proceed and surface real error
        return None

    # If there is at least one ABI intersection, Android can satisfy the install
    compatible_abis = apk_abis & emulator_abis
    if compatible_abis:
        return None

    # Full mismatch — return early with a clear message
    apk_list = ", ".join(sorted(apk_abis))
    emu_list = ", ".join(sorted(emulator_abis))
    msg = (
        f"APK requires native ABI(s) [{apk_list}] but the sandbox emulator only "
        f"supports [{emu_list}]. Dynamic execution skipped — static analysis results remain fully valid."
    )
    logger.warning(f"[ABI check] {msg}")
    return {
        "status": "UNSUPPORTED_ABI",
        "events": [],
        "event_count": 0,
        "duration_seconds": 0,
        "error_message": msg,
        "apk_abis": sorted(apk_abis),
        "emulator_abis": sorted(emulator_abis)
    }


def ensure_frida_server_running() -> bool:
    try:
        import sandbox_bootstrap
        if sandbox_bootstrap.check_frida_server_running():
            return True
        subprocess.run([ADB_PATH, "wait-for-device"], capture_output=True, timeout=30)
        return sandbox_bootstrap.start_frida_server()
    except Exception as exc:
        logger.error(f"Error ensuring Frida server is running: {exc}")
        return False


def _wait_for_pm_ready(timeout_secs: int = 90, log_fn=None) -> bool:
    """
    Poll the guest package manager until it is responsive.
    Returns True when ready, False on timeout.
    This is the fix for the 'Can't find service: package' error that
    occurs when the guest system_server is still starting up.
    """
    deadline = time.time() + timeout_secs
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            res = subprocess.run(
                [ADB_PATH, "shell", "pm", "path", "android"],
                capture_output=True, text=True, timeout=8
            )
            if "package:" in res.stdout or res.returncode == 0:
                if log_fn:
                    log_fn(f"Package manager ready (attempt {attempt}).")
                return True
            # system_server still booting
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        if log_fn and attempt % 5 == 0:
            elapsed = int(time.time() - (deadline - timeout_secs))
            log_fn(f"Waiting for guest package manager… ({elapsed}s elapsed)")
        time.sleep(3)
    return False

def run_behavioral_trace(
    apk_path: str,
    package_name: str,
    duration: int = 20,
    launcher_activity: str = "",
    active_packs: Optional[List[str]] = None,
    static_signals: Optional[Dict[str, Any]] = None,
    log_callback=None,
) -> Dict[str, Any]:
    """
    Run the full behavioral trace pipeline:
      1. ABI pre-flight
      2. Install APK
      3. Spawn + Frida attach with selected hook packs
      4. Run trigger playbook in parallel
      5. Collect raw events
      6. Normalize, redact, deduplicate events
      7. Return structured result with normalized_events + trigger_transcript
    """
    signals = static_signals or {}
    if active_packs is None:
        active_packs = select_packs_from_signals(signals)
    def log_event(msg: str, is_error: bool = False, is_warn: bool = False):
        if is_error:
            logger.error(msg)
        elif is_warn:
            logger.warning(msg)
        else:
            logger.info(msg)
        if log_callback:
            try:
                log_callback(msg)
            except Exception as le:
                logger.error(f"Error invoking log callback: {le}")

    try:
        import sandbox_bootstrap
        sandbox_info = sandbox_bootstrap.ensure_sandbox_ready()
        bootstrap_status = sandbox_info["sandbox_status"]
        if bootstrap_status != "READY":
            log_event(
                f"Sandbox not READY ({bootstrap_status}) — attempting dynamic trace anyway if ADB is up.",
                is_warn=True,
            )
    except Exception as exc:
        log_event(f"Error reading sandbox status: {exc}", is_warn=True)

    raw_events: List[Dict[str, Any]] = []
    normalized_events: List[Dict[str, Any]] = []
    trigger_transcript: List[Dict[str, Any]] = []
    coverage_map: Dict[str, Any] = {}
    status = "UNAVAILABLE"
    error_msg = None
    _raw_dedup: Dict[str, int] = {}   # per-run dedup tracker (category::evidence[:80] → count)

    # Track resources for cleanup
    session = None
    script = None
    pid = None
    device = None

    try:
        # ADB accessibility check
        adb_check = subprocess.run([ADB_PATH, "get-state"], capture_output=True, text=True, timeout=20)
        if adb_check.returncode != 0 or "device" not in adb_check.stdout:
            log_event("Android emulator is offline or unreachable via ADB.", is_warn=True)
            return {
                "status": "UNAVAILABLE",
                "events": [],
                "normalized_events": [],
                "trigger_transcript": [],
                "event_count": 0,
                "duration_seconds": duration,
                "error_message": "Android emulator is offline or unreachable."
            }

        # Ensure Frida server is running
        log_event("Ensuring Frida server is running in sandbox...")
        if not ensure_frida_server_running():
            log_event("Frida server check failed.", is_error=True)
            return {
                "status": "UNAVAILABLE",
                "events": [],
                "normalized_events": [],
                "trigger_transcript": [],
                "event_count": 0,
                "duration_seconds": duration,
                "error_message": "Frida server could not be started on emulator."
            }

        # ABI pre-flight check
        log_event("Checking native ABI compatibility with sandbox emulator...")
        abi_result = check_abi_compatibility(apk_path)
        if abi_result is not None:
            log_event(abi_result["error_message"], is_warn=True)
            abi_result["normalized_events"] = []
            abi_result["trigger_transcript"] = []
            return abi_result

        # Clear previous installation
        log_event(f"Removing package {package_name} from sandbox if exists...")
        try:
            subprocess.run([ADB_PATH, "uninstall", package_name], capture_output=True, timeout=45)
        except subprocess.TimeoutExpired:
            log_event("adb uninstall timed out (package may not be present), continuing...", is_warn=True)
        except Exception as ue:
            log_event(f"adb uninstall error (non-fatal): {ue}", is_warn=True)

        # Wait for the guest package manager to be fully responsive before installing.
        # This is the key fix for 'Can't find service: package' — the system_server
        # can restart after first boot and take up to 60-90s to re-expose PM.
        log_event("Waiting for guest package manager to be ready...")
        pm_ready = _wait_for_pm_ready(timeout_secs=90, log_fn=log_event)
        if not pm_ready:
            log_event("Package manager did not become ready in time. Aborting install.", is_error=True)
            return {
                "status": "FAILED",
                "events": [],
                "normalized_events": [],
                "trigger_transcript": [],
                "event_count": 0,
                "duration_seconds": duration,
                "error_message": "Guest package manager (system_server) did not become ready in 90s."
            }

        # Deploy APK — 3 retries with PM re-check between attempts
        install_timeout = int(os.environ.get("ADB_INSTALL_TIMEOUT_SECS", "300"))
        log_event(f"Deploying target {package_name} to emulator (timeout {install_timeout}s per attempt)…")
        install_res = None
        last_err = ""
        for attempt in range(1, 4):  # 3 attempts
            try:
                install_res = subprocess.run(
                    [ADB_PATH, "install", "-r", "-t", apk_path],
                    capture_output=True, text=True, timeout=install_timeout,
                )
                if install_res.returncode == 0:
                    break
                last_err = install_res.stderr.strip() or install_res.stdout.strip()
                log_event(f"ADB install attempt {attempt} failed: {last_err[:200]}", is_warn=True)
                if "Can't find service: package" in last_err:
                    # PM dropped — wait for it to come back before next attempt
                    log_event("Package manager dropped, waiting for recovery...", is_warn=True)
                    _wait_for_pm_ready(timeout_secs=60, log_fn=log_event)
            except subprocess.TimeoutExpired:
                last_err = f"timed out after {install_timeout}s"
                log_event(f"ADB install attempt {attempt} timed out", is_warn=True)
                subprocess.run([ADB_PATH, "wait-for-device"], capture_output=True, timeout=30)
            if attempt < 3:
                time.sleep(5)

        if not install_res or install_res.returncode != 0:
            err_text = last_err or "unknown install error"
            log_event(f"ADB installation failed: {err_text}", is_error=True)
            return {
                "status": "FAILED",
                "events": [],
                "normalized_events": [],
                "trigger_transcript": [],
                "event_count": 0,
                "duration_seconds": duration,
                "error_message": f"ADB install failed: {err_text}"
            }
        log_event("Installation successful.")

        # Frida attach
        log_event("Initializing Frida USB binding...")
        device = frida.get_usb_device(timeout=20)
        log_event(f"Spawning sandbox package: {package_name}...")
        
        session = None
        pid = None
        try:
            pid = device.spawn([package_name])
            log_event(f"Spawned package successfully. PID: {pid}")
            session = device.attach(pid)
        except Exception as spawn_err:
            log_event(f"Frida spawn failed: {spawn_err}. Engaging manual launch and direct PID attach fallback...", is_warn=True)
            
            # Start process using ADB monkey or am start
            if launcher_activity:
                full_act = launcher_activity
                if launcher_activity.startswith("."):
                    full_act = package_name + launcher_activity
                elif "." not in launcher_activity:
                    full_act = package_name + "." + launcher_activity
                log_event(f"Launching explicit activity via ADB: {full_act}")
                subprocess.run([ADB_PATH, "shell", "am", "start", "-n", f"{package_name}/{full_act}"], capture_output=True, timeout=20)
            else:
                log_event("Launching default launcher activity via monkey...")
                subprocess.run(
                    [ADB_PATH, "shell", f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
                )
            time.sleep(2.5)
            
            # Query running process PID
            try:
                pid_res = subprocess.run([ADB_PATH, "shell", "pidof", package_name], capture_output=True, text=True, timeout=10)
                pid_str = pid_res.stdout.strip()
                if pid_str:
                    pid = int(pid_str.split()[0])
            except Exception as pe:
                log_event(f"Could not query PID via ADB: {pe}", is_warn=True)
                
            if not pid:
                try:
                    for p in device.enumerate_processes():
                        if p.name == package_name:
                            pid = p.pid
                            break
                except Exception as fe:
                    log_event(f"Could not enumerate processes via Frida: {fe}", is_warn=True)
                    
            if not pid:
                raise Exception(f"Failed to locate running process PID for package {package_name}")
                
            log_event(f"Successfully located running process. Attaching to PID: {pid}")
            session = device.attach(pid)

        # Assemble hook script from selected packs
        hook_script_js = build_frida_script(active_packs)
        log_event(f"Loading Frida hook packs: {', '.join(active_packs)}")
        script = session.create_script(hook_script_js)

        def on_message(message, data):
            if message["type"] == "send":
                payload = message["payload"]
                if not isinstance(payload, dict):
                    return

                # Normalize to typed event schema
                ts_now = datetime.datetime.utcnow().isoformat() + "Z"
                norm = {
                    "ts":           ts_now,
                    "category":     payload.get("category", "unknown"),
                    "action":       payload.get("action", ""),
                    "severity_hint":payload.get("severity_hint", "low"),
                    "class_name":   payload.get("class_name", ""),
                    "method":       payload.get("method", ""),
                    "args":         payload.get("args", {}),
                    "evidence":     payload.get("evidence", ""),
                    "source":       "frida",
                    "package":      package_name,
                }

                # Raw dedup by category+evidence (cap per signature)
                sig = f"{norm['category']}::{norm['evidence'][:80]}"
                cnt = _raw_dedup.get(sig, 0)
                if cnt >= 3:
                    _raw_dedup[sig] = cnt + 1
                    return
                _raw_dedup[sig] = cnt + 1

                if len(raw_events) < 200:
                    raw_events.append(norm)
                    log_event(f"[FRIDA] [{norm['severity_hint'].upper()}] [{norm['category']}] {norm['evidence'][:100]}")

            elif message["type"] == "error":
                log_event(f"[Frida script error] {message.get('description','')}", is_error=True)

        script.on("message", on_message)
        script.load()
        device.resume(pid)
        log_event(f"Process {pid} resumed. Instrumentation active.")

        # Explicit launcher launch
        if launcher_activity:
            full_act = launcher_activity
            if launcher_activity.startswith("."):
                full_act = package_name + launcher_activity
            elif "." not in launcher_activity:
                full_act = package_name + "." + launcher_activity
            log_event(f"Launching explicit activity: {full_act}")
            subprocess.run([ADB_PATH, "shell", "am", "start", "-n",
                            f"{package_name}/{full_act}"],
                           capture_output=True, timeout=20)
        else:
            subprocess.run(
                [ADB_PATH, "shell",
                 f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
            )
        time.sleep(1.5)

        # Run trigger playbook (exercising exported components, UI interaction, etc.)
        log_event("Starting trigger playbook...")
        try:
            from playbook_engine import run_playbook
            play_result = run_playbook(
                adb=ADB_PATH,
                package_name=package_name,
                launcher_activity=launcher_activity or None,
                static_signals=signals,
                log_callback=log_callback,
            )
            trigger_transcript = play_result["transcript"]
            coverage_map = play_result["coverage_map"]
            log_event(f"Playbook: {play_result['steps_succeeded']}/{play_result['steps_attempted']} steps succeeded")
        except Exception as pe:
            log_event(f"Playbook error (non-fatal): {pe}", is_warn=True)
            trigger_transcript = []
            coverage_map = {}

        # Record telemetry for remaining duration
        time.sleep(max(duration - 25, 5))   # playbook already consumed ~20s
        status = "COMPLETED"
        log_event(f"Trace complete. Raw events: {len(raw_events)}")

    except Exception as e:
        log_event(f"Dynamic analysis engine execution failed: {e}", is_error=True)
        status = "FAILED"
        error_msg = str(e)

    finally:
        log_event("Entering sandbox cleanup sequence...")
        if script:
            try:
                script.unload()
            except Exception:
                pass
        if session:
            try:
                session.detach()
            except Exception:
                pass
        if device and pid:
            try:
                device.kill(pid)
            except Exception:
                pass
        log_event(f"Uninstalling package {package_name} from sandbox...")
        try:
            subprocess.run([ADB_PATH, "uninstall", package_name], capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            log_event("adb uninstall timed out during cleanup, continuing...", is_warn=True)
        except Exception as ue:
            log_event(f"adb uninstall cleanup error (non-fatal): {ue}", is_warn=True)
        log_event("Cleanup complete.")

    # Post-collection: redact + deduplicate normalized events
    normalized_events = redact_events(deduplicate_events(raw_events))

    # Replace None/null values with empty structures to ensure schema validation
    # Determine runtime_confidence
    n_events = len(normalized_events)
    play_steps_ok = sum(1 for s in trigger_transcript if s.get("result") == "succeeded")
    
    if status == "FAILED" and n_events > 0:
        # If hooks attached and some telemetry exists but playbook failed, set partial
        status = "PARTIAL"
        
    if status not in ("COMPLETED", "PARTIAL"):
        runtime_confidence = "none"
    elif n_events >= 10 and play_steps_ok >= 6:
        runtime_confidence = "full"
    elif n_events >= 3 or play_steps_ok >= 3:
        runtime_confidence = "partial"
    else:
        runtime_confidence = "minimal"

    return {
        "status":            status,
        "events":            raw_events if raw_events is not None else [],           # raw (for auditability)
        "normalized_events": normalized_events if normalized_events is not None else [],    # redacted + deduped
        "trigger_transcript": trigger_transcript if trigger_transcript is not None else [],
        "coverage_map":      coverage_map if coverage_map is not None else {},
        "event_count":       len(normalized_events),
        "duration_seconds":  duration,
        "error_message":     error_msg,
        "active_packs":      active_packs if active_packs is not None else [],
        "runtime_confidence": runtime_confidence,
    }
