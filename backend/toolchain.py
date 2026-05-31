"""Resolve analysis toolchain binaries for local dev and Docker."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = os.path.join(_BACKEND_DIR, "tools")


def _first_existing(*paths: str) -> Optional[str]:
    for path in paths:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def resolve_jadx() -> str:
    override = os.environ.get("JADX_BIN")
    if override and os.path.isfile(override):
        return override
    local = _first_existing(
        os.path.join(_TOOLS_DIR, "jadx", "bin", "jadx"),
        "/opt/jadx/bin/jadx",
    )
    if local:
        return local
    found = shutil.which("jadx")
    if found:
        return found
    raise FileNotFoundError(
        "jadx not found. Run backend/scripts/install_local_tools.sh or set JADX_BIN."
    )


def resolve_apktool() -> List[str]:
    override = os.environ.get("APKTOOL_BIN")
    if override:
        return [override]
    local = _first_existing(
        os.path.join(_TOOLS_DIR, "apktool"),
        "/usr/local/bin/apktool",
    )
    if local:
        return [local]
    found = shutil.which("apktool")
    if found:
        return [found]
    jar = os.path.join(_TOOLS_DIR, "apktool.jar")
    if os.path.isfile(jar):
        return ["java", "-jar", jar]
    docker_jar = "/opt/apktool/apktool.jar"
    if os.path.isfile(docker_jar):
        return ["java", "-jar", docker_jar]
    raise FileNotFoundError(
        "apktool not found. Run backend/scripts/install_local_tools.sh or set APKTOOL_BIN."
    )


def resolve_apkid() -> List[str]:
    override = os.environ.get("APKID_BIN")
    if override:
        return [override]
    found = shutil.which("apkid")
    if found:
        return [found]
    venv_bin = os.path.join(_BACKEND_DIR, "venv", "bin", "apkid")
    if os.path.isfile(venv_bin):
        return [venv_bin]
    return ["apkid"]


def resolve_android_home() -> Optional[str]:
    for candidate in (
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.expanduser("~/Android/Sdk"),
        "/opt/android-sdk",
    ):
        if candidate and os.path.isdir(candidate):
            return candidate
    return None


def resolve_adb() -> str:
    override = os.environ.get("ADB_BIN")
    if override and os.path.isfile(override):
        return override
    sdk = resolve_android_home()
    if sdk:
        sdk_adb = os.path.join(sdk, "platform-tools", "adb")
        if os.path.isfile(sdk_adb):
            return sdk_adb
    found = shutil.which("adb")
    return found or "adb"


def resolve_emulator() -> Optional[str]:
    override = os.environ.get("EMULATOR_BIN")
    if override and os.path.isfile(override):
        return override
    sdk = resolve_android_home()
    if sdk:
        emu = os.path.join(sdk, "emulator", "emulator")
        if os.path.isfile(emu):
            return emu
    return shutil.which("emulator")


def resolve_aapt() -> Optional[str]:
    override = os.environ.get("AAPT_BIN")
    if override and os.path.isfile(override):
        return override
    sdk = resolve_android_home()
    if not sdk:
        return None
    bt_dir = os.path.join(sdk, "build-tools")
    if not os.path.isdir(bt_dir):
        return None
    for ver in sorted(os.listdir(bt_dir), reverse=True):
        aapt = os.path.join(bt_dir, ver, "aapt")
        if os.path.isfile(aapt) and os.access(aapt, os.X_OK):
            return aapt
    return shutil.which("aapt")


def configure_android_env() -> None:
    sdk = resolve_android_home()
    if not sdk:
        return
    os.environ.setdefault("ANDROID_HOME", sdk)
    os.environ.setdefault("ANDROID_SDK_ROOT", sdk)
    extra = os.pathsep.join(
        [
            os.path.join(sdk, "cmdline-tools", "latest", "bin"),
            os.path.join(sdk, "platform-tools"),
            os.path.join(sdk, "emulator"),
        ]
    )
    os.environ["PATH"] = f"{extra}{os.pathsep}{os.environ.get('PATH', '')}"


def maybe_nice(cmd: List[str], low_priority: bool = True) -> List[str]:
    """Deprioritize background tools only — never use on JADX (kills throughput)."""
    if not low_priority or os.name != "posix":
        return cmd
    if shutil.which("nice"):
        return ["nice", "-n", "19", *cmd]
    return cmd


def run_cmd(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, **kwargs)
