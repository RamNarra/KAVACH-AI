"""
sandbox_runner.py — Secure subprocess execution with optional Docker isolation.

When KAVACH_DOCKER_SANDBOX=1 env var is set, wraps JADX and APKTool inside a
disposable Docker container so a malicious APK exploiting a JVM bug cannot
escape to the host.

Falls back to direct execution if Docker is unavailable (graceful degradation
for developer laptops without Docker).
"""

import os
import subprocess
import shutil
import logging
from typing import List, Optional

logger = logging.getLogger("kavach-api")

# Set KAVACH_DOCKER_SANDBOX=1 in production to enable container isolation
DOCKER_SANDBOX_ENABLED = os.getenv("KAVACH_DOCKER_SANDBOX", "0") in ("1", "true", "True")
SANDBOX_IMAGE = os.getenv("KAVACH_SANDBOX_IMAGE", "kavach-sandbox:latest")

_docker_available: Optional[bool] = None


def _check_docker() -> bool:
    """Check once whether Docker daemon is reachable."""
    global _docker_available
    if _docker_available is not None:
        return _docker_available
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=5
        )
        _docker_available = result.returncode == 0
    except Exception:
        _docker_available = False
    if _docker_available:
        logger.info("Docker daemon reachable — sandbox isolation ACTIVE")
    else:
        logger.warning(
            "Docker not available — falling back to host execution. "
            "Set KAVACH_DOCKER_SANDBOX=1 and ensure Docker is running for full isolation."
        )
    return _docker_available


def sandboxed_run(
    cmd: List[str],
    *,
    input_path: str,          # APK or directory to mount read-only inside container
    output_path: str,         # Output directory to mount read-write inside container
    timeout: Optional[int] = None,
    capture_output: bool = False,
    text: bool = True,
    **popen_kwargs,
) -> subprocess.CompletedProcess:
    """
    Run cmd either inside a Docker sandbox container or directly on the host.

    Docker mount layout:
      /sandbox/input   →  input_path  (read-only)
      /sandbox/output  →  output_path (read-write)

    The container is disposable (--rm), has no network access (--network none),
    has a memory cap (--memory 3g), and runs as a non-root user (--user nobody).
    """
    if DOCKER_SANDBOX_ENABLED and _check_docker():
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "none",                        # No outbound network
            "--memory", "3g",                           # OOM bomb cap
            "--memory-swap", "3g",                      # No swap escape
            "--cpus", "2",                              # CPU cap
            "--pids-limit", "100",                      # Fork-bomb protection
            "--user", "nobody",                         # Non-root
            "--read-only",                              # Immutable container FS
            "--tmpfs", "/tmp:size=512m",                # Writable /tmp in RAM only
            "-v", f"{os.path.abspath(input_path)}:/sandbox/input:ro",
            "-v", f"{os.path.abspath(output_path)}:/sandbox/output:rw",
            SANDBOX_IMAGE,
        ] + cmd
        logger.info(f"[SANDBOX] Running in container: {' '.join(cmd[:3])}...")
        return subprocess.run(
            docker_cmd,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            **popen_kwargs,
        )
    else:
        # Direct host execution (developer mode / Docker not available)
        return subprocess.run(
            cmd,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            **popen_kwargs,
        )


def sandboxed_popen(
    cmd: List[str],
    *,
    input_path: str,
    output_path: str,
    **popen_kwargs,
) -> subprocess.Popen:
    """
    Popen variant for streaming output (used by JADX which runs long).
    """
    if DOCKER_SANDBOX_ENABLED and _check_docker():
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--memory", "3g",
            "--memory-swap", "3g",
            "--cpus", "2",
            "--pids-limit", "100",                      # Fork-bomb protection
            "--user", "nobody",
            "--read-only",
            "--tmpfs", "/tmp:size=512m",
            "-v", f"{os.path.abspath(input_path)}:/sandbox/input:ro",
            "-v", f"{os.path.abspath(output_path)}:/sandbox/output:rw",
            SANDBOX_IMAGE,
        ] + cmd
        logger.info(f"[SANDBOX] Popen in container: {' '.join(cmd[:3])}...")
        return subprocess.Popen(docker_cmd, **popen_kwargs)
    else:
        return subprocess.Popen(cmd, **popen_kwargs)
