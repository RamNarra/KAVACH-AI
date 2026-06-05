"""
Session-scoped request ownership for local/demo mode.

Firebase auth is currently disabled, so the backend enforces ownership using a
high-entropy client session token sent in `X-Kavach-Session`.
"""

from __future__ import annotations

import os
import re
from typing import Optional

from fastapi import HTTPException, Request


SESSION_HEADER = "X-Kavach-Session"
ADMIN_TOKEN_ENV = "KAVACH_ADMIN_TOKEN"
LEGACY_UID_ENV = "KAVACH_ALLOW_LEGACY_UID"
_SESSION_RE = re.compile(r"^[A-Za-z0-9_\-]{24,128}$")


def get_session_header_name() -> str:
    return SESSION_HEADER


def is_admin_request(request: Request) -> bool:
    admin_token = os.getenv(ADMIN_TOKEN_ENV, "").strip()
    if not admin_token:
        return False

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip() == admin_token

    return request.headers.get("X-Kavach-Admin", "").strip() == admin_token


def verify_request_uid(request: Request, claimed_uid: Optional[str]) -> str:
    """
    Return the validated session owner id for this request.

    In local/demo mode, ownership is enforced by the `X-Kavach-Session` header.
    A legacy uid fallback can be re-enabled explicitly for one-off compatibility.
    """
    session_id = (request.headers.get(SESSION_HEADER) or "").strip()
    if session_id:
        if not _SESSION_RE.fullmatch(session_id):
            raise HTTPException(status_code=400, detail="Invalid session header format.")
        return session_id

    if is_admin_request(request):
        return "admin"

    if os.getenv(LEGACY_UID_ENV, "0") in ("1", "true", "True"):
        legacy_uid = (claimed_uid or "").strip()
        if legacy_uid:
            if not _SESSION_RE.fullmatch(legacy_uid):
                raise HTTPException(status_code=400, detail="Invalid legacy uid format.")
            return legacy_uid

    raise HTTPException(
        status_code=401,
        detail=f"Missing required {SESSION_HEADER} header.",
    )
