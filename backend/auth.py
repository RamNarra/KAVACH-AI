"""
Session-scoped request ownership and asymmetric JWT authentication.

Supports JWT verification via RS256 with a transient fallback RSA keypair
for local demonstration, alongside traditional high-entropy session headers.
"""

from __future__ import annotations

import os
import re
from typing import Optional

from fastapi import HTTPException, Request
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


SESSION_HEADER = "X-Kavach-Session"
ADMIN_TOKEN_ENV = "KAVACH_ADMIN_TOKEN"
LEGACY_UID_ENV = "KAVACH_ALLOW_LEGACY_UID"
_SESSION_RE = re.compile(r"^[A-Za-z0-9_\-]{24,128}$")

# Dynamic generation of transient RSA keypair for local fallback verification:
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()

_PUBLIC_PEM = _PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')


def get_session_header_name() -> str:
    return SESSION_HEADER


def is_admin_request(request: Request) -> bool:
    admin_token = os.getenv(ADMIN_TOKEN_ENV, "").strip()
    if not admin_token:
        return False

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token == admin_token:
            return True
        try:
            pub_key = os.getenv("KAVACH_JWT_PUBLIC_KEY", _PUBLIC_PEM)
            decoded = jwt.decode(token, pub_key, algorithms=["RS256"])
            if decoded.get("role") == "admin":
                return True
        except Exception:
            pass

    return request.headers.get("X-Kavach-Admin", "").strip() == admin_token


def verify_request_uid(request: Request, claimed_uid: Optional[str]) -> str:
    """
    Return the validated session owner id (UID) for this request.

    Supports JWT validation via Authorization bearer tokens, falling back
    to X-Kavach-Session headers and legacy query params.
    """
    # 1. Check dynamic JWT Bearer token in Authorization header
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        try:
            pub_key = os.getenv("KAVACH_JWT_PUBLIC_KEY", _PUBLIC_PEM)
            decoded = jwt.decode(token, pub_key, algorithms=["RS256"])
            uid = decoded.get("sub") or decoded.get("uid")
            if uid:
                return str(uid)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="JWT signature has expired.")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"Invalid JWT: {e}")

    # 2. Fallback to existing Session-based logic
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
        detail=f"Missing required {SESSION_HEADER} or JWT Authorization header.",
    )

