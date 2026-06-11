"""
Session-scoped request ownership and asymmetric JWT authentication.

Supports JWT verification via Firebase Admin SDK when initialized, falling
back to RS256 with a transient RSA keypair for local demonstration, alongside
traditional high-entropy session headers.
"""

from __future__ import annotations

import os
import re
import logging
from typing import Optional

from fastapi import HTTPException, Request
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("kavach-api")

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

    Supports JWT validation via Firebase Admin SDK, Supabase JWT, or local Authorization bearer tokens,
    falling back to X-Kavach-Session headers and legacy query params.
    """
    # 1. Check dynamic JWT Bearer token in Authorization header
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        
        # A. Try Supabase JWT verification first if SUPABASE_JWT_SECRET is set
        supabase_jwt_secret = os.getenv("SUPABASE_JWT_SECRET", "").strip()
        if supabase_jwt_secret:
            try:
                decoded = jwt.decode(
                    token, 
                    supabase_jwt_secret, 
                    algorithms=["HS256", "RS256"], 
                    options={"verify_aud": False}
                )
                uid = decoded.get("sub") or decoded.get("uid")
                if uid:
                    return str(uid)
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Supabase JWT signature has expired.")
            except jwt.InvalidTokenError as e:
                logger.debug(f"Supabase JWT decode failed: {e}. Trying other decoders.")
        
        # B. Try Firebase Admin SDK verification if Firebase is initialized
        try:
            import firebase_admin
            from firebase_admin import auth as firebase_auth
            if firebase_admin._apps:
                decoded = firebase_auth.verify_id_token(token)
                uid = decoded.get("uid") or decoded.get("sub")
                if uid:
                    return str(uid)
        except Exception as fb_err:
            logger.debug(f"Firebase token verification bypassed/failed: {fb_err}. Trying local JWT fallback.")

        # C. Fallback to local JWT verification
        try:
            try:
                header = jwt.get_unverified_header(token)
                alg = header.get("alg", "RS256")
            except Exception:
                alg = "RS256"

            if alg == "HS256":
                secret = os.getenv("SUPABASE_JWT_SECRET")
                if not secret:
                    raise HTTPException(status_code=500, detail="Backend configuration error: SUPABASE_JWT_SECRET is missing on the host.")
                decoded = jwt.decode(token, secret.strip(), algorithms=["HS256"])
            else:
                pub_key = os.getenv("KAVACH_JWT_PUBLIC_KEY", _PUBLIC_PEM)
                decoded = jwt.decode(token, pub_key, algorithms=["RS256"])
            uid = decoded.get("sub") or decoded.get("uid")
            if uid:
                return str(uid)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="JWT signature has expired.")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"Invalid JWT: {e}")

    # 2. Check if admin or legacy override is active
    if is_admin_request(request):
        return "admin"

    if os.getenv(LEGACY_UID_ENV, "0") in ("1", "true", "True"):
        # Allow fallback to Session-based logic only if legacy mode is explicitly turned on
        session_id = (request.headers.get(SESSION_HEADER) or "").strip()
        if session_id:
            if not _SESSION_RE.fullmatch(session_id):
                raise HTTPException(status_code=400, detail="Invalid session header format.")
            return session_id

        legacy_uid = (claimed_uid or "").strip()
        if legacy_uid:
            if not re.match(r"^[A-Za-z0-9_\-]{3,128}$", legacy_uid):
                raise HTTPException(status_code=400, detail="Invalid legacy uid format.")
            return legacy_uid

    raise HTTPException(
        status_code=401,
        detail="Missing or invalid JWT Authorization header.",
    )
