"""
Firebase ID token verification for Kavach API endpoints.
Set DISABLE_AUTH=1 for local development without tokens.
"""

import os
from typing import Optional

from fastapi import HTTPException, Request
from firebase_admin import auth as firebase_auth

DISABLE_AUTH = os.environ.get("DISABLE_AUTH", "0") in ("1", "true", "True")


def verify_request_uid(request: Request, claimed_uid: Optional[str]) -> str:
    """
    Verify Authorization: Bearer <firebase_id_token> and return uid.
    Falls back to claimed_uid only when DISABLE_AUTH is set.
    """
    if DISABLE_AUTH:
        if not claimed_uid:
            raise HTTPException(status_code=400, detail="uid required when auth disabled")
        return claimed_uid

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header[7:].strip()
    try:
        decoded = firebase_auth.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        if claimed_uid and claimed_uid != uid:
            raise HTTPException(status_code=403, detail="uid does not match authenticated user")
        return uid
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {e}") from e
