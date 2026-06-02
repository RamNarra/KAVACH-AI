"""
Auth: Firebase suspended — replaced with open passthrough for hackathon demo.
No token verification. All requests are treated as anonymous.
"""

from typing import Optional
from fastapi import Request


ANONYMOUS_UID = "anonymous"


def verify_request_uid(request: Request, claimed_uid: Optional[str]) -> str:
    """
    No-op auth: always returns the claimed uid or 'anonymous'.
    Firebase authentication has been disabled for hackathon demo mode.
    """
    return claimed_uid or ANONYMOUS_UID
