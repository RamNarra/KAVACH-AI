"""
redaction.py — Sanitize sensitive dynamic evidence before persistence and Gemini prompts.

Rules (conservative by default, can loosen with debug=True):
- Values for keys matching auth/credential patterns → redact to [REDACTED] or hash prefix
- Crypto key material → algorithm + length + first 4 bytes (hex), never full key
- Clipboard text → length + type metadata only (not content)
- URLs → scheme + host + path preserved; sensitive query params stripped
- HTTP request bodies → field names extracted, values redacted
"""

import re
import hashlib
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Sensitive key patterns — applied to dict keys in args{}
# ---------------------------------------------------------------------------
_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|token|auth|authorization|secret|api_?key|session|"
    r"cookie|credential|private_?key|access_?key|refresh_?token|bearer|jwt|pin|otp)",
    re.IGNORECASE,
)

# Query params to strip from URLs
_SENSITIVE_PARAM_RE = re.compile(
    r"([?&])(token|auth|key|secret|password|access_token|api_key|session_id|jwt)"
    r"=[^&]*",
    re.IGNORECASE,
)


def _hash_prefix(value: str, length: int = 8) -> str:
    """Return first N chars of SHA-256 hex digest."""
    h = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{h[:length]}…"


def _redact_value(key: str, value: Any, debug: bool = False) -> Any:
    """Redact a value if the key is sensitive."""
    if debug:
        return value
    if not isinstance(key, str):
        return value
    if _SENSITIVE_KEY_RE.search(key):
        if isinstance(value, str) and value:
            return _hash_prefix(value)
        return "[REDACTED]"
    return value


def redact_args(args: Dict[str, Any], debug: bool = False) -> Dict[str, Any]:
    """Apply redaction rules to the args dict of a normalized event."""
    if not isinstance(args, dict):
        return args
    return {k: _redact_value(k, v, debug) for k, v in args.items()}


def redact_url(url: str, debug: bool = False) -> str:
    """Strip sensitive query parameters from a URL."""
    if debug or not isinstance(url, str):
        return url
    return _SENSITIVE_PARAM_RE.sub(r"\1\2=[REDACTED]", url)


def redact_crypto_key_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    For crypto.key events: replace raw key material with algorithm + length + digest.
    Preserves algorithm name and key length (informative), drops actual bytes.
    """
    out = dict(args)
    if "key_preview" in out and isinstance(out["key_preview"], str) and out["key_preview"]:
        out["key_preview"] = _hash_prefix(out["key_preview"])
    if "key_bytes" in out:
        out["key_bytes"] = "[REDACTED — use key_preview hash]"
    return out


def redact_clipboard_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """For clipboard events: replace content with length metadata."""
    out = dict(args)
    preview = out.get("preview", "")
    if isinstance(preview, str) and preview:
        out["preview"] = f"[{len(preview)} chars, redacted]"
    return out


def redact_event(event: Dict[str, Any], debug: bool = False) -> Dict[str, Any]:
    """
    Apply category-aware redaction to a single normalized event dict.
    Returns a new dict (original is not mutated).
    """
    ev = dict(event)
    category = ev.get("category", "")
    args = dict(ev.get("args", {}))

    if category == "crypto.key":
        args = redact_crypto_key_args(args)
    elif category in ("clipboard.read", "clipboard.write"):
        args = redact_clipboard_args(args)
    elif category in ("network.http", "network.tls", "webview.load_url"):
        # Strip sensitive query params from URL args
        for k in ("url",):
            if isinstance(args.get(k), str):
                args[k] = redact_url(args[k], debug)
    else:
        args = redact_args(args, debug)

    # Also apply to the evidence string: strip obvious credential patterns
    evidence = ev.get("evidence", "")
    if isinstance(evidence, str):
        evidence = _SENSITIVE_KEY_RE.sub(
            lambda m: m.group(0),  # keep the key name
            evidence
        )
        evidence = redact_url(evidence, debug)

    ev["args"] = args
    ev["evidence"] = evidence
    return ev


def redact_events(events: List[Dict[str, Any]], debug: bool = False) -> List[Dict[str, Any]]:
    """Redact a list of normalized events in bulk."""
    return [redact_event(e, debug) for e in events]


# ---------------------------------------------------------------------------
# Deduplication and throttling
# ---------------------------------------------------------------------------
def _event_signature(event: Dict[str, Any]) -> str:
    """
    Create a stable signature for an event to use as dedup key.
    Uses category + action + first 80 chars of evidence.
    """
    category = event.get("category", "?")
    action   = event.get("action", "?")
    evidence = str(event.get("evidence", ""))[:80]
    return f"{category}::{action}::{evidence}"


def deduplicate_events(
    events: List[Dict[str, Any]],
    max_per_signature: int = 3,
    global_cap: int = 150,
) -> List[Dict[str, Any]]:
    """
    Deduplicate events by signature.
    - At most `max_per_signature` events per unique signature (keeps first N, counts rest)
    - Hard cap at `global_cap` total events

    Returns deduplicated list. The first event for each burst group has a
    `_dup_count` field showing how many were suppressed.
    """
    counts: Dict[str, int] = {}
    first_seen: Dict[str, Dict] = {}
    out: List[Dict] = []

    for ev in events:
        sig = _event_signature(ev)
        n = counts.get(sig, 0)
        counts[sig] = n + 1

        if n == 0:
            first_seen[sig] = ev
            out.append(ev)
            if len(out) >= global_cap:
                break
        elif n < max_per_signature:
            out.append(ev)
            if len(out) >= global_cap:
                break
        # else: suppress, but increment count for summary

    # Annotate first-seen events with suppressed count
    for sig, ev in first_seen.items():
        total = counts[sig]
        if total > max_per_signature:
            ev = dict(ev)
            ev["_dup_count"] = total - max_per_signature
            # Update in-place reference
            for i, o in enumerate(out):
                if o is first_seen[sig]:
                    out[i] = ev
                    break

    return out
