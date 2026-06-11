"""
supabase_db.py — Drop-in Firestore replacement using Supabase REST API (Postgrest).
Mimics the Firestore client API surface used by Kavach AI.
No heavy PostgreSQL binary dependencies (uses standard python requests).
"""

import os
import re
import json
import uuid
import logging
import threading
from typing import Any, Dict, Optional, List
import requests
import base64
import hashlib
from cryptography.fernet import Fernet

def _get_cipher():
    # Stable encryption key derived from environment or fallback
    key_source = os.getenv("KAVACH_DB_ENCRYPTION_KEY", "kavach_db_secure_encryption_key_default_321").strip()
    key_bytes = hashlib.sha256(key_source.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)

_cipher = _get_cipher()

def encrypt_data(data: Dict) -> str:
    json_str = json.dumps(data)
    encrypted_bytes = _cipher.encrypt(json_str.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')

def decrypt_data(encrypted_str: str) -> Dict:
    if not encrypted_str:
        return {}
    try:
        # Try to decrypt using Fernet
        decrypted_bytes = _cipher.decrypt(encrypted_str.strip().encode('utf-8'))
        return json.loads(decrypted_bytes.decode('utf-8'))
    except Exception:
        # Fallback to plain JSON parsing if unencrypted
        try:
            return json.loads(encrypted_str)
        except Exception:
            return {}

logger = logging.getLogger("kavach-api")

def get_supabase_config():
    url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    key = os.getenv("SUPABASE_KEY", "").strip()
    return url, key


def is_supabase_configured() -> bool:
    url, key = get_supabase_config()
    return bool(url and key)


_write_lock = threading.RLock()


def _serialize_json(data: Any) -> str:
    def helper(obj):
        if isinstance(obj, bytes):
            try:
                return obj.decode('utf-8', errors='ignore')
            except Exception:
                return obj.hex()
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return str(obj)
    return json.dumps(data, default=helper)


def _get_headers() -> Dict[str, str]:
    _, key = get_supabase_config()
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }


def _get_nested(data: Dict[str, Any], field: str, default: Any = None) -> Any:
    current: Any = data
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _set_nested(data: Dict[str, Any], field: str, value: Any) -> None:
    parts = field.split(".")
    current = data
    for part in parts[:-1]:
        next_value = current.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


# ─── ArrayUnion sentinel ──────────────────────────────────────────────────────
class ArrayUnion:
    def __init__(self, values: list):
        self.values = values


# ─── Document Snapshot ────────────────────────────────────────────────────────
class DocumentSnapshot:
    def __init__(self, doc_id: str, data: Optional[Dict]):
        self.id = doc_id
        self._data = data
        self.exists = data is not None

    def to_dict(self):
        return dict(self._data) if self._data else {}


# ─── Document Reference ───────────────────────────────────────────────────────
class DocumentReference:
    def __init__(self, collection_name: str, doc_id: str):
        self._col = collection_name
        self.id = doc_id

    def _key(self) -> str:
        return f"{self._col}/{self.id}"

    def get(self) -> DocumentSnapshot:
        if not is_supabase_configured():
            logger.warning("Supabase not configured. DocumentReference.get returning empty.")
            return DocumentSnapshot(self.id, None)

        url, _ = get_supabase_config()
        url = f"{url}/rest/v1/documents?key=eq.{self._key()}"
        try:
            res = requests.get(url, headers=_get_headers(), timeout=10.0)
            if res.status_code == 200:
                rows = res.json()
                if rows:
                    data = rows[0].get("data")
                    if isinstance(data, str):
                        data = decrypt_data(data)
                    return DocumentSnapshot(self.id, data)
            else:
                logger.error(f"Supabase GET failed ({res.status_code}): {res.text}")
        except Exception as e:
            logger.error(f"Supabase connection error in get(): {e}")
        return DocumentSnapshot(self.id, None)

    def set(self, data: Dict):
        if not is_supabase_configured():
            return
        
        # Enforce that key, collection, and doc_id are present at root level for Postgrest mapping
        payload = {
            "key": self._key(),
            "collection": self._col,
            "doc_id": self.id,
            "data": encrypt_data(data)
        }
        
        headers = _get_headers()
        headers["Prefer"] = "resolution=merge-duplicates"
        url, _ = get_supabase_config()
        url = f"{url}/rest/v1/documents"
        
        with _write_lock:
            try:
                res = requests.post(url, headers=headers, json=payload, timeout=10.0)
                if res.status_code not in (200, 201):
                    logger.error(f"Supabase SET failed ({res.status_code}): {res.text}")
            except Exception as e:
                logger.error(f"Supabase connection error in set(): {e}")

    def update(self, updates: Dict):
        if not is_supabase_configured():
            return

        with _write_lock:
            # 1. Fetch current document
            snap = self.get()
            existing = snap.to_dict() if snap.exists else {}

            # 2. Merge changes in Python
            for k, v in updates.items():
                if isinstance(v, ArrayUnion):
                    existing_list = _get_nested(existing, k, [])
                    if not isinstance(existing_list, list):
                        existing_list = []
                    _set_nested(existing, k, existing_list + v.values)
                else:
                    _set_nested(existing, k, v)

            # 3. Write back complete document
            self.set(existing)

    def increment_counter_with_limit(self, field_name: str, max_limit: int) -> int:
        """Atomically increment a counter field inside the JSON document with a maximum limit check.
        Raises ValueError if the limit is exceeded. Returns the new count.
        """
        with _write_lock:
            snap = self.get()
            existing = snap.to_dict() if snap.exists else {}
            
            current_count = _get_nested(existing, field_name, 0)
            if not isinstance(current_count, int):
                current_count = 0
            
            if current_count >= max_limit:
                raise ValueError("Limit exceeded")
                
            new_count = current_count + 1
            _set_nested(existing, field_name, new_count)
            
            self.set(existing)
            return new_count

    def check_and_update_rate_limit(self, now: float, window_secs: int, requests_limit: int) -> bool:
        """Atomically check and update rate limit timestamps in a process-safe manner using Supabase RPC."""
        if not is_supabase_configured():
            return False
            
        url, _ = get_supabase_config()
        rpc_url = f"{url}/rest/v1/rpc/check_and_update_rate_limit"
        
        payload = {
            "p_key": self._key(),
            "p_collection": self._col,
            "p_doc_id": self.id,
            "p_now": now,
            "p_window_secs": float(window_secs),
            "p_requests_limit": requests_limit
        }
        
        with _write_lock:
            try:
                res = requests.post(rpc_url, headers=_get_headers(), json=payload, timeout=10.0)
                if res.status_code == 200:
                    return res.json()
                else:
                    logger.error(f"Supabase RPC check_and_update_rate_limit failed ({res.status_code}): {res.text}. Falling back to Python read-modify-write.")
            except Exception as e:
                logger.error(f"Supabase connection error in RPC check_and_update_rate_limit: {e}. Falling back to Python read-modify-write.")
            
            # Fallback to python read-modify-write
            snap = self.get()
            existing = snap.to_dict() if snap.exists else {}
            timestamps = existing.get("timestamps", [])
            if not isinstance(timestamps, list):
                timestamps = []
            timestamps = [t for t in timestamps if now - t < window_secs]
            if len(timestamps) >= requests_limit:
                return False
            timestamps.append(now)
            existing["timestamps"] = timestamps
            self.set(existing)
            return True

    def delete(self):
        if not is_supabase_configured():
            return
        
        url, _ = get_supabase_config()
        url = f"{url}/rest/v1/documents?key=eq.{self._key()}"
        with _write_lock:
            try:
                res = requests.delete(url, headers=_get_headers(), timeout=10.0)
                if res.status_code not in (200, 204):
                    logger.error(f"Supabase DELETE failed ({res.status_code}): {res.text}")
            except Exception as e:
                logger.error(f"Supabase connection error in delete(): {e}")


# ─── Query (supports where + orderBy + limit) ─────────────────────────────────
class Query:
    def __init__(self, collection_name: str, docs: Optional[List[Dict]] = None):
        self._col = collection_name
        self._docs = docs
        self._filters: List = []
        self._order_field: Optional[str] = None
        self._order_desc: bool = False
        self._limit_n: Optional[int] = None

    def where(self, field: str, op: str, value: Any) -> "Query":
        q = Query(self._col, self._docs)
        q._filters = self._filters + [(field, op, value)]
        q._order_field = self._order_field
        q._order_desc = self._order_desc
        q._limit_n = self._limit_n
        return q

    def order_by(self, field: str, direction=None) -> "Query":
        q = Query(self._col, self._docs)
        q._filters = self._filters
        q._order_field = field
        q._order_desc = (direction == "DESCENDING")
        q._limit_n = self._limit_n
        return q

    def limit(self, n: int) -> "Query":
        q = Query(self._col, self._docs)
        q._filters = self._filters
        q._order_field = self._order_field
        q._order_desc = self._order_desc
        q._limit_n = n
        return q

    def stream(self) -> List[DocumentSnapshot]:
        docs_to_process = self._docs
        if docs_to_process is None:
            if not is_supabase_configured():
                return []
            
            url, _ = get_supabase_config()
            url = f"{url}/rest/v1/documents?collection=eq.{self._col}"
            try:
                res = requests.get(url, headers=_get_headers(), timeout=15.0)
                if res.status_code == 200:
                    rows = res.json()
                    docs_to_process = []
                    for row in rows:
                        doc_id = row.get("doc_id")
                        data = row.get("data")
                        if isinstance(data, str):
                            data = decrypt_data(data)
                        docs_to_process.append((doc_id, data))
                else:
                    logger.error(f"Supabase GET collection query failed ({res.status_code}): {res.text}")
                    return []
            except Exception as e:
                logger.error(f"Supabase connection error in stream(): {e}")
                return []

        results = []
        for doc_id, data in docs_to_process:
            match = True
            for field, op, value in self._filters:
                v = _get_nested(data, field)
                if op == "==" and v != value:
                    match = False; break
                elif op == "!=" and v == value:
                    match = False; break
                elif op == ">" and not (v is not None and v > value):
                    match = False; break
                elif op == "<" and not (v is not None and v < value):
                    match = False; break
            if match:
                results.append(DocumentSnapshot(doc_id, data))

        if self._order_field:
            def sort_key(s):
                val = _get_nested(s.to_dict(), self._order_field, "")
                return val if val is not None else ""
            results.sort(key=sort_key, reverse=self._order_desc)

        if self._limit_n is not None:
            results = results[:self._limit_n]

        return results

    def get(self) -> List[DocumentSnapshot]:
        return self.stream()


# ─── Collection Reference ─────────────────────────────────────────────────────
class CollectionReference:
    def __init__(self, name: str):
        self._name = name

    def document(self, doc_id: str = None) -> DocumentReference:
        if doc_id is None:
            doc_id = str(uuid.uuid4()).replace("-", "")
        return DocumentReference(self._name, doc_id)

    def where(self, field: str, op: str, value: Any) -> Query:
        return self._make_query().where(field, op, value)

    def order_by(self, field: str, direction=None) -> Query:
        return self._make_query().order_by(field, direction)

    def _make_query(self) -> Query:
        return Query(self._name, None)

    def get(self) -> List[DocumentSnapshot]:
        return self._make_query().get()


# ─── Supabase DB Client (mimics firestore.client()) ───────────────────────────
class SupabaseDB:
    def collection(self, name: str) -> CollectionReference:
        return CollectionReference(name)


class _Direction:
    DESCENDING = "DESCENDING"
    ASCENDING = "ASCENDING"

Query_Direction = _Direction()
