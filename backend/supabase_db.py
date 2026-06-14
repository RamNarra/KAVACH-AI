"""
supabase_db.py — Database client wrapper using Supabase REST API (Postgrest).
Provides query/document abstraction used by Kavach AI.
No heavy PostgreSQL binary dependencies (uses standard python requests).
"""

import os
import time
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
    key_source = os.getenv("KAVACH_DB_ENCRYPTION_KEY", "").strip()
    if not key_source:
        import sys
        is_production = os.getenv("KAVACH_ENV", "development").strip().lower() in ("production", "prod")
        
        if is_production:
            raise RuntimeError(
                "CRITICAL CONFIGURATION ERROR: KAVACH_DB_ENCRYPTION_KEY must be configured in environment."
            )
        
        logger = logging.getLogger("kavach-api")
        logger.warning(
            "CRITICAL SECURITY WARNING: KAVACH_DB_ENCRYPTION_KEY is not defined in the environment. "
            "Using a transient dynamically-generated session key. Encrypted database records will NOT persist across backend restarts."
        )
        # Fall back to SUPABASE_JWT_SECRET if available as a dynamic per-deployment secret
        key_source = os.getenv("SUPABASE_JWT_SECRET", "").strip()
        if not key_source:
            # Fall back to a completely random cryptographically secure dynamic key
            key_source = os.urandom(32).hex()

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
        self._cached_data: Optional[Dict] = None
        self._cached_encrypted_data: Optional[str] = None

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
                    raw_data = rows[0].get("data")
                    self._cached_encrypted_data = raw_data
                    data = raw_data
                    if isinstance(data, str):
                        data = decrypt_data(data)
                    self._cached_data = data
                    return DocumentSnapshot(self.id, data)
                else:
                    self._cached_data = None
                    self._cached_encrypted_data = None
            else:
                logger.error(f"Supabase GET failed ({res.status_code}): {res.text}")
        except Exception as e:
            logger.error(f"Supabase connection error in get(): {e}")
        return DocumentSnapshot(self.id, None)

    def set(self, data: Dict):
        if not is_supabase_configured():
            return
        
        # Enforce that key, collection, and doc_id are present at root level for Postgrest mapping
        encrypted = encrypt_data(data)
        payload = {
            "key": self._key(),
            "collection": self._col,
            "doc_id": self.id,
            "data": encrypted
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
                else:
                    self._cached_data = dict(data)
                    self._cached_encrypted_data = encrypted
            except Exception as e:
                logger.error(f"Supabase connection error in set(): {e}")

    def update(self, updates: Dict):
        if not is_supabase_configured():
            return

        url, _ = get_supabase_config()
        headers = _get_headers()

        with _write_lock:
            for attempt in range(5):
                row_exists = False
                fetched_encrypted_data = None
                existing = {}

                if self._cached_data is not None:
                    row_exists = True
                    existing = dict(self._cached_data)
                    fetched_encrypted_data = self._cached_encrypted_data
                else:
                    url_get = f"{url}/rest/v1/documents?key=eq.{self._key()}"
                    try:
                        res = requests.get(url_get, headers=headers, timeout=10.0)
                        if res.status_code == 200:
                            rows = res.json()
                            if rows:
                                row_exists = True
                                fetched_encrypted_data = rows[0].get("data")
                                if isinstance(fetched_encrypted_data, str):
                                    existing = decrypt_data(fetched_encrypted_data)
                                elif isinstance(fetched_encrypted_data, dict):
                                    existing = fetched_encrypted_data
                                
                                self._cached_data = existing
                                self._cached_encrypted_data = fetched_encrypted_data
                            else:
                                self._cached_data = None
                                self._cached_encrypted_data = None
                        else:
                            logger.error(f"Supabase GET failed in update ({res.status_code}): {res.text}")
                    except Exception as e:
                        logger.error(f"Supabase connection/request error in update() GET phase: {e}")

                # Merge updates
                for k, v in updates.items():
                    if isinstance(v, ArrayUnion):
                        existing_list = _get_nested(existing, k, [])
                        if not isinstance(existing_list, list):
                            existing_list = []
                        _set_nested(existing, k, existing_list + v.values)
                    else:
                        _set_nested(existing, k, v)

                new_encrypted_data = encrypt_data(existing)

                try:
                    if row_exists:
                        params = {
                            "key": f"eq.{self._key()}",
                        }
                        if fetched_encrypted_data is not None:
                            if isinstance(fetched_encrypted_data, str):
                                params["data"] = f"eq.{fetched_encrypted_data}"
                            else:
                                params["data"] = f"eq.{json.dumps(fetched_encrypted_data)}"
                        else:
                            params["data"] = "is.null"

                        payload = {
                            "data": new_encrypted_data
                        }

                        res_patch = requests.patch(
                            f"{url}/rest/v1/documents",
                            headers=headers,
                            json=payload,
                            params=params,
                            timeout=10.0
                        )

                        if res_patch.status_code in (200, 204):
                            updated_rows = res_patch.json() if res_patch.text else []
                            if res_patch.text and not updated_rows:
                                logger.warning(f"OCC conflict on update for {self._key()}, retrying... (attempt {attempt + 1})")
                                self._cached_data = None
                                self._cached_encrypted_data = None
                                time.sleep(0.05 * (attempt + 1))
                                continue
                            
                            self._cached_data = existing
                            self._cached_encrypted_data = new_encrypted_data
                            return
                        else:
                            logger.error(f"Supabase PATCH failed ({res_patch.status_code}): {res_patch.text}")
                            self._cached_data = None
                            self._cached_encrypted_data = None
                            time.sleep(0.05 * (attempt + 1))
                            continue
                    else:
                        payload = {
                            "key": self._key(),
                            "collection": self._col,
                            "doc_id": self.id,
                            "data": new_encrypted_data
                        }

                        res_post = requests.post(
                            f"{url}/rest/v1/documents",
                            headers=headers,
                            json=payload,
                            timeout=10.0
                        )

                        if res_post.status_code in (200, 201):
                            self._cached_data = existing
                            self._cached_encrypted_data = new_encrypted_data
                            return
                        elif res_post.status_code == 409:
                            logger.warning(f"OCC conflict (duplicate key) on insert for {self._key()}, retrying... (attempt {attempt + 1})")
                            self._cached_data = None
                            self._cached_encrypted_data = None
                            time.sleep(0.05 * (attempt + 1))
                            continue
                        else:
                            logger.error(f"Supabase POST failed ({res_post.status_code}): {res_post.text}")
                            self._cached_data = None
                            self._cached_encrypted_data = None
                            time.sleep(0.05 * (attempt + 1))
                            continue
                except Exception as e:
                    logger.error(f"Supabase connection/request error in update() PATCH/POST phase: {e}")
                    self._cached_data = None
                    self._cached_encrypted_data = None
                    time.sleep(0.05 * (attempt + 1))
                    continue
            logger.error(f"Failed to update document {self._key()} after 5 attempts due to concurrency conflicts or network issues.")

    def increment_counter_with_limit(self, field_name: str, max_limit: int) -> int:
        """Atomically increment a counter field inside the JSON document with a maximum limit check.
        Raises ValueError if the limit is exceeded. Returns the new count.
        """
        if not is_supabase_configured():
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

        url, _ = get_supabase_config()
        headers = _get_headers()

        with _write_lock:
            for attempt in range(5):
                row_exists = False
                fetched_encrypted_data = None
                existing = {}

                if self._cached_data is not None:
                    row_exists = True
                    existing = dict(self._cached_data)
                    fetched_encrypted_data = self._cached_encrypted_data
                else:
                    url_get = f"{url}/rest/v1/documents?key=eq.{self._key()}"
                    try:
                        res = requests.get(url_get, headers=headers, timeout=10.0)
                        if res.status_code == 200:
                            rows = res.json()
                            if rows:
                                row_exists = True
                                fetched_encrypted_data = rows[0].get("data")
                                if isinstance(fetched_encrypted_data, str):
                                    existing = decrypt_data(fetched_encrypted_data)
                                elif isinstance(fetched_encrypted_data, dict):
                                    existing = fetched_encrypted_data
                                self._cached_data = existing
                                self._cached_encrypted_data = fetched_encrypted_data
                            else:
                                self._cached_data = None
                                self._cached_encrypted_data = None
                        else:
                            logger.error(f"Supabase GET failed in increment ({res.status_code}): {res.text}")
                    except Exception as e:
                        logger.error(f"Supabase GET error in increment: {e}")

                current_count = _get_nested(existing, field_name, 0)
                if not isinstance(current_count, int):
                    current_count = 0

                if current_count >= max_limit:
                    raise ValueError("Limit exceeded")

                new_count = current_count + 1
                _set_nested(existing, field_name, new_count)

                new_encrypted_data = encrypt_data(existing)

                try:
                    if row_exists:
                        params = {
                            "key": f"eq.{self._key()}",
                        }
                        if fetched_encrypted_data is not None:
                            if isinstance(fetched_encrypted_data, str):
                                params["data"] = f"eq.{fetched_encrypted_data}"
                            else:
                                params["data"] = f"eq.{json.dumps(fetched_encrypted_data)}"
                        else:
                            params["data"] = "is.null"

                        payload = {
                            "data": new_encrypted_data
                        }

                        res_patch = requests.patch(
                            f"{url}/rest/v1/documents",
                            headers=headers,
                            json=payload,
                            params=params,
                            timeout=10.0
                        )

                        if res_patch.status_code in (200, 204):
                            updated_rows = res_patch.json() if res_patch.text else []
                            if res_patch.text and not updated_rows:
                                logger.warning(f"OCC conflict on increment for {self._key()}, retrying... (attempt {attempt + 1})")
                                self._cached_data = None
                                self._cached_encrypted_data = None
                                time.sleep(0.05 * (attempt + 1))
                                continue
                            
                            self._cached_data = existing
                            self._cached_encrypted_data = new_encrypted_data
                            return new_count
                        else:
                            logger.error(f"Supabase PATCH failed ({res_patch.status_code}): {res_patch.text}")
                            self._cached_data = None
                            self._cached_encrypted_data = None
                            time.sleep(0.05 * (attempt + 1))
                            continue
                    else:
                        payload = {
                            "key": self._key(),
                            "collection": self._col,
                            "doc_id": self.id,
                            "data": new_encrypted_data
                        }

                        res_post = requests.post(
                            f"{url}/rest/v1/documents",
                            headers=headers,
                            json=payload,
                            timeout=10.0
                        )

                        if res_post.status_code in (200, 201):
                            self._cached_data = existing
                            self._cached_encrypted_data = new_encrypted_data
                            return new_count
                        elif res_post.status_code == 409:
                            logger.warning(f"OCC conflict on increment (duplicate key) for {self._key()}, retrying... (attempt {attempt + 1})")
                            self._cached_data = None
                            self._cached_encrypted_data = None
                            time.sleep(0.05 * (attempt + 1))
                            continue
                        else:
                            logger.error(f"Supabase POST failed ({res_post.status_code}): {res_post.text}")
                            self._cached_data = None
                            self._cached_encrypted_data = None
                            time.sleep(0.05 * (attempt + 1))
                            continue
                except ValueError:
                    raise
                except Exception as e:
                    logger.error(f"Supabase connection/request error in increment_counter_with_limit(): {e}")
                    self._cached_data = None
                    self._cached_encrypted_data = None
                    time.sleep(0.05 * (attempt + 1))
                    continue
        raise RuntimeError("Failed to increment counter due to database concurrency conflicts")

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
            
            # Fallback to python OCC read-modify-write
            for attempt in range(5):
                row_exists = False
                fetched_encrypted_data = None
                existing = {}

                if self._cached_data is not None:
                    row_exists = True
                    existing = dict(self._cached_data)
                    fetched_encrypted_data = self._cached_encrypted_data
                else:
                    url_get = f"{url}/rest/v1/documents?key=eq.{self._key()}"
                    try:
                        res = requests.get(url_get, headers=_get_headers(), timeout=10.0)
                        if res.status_code == 200:
                            rows = res.json()
                            if rows:
                                row_exists = True
                                fetched_encrypted_data = rows[0].get("data")
                                if isinstance(fetched_encrypted_data, str):
                                    existing = decrypt_data(fetched_encrypted_data)
                                elif isinstance(fetched_encrypted_data, dict):
                                    existing = fetched_encrypted_data
                                self._cached_data = existing
                                self._cached_encrypted_data = fetched_encrypted_data
                            else:
                                self._cached_data = None
                                self._cached_encrypted_data = None
                        else:
                            logger.error(f"Supabase GET failed in rate limit fallback ({res.status_code}): {res.text}")
                    except Exception as e:
                        logger.error(f"Supabase GET error in rate limit fallback: {e}")
            
                timestamps = existing.get("timestamps", [])
                if not isinstance(timestamps, list):
                    timestamps = []
                timestamps = [t for t in timestamps if now - t < window_secs]
                if len(timestamps) >= requests_limit:
                    return False
                timestamps.append(now)
                existing["timestamps"] = timestamps
                new_encrypted_data = encrypt_data(existing)

                if row_exists:
                    params = {
                        "key": f"eq.{self._key()}",
                    }
                    if fetched_encrypted_data is not None:
                        if isinstance(fetched_encrypted_data, str):
                            params["data"] = f"eq.{fetched_encrypted_data}"
                        else:
                            params["data"] = f"eq.{json.dumps(fetched_encrypted_data)}"
                    else:
                        params["data"] = "is.null"

                    payload = {
                        "data": new_encrypted_data
                    }

                    res_patch = requests.patch(
                        f"{url}/rest/v1/documents",
                        headers=_get_headers(),
                        json=payload,
                        params=params,
                        timeout=10.0
                    )

                    if res_patch.status_code in (200, 204):
                        updated_rows = res_patch.json() if res_patch.text else []
                        if res_patch.text and not updated_rows:
                            logger.warning(f"OCC conflict on check_and_update_rate_limit fallback for {self._key()}, retrying... (attempt {attempt + 1})")
                            self._cached_data = None
                            self._cached_encrypted_data = None
                            time.sleep(0.05 * (attempt + 1))
                            continue
                        self._cached_data = existing
                        self._cached_encrypted_data = new_encrypted_data
                        return True
                    else:
                        logger.error(f"Supabase PATCH failed ({res_patch.status_code}): {res_patch.text}")
                        self._cached_data = None
                        self._cached_encrypted_data = None
                        time.sleep(0.05 * (attempt + 1))
                        continue
                else:
                    payload = {
                        "key": self._key(),
                        "collection": self._col,
                        "doc_id": self.id,
                        "data": new_encrypted_data
                    }

                    res_post = requests.post(
                        f"{url}/rest/v1/documents",
                        headers=_get_headers(),
                        json=payload,
                        timeout=10.0
                    )

                    if res_post.status_code in (200, 201):
                        self._cached_data = existing
                        self._cached_encrypted_data = new_encrypted_data
                        return True
                    elif res_post.status_code == 409:
                        logger.warning(f"OCC conflict on check_and_update_rate_limit fallback (duplicate key) for {self._key()}, retrying... (attempt {attempt + 1})")
                        self._cached_data = None
                        self._cached_encrypted_data = None
                        time.sleep(0.05 * (attempt + 1))
                        continue
                    else:
                        logger.error(f"Supabase POST failed ({res_post.status_code}): {res_post.text}")
                        self._cached_data = None
                        self._cached_encrypted_data = None
                        time.sleep(0.05 * (attempt + 1))
                        continue
            return False

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
                else:
                    self._cached_data = None
                    self._cached_encrypted_data = None
            except Exception as e:
                logger.error(f"Supabase connection error in delete(): {e}")


# ─── Query (supports where + orderBy + limit) ─────────────────────────────────
class Query:
    DESCENDING = "DESCENDING"
    ASCENDING = "ASCENDING"

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
    ArrayUnion = ArrayUnion
    Query = Query

    def collection(self, name: str) -> CollectionReference:
        return CollectionReference(name)


class _Direction:
    DESCENDING = "DESCENDING"
    ASCENDING = "ASCENDING"

Query_Direction = _Direction()
