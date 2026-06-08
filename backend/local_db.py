"""
local_db.py — Drop-in Firestore replacement using local SQLite storage with WAL mode.
Mimics the Firestore client API surface used by Kavach AI main.py.
No Firebase / GCP credentials required.
"""

import os
import re
import json
import uuid
import sqlite3
import threading
from typing import Any, Dict, Optional, List

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp_scans", "local_store.db")
_db_initialized = False
_init_lock = threading.Lock()

_write_lock = threading.Lock()

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

def _init_db():
    global _db_initialized
    if _db_initialized:
        return
    with _init_lock:
        if _db_initialized:
            return
        os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
        conn = sqlite3.connect(_DB_PATH, timeout=30.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS documents ("
                "key TEXT PRIMARY KEY, "
                "collection TEXT, "
                "doc_id TEXT, "
                "data TEXT"
                ");"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_documents_collection ON documents(collection);"
            )
            conn.commit()
            _db_initialized = True
        finally:
            conn.close()


_local_cache = threading.local()

class _ConnectionProxy:
    def __init__(self, conn):
        self._conn = conn

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def close(self):
        # Connection is managed by the thread-local cache; do not close yet.
        pass

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def execute(self, *args, **kwargs):
        return self._conn.execute(*args, **kwargs)

    def cursor(self, *args, **kwargs):
        return self._conn.cursor(*args, **kwargs)


def _get_conn():
    _init_db()
    conn = getattr(_local_cache, "conn", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1;")
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            conn = None

    if conn is None:
        conn = sqlite3.connect(_DB_PATH, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        _local_cache.conn = conn

    return _ConnectionProxy(conn)


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


# ─── Fake ArrayUnion sentinel ──────────────────────────────────────────────────
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

    def _key(self):
        return f"{self._col}/{self.id}"

    def get(self) -> DocumentSnapshot:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM documents WHERE key = ?", (self._key(),))
            row = cursor.fetchone()
            if row:
                data = json.loads(row[0])
                return DocumentSnapshot(self.id, data)
            return DocumentSnapshot(self.id, None)
        finally:
            conn.close()

    def set(self, data: Dict):
        with _write_lock:
            conn = _get_conn()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO documents (key, collection, doc_id, data) VALUES (?, ?, ?, ?)",
                    (self._key(), self._col, self.id, _serialize_json(data))
                )
                conn.commit()
            finally:
                conn.close()

    def update(self, updates: Dict):
        with _write_lock:
            conn = _get_conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                cursor = conn.cursor()
                cursor.execute("SELECT data FROM documents WHERE key = ?", (self._key(),))
                row = cursor.fetchone()
                existing = json.loads(row[0]) if row else {}
                for k, v in updates.items():
                    if isinstance(v, ArrayUnion):
                        existing_list = _get_nested(existing, k, [])
                        if not isinstance(existing_list, list):
                            existing_list = []
                        _set_nested(existing, k, existing_list + v.values)
                    else:
                        _set_nested(existing, k, v)
                cursor.execute(
                    "INSERT OR REPLACE INTO documents (key, collection, doc_id, data) VALUES (?, ?, ?, ?)",
                    (self._key(), self._col, self.id, _serialize_json(existing))
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def increment_counter_with_limit(self, field_name: str, max_limit: int) -> int:
        """Atomically increment a counter field inside the JSON document with a maximum limit check.
        Raises ValueError if the limit is exceeded. Returns the new count.
        """
        with _write_lock:
            conn = _get_conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                cursor = conn.cursor()
                cursor.execute("SELECT data FROM documents WHERE key = ?", (self._key(),))
                row = cursor.fetchone()
                existing = json.loads(row[0]) if row else {}
                
                current_count = _get_nested(existing, field_name, 0)
                if not isinstance(current_count, int):
                    current_count = 0
                
                if current_count >= max_limit:
                    raise ValueError("Limit exceeded")
                    
                new_count = current_count + 1
                _set_nested(existing, field_name, new_count)
                
                cursor.execute(
                    "INSERT OR REPLACE INTO documents (key, collection, doc_id, data) VALUES (?, ?, ?, ?)",
                    (self._key(), self._col, self.id, _serialize_json(existing))
                )
                conn.commit()
                return new_count
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def delete(self):
        with _write_lock:
            conn = _get_conn()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM documents WHERE key = ?", (self._key(),))
                conn.commit()
            finally:
                conn.close()


# ─── Query (simplified — supports where + orderBy + limit) ────────────────────
class Query:
    def __init__(self, collection_name: str, docs: Optional[List[Dict]] = None):
        self._col = collection_name
        self._docs = docs  # list of (id, data) tuples
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
            sql = "SELECT doc_id, data FROM documents WHERE collection = ?"
            params = [self._col]
            
            for field, op, value in self._filters:
                safe_field = re.sub(r"[^a-zA-Z0-9_.-]", "", field)
                sql_op = "=" if op == "==" else op
                sql += f" AND json_extract(data, '$.{safe_field}') {sql_op} ?"
                params.append(value)
                
            if self._order_field:
                safe_order_field = re.sub(r"[^a-zA-Z0-9_.-]", "", self._order_field)
                sql += f" ORDER BY json_extract(data, '$.{safe_order_field}') {'DESC' if self._order_desc else 'ASC'}"
                
            if self._limit_n is not None:
                sql += " LIMIT ?"
                params.append(self._limit_n)
                
            conn = _get_conn()
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params)
                rows = cursor.fetchall()
                docs_to_process = []
                for doc_id, data_str in rows:
                    try:
                        data = json.loads(data_str)
                        docs_to_process.append((doc_id, data))
                    except Exception:
                        pass
            finally:
                conn.close()
                
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

        if self._docs is not None:
            # Only perform manual sorting/limiting if we didn't do it at SQL level
            if self._order_field:
                results.sort(
                    key=lambda s: _get_nested(s.to_dict(), self._order_field, ""),
                    reverse=self._order_desc
                )
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


# ─── Local DB Client (mimics firestore.client()) ──────────────────────────────
class LocalDB:
    def collection(self, name: str) -> CollectionReference:
        return CollectionReference(name)


# Direction constant (mirrors firestore.Query.DESCENDING)
class _Direction:
    DESCENDING = "DESCENDING"
    ASCENDING = "ASCENDING"

Query_Direction = _Direction()

