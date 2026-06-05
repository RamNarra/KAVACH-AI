"""
local_db.py — Drop-in Firestore replacement using local JSON file storage.
Mimics the Firestore client API surface used by Kavach AI main.py.
No Firebase / GCP credentials required.
"""

import os
import json
import uuid
import threading
from typing import Any, Dict, Optional, List
import tempfile

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None

_STORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp_scans", "local_store.json")
_lock = threading.Lock()
_LOCK_PATH = _STORE_PATH + ".lock"


def _load() -> Dict[str, Any]:
    if os.path.exists(_STORE_PATH):
        try:
            with open(_STORE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save(data: Dict[str, Any]):
    os.makedirs(os.path.dirname(_STORE_PATH), exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix="local_store_", suffix=".json", dir=os.path.dirname(_STORE_PATH))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, default=str)
        os.replace(temp_path, _STORE_PATH)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


class _FileLock:
    def __enter__(self):
        os.makedirs(os.path.dirname(_LOCK_PATH), exist_ok=True)
        self._fh = open(_LOCK_PATH, "a+", encoding="utf-8")
        if fcntl is not None:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        return self._fh

    def __exit__(self, exc_type, exc, tb):
        if fcntl is not None:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        self._fh.close()


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
        with _lock, _FileLock():
            store = _load()
        data = store.get(self._key())
        return DocumentSnapshot(self.id, data)

    def set(self, data: Dict):
        with _lock, _FileLock():
            store = _load()
            store[self._key()] = dict(data)
            _save(store)

    def update(self, updates: Dict):
        with _lock, _FileLock():
            store = _load()
            existing = store.get(self._key(), {})
            for k, v in updates.items():
                if isinstance(v, ArrayUnion):
                    existing_list = _get_nested(existing, k, [])
                    if not isinstance(existing_list, list):
                        existing_list = []
                    _set_nested(existing, k, existing_list + v.values)
                else:
                    _set_nested(existing, k, v)
            store[self._key()] = existing
            _save(store)

    def delete(self):
        with _lock, _FileLock():
            store = _load()
            store.pop(self._key(), None)
            _save(store)


# ─── Query (simplified — supports where + orderBy + limit) ────────────────────
class Query:
    def __init__(self, collection_name: str, docs: List[Dict]):
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
        results = []
        for doc_id, data in self._docs:
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
        with _lock, _FileLock():
            store = _load()
        prefix = f"{self._name}/"
        docs = [
            (k[len(prefix):], v)
            for k, v in store.items()
            if k.startswith(prefix)
        ]
        return Query(self._name, docs)

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
