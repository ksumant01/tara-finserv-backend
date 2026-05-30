"""
TARA Finserv — MongoDB-compatible adapter over MySQL JSON columns.

Goal: let `server.py` keep using `await db.<collection>.find_one(...)` etc.
exactly as it did with Motor (MongoDB), without rewriting any business logic.

How:
- Each "collection" is a MySQL table with two columns: `doc_id VARCHAR(64)` PK
  and `doc JSON NOT NULL`. We load documents in-memory and filter in Python
  (data volumes for a DSA platform are tiny — well within hundreds of MB).
- Implements ONLY the Motor surface area used by server.py:
    find_one, find (+sort, projection, to_list),
    insert_one, update_one (with upsert), update_many,
    delete_one, count_documents, find_one_and_update,
    create_index (no-op, harmless).
- Supports operators used by server.py:
    $set, $inc, $in, $or, $regex, $options (case-insensitive)
- All async methods run sync MySQL calls inside `asyncio.to_thread` so the
  FastAPI event loop is never blocked.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pymysql
from pymysql.cursors import DictCursor


# ---------- low-level pool ----------
class _Pool:
    """Tiny thread-safe connection pool (good enough for cPanel Passenger)."""

    def __init__(self, host: str, port: int, user: str, password: str, db: str, size: int = 4):
        self._cfg = dict(
            host=host, port=port, user=user, password=password, database=db,
            charset="utf8mb4", autocommit=True, cursorclass=DictCursor,
        )
        self._lock = threading.Lock()
        self._conns: List[pymysql.connections.Connection] = []
        self._size = size

    def _new(self):
        return pymysql.connect(**self._cfg)

    def get(self):
        with self._lock:
            while self._conns:
                c = self._conns.pop()
                try:
                    c.ping(reconnect=True)
                    return c
                except Exception:
                    try: c.close()
                    except Exception: pass
            return self._new()

    def put(self, c):
        with self._lock:
            if len(self._conns) < self._size:
                self._conns.append(c)
            else:
                try: c.close()
                except Exception: pass


# ---------- query matcher ----------
def _to_regex(pat: str, opts: str = "") -> re.Pattern:
    flags = re.IGNORECASE if "i" in (opts or "") else 0
    return re.compile(pat, flags)


def _match_value(actual: Any, expected: Any) -> bool:
    # Operator dict like {"$regex": "x", "$options": "i"} or {"$in": [...]}
    if isinstance(expected, dict) and any(k.startswith("$") for k in expected.keys()):
        for op, val in expected.items():
            if op == "$regex":
                opts = expected.get("$options", "")
                if actual is None or not _to_regex(val, opts).search(str(actual)):
                    return False
            elif op == "$options":
                pass  # handled with $regex
            elif op == "$in":
                if actual not in val:
                    return False
            elif op == "$nin":
                if actual in val:
                    return False
            elif op == "$ne":
                if actual == val:
                    return False
            elif op == "$gt":
                if not (actual is not None and actual > val): return False
            elif op == "$gte":
                if not (actual is not None and actual >= val): return False
            elif op == "$lt":
                if not (actual is not None and actual < val): return False
            elif op == "$lte":
                if not (actual is not None and actual <= val): return False
            elif op == "$exists":
                exists = actual is not None
                if bool(val) != exists:
                    return False
            else:
                # Unknown operator → fail safe
                return False
        return True
    return actual == expected


def _get_path(doc: Dict[str, Any], path: str) -> Any:
    """Get nested field by dotted path."""
    cur: Any = doc
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _matches(doc: Dict[str, Any], query: Dict[str, Any]) -> bool:
    if not query:
        return True
    for k, v in query.items():
        if k == "$or":
            if not any(_matches(doc, sub) for sub in v):
                return False
        elif k == "$and":
            if not all(_matches(doc, sub) for sub in v):
                return False
        else:
            if not _match_value(_get_path(doc, k), v):
                return False
    return True


# ---------- update operators ----------
def _set_path(doc: Dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = doc
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _apply_update(doc: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    if not update:
        return doc
    # Operator-based update
    if any(k.startswith("$") for k in update.keys()):
        for op, payload in update.items():
            if op == "$set":
                for k, v in (payload or {}).items():
                    _set_path(doc, k, v)
            elif op == "$inc":
                for k, v in (payload or {}).items():
                    cur = _get_path(doc, k) or 0
                    _set_path(doc, k, cur + v)
            elif op == "$unset":
                for k in (payload or {}).keys():
                    parts = k.split(".")
                    c = doc
                    for p in parts[:-1]:
                        if not isinstance(c, dict): return doc
                        c = c.get(p, {})
                    if isinstance(c, dict): c.pop(parts[-1], None)
            elif op == "$push":
                for k, v in (payload or {}).items():
                    cur = _get_path(doc, k)
                    if not isinstance(cur, list):
                        cur = []
                    cur.append(v)
                    _set_path(doc, k, cur)
            else:
                pass
        return doc
    # Whole-doc replacement
    return dict(update)


# ---------- projection ----------
def _apply_projection(doc: Dict[str, Any], proj: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not proj:
        return doc
    # Pymongo allows mix; in server.py only exclusion is used (e.g. {"_id":0,"password_hash":0,"kyc.doc_base64":0})
    out = json.loads(json.dumps(doc))  # deep copy
    for key, flag in proj.items():
        if flag == 0:
            parts = key.split(".")
            c = out
            for p in parts[:-1]:
                if not isinstance(c, dict): break
                c = c.get(p)
            if isinstance(c, dict):
                c.pop(parts[-1], None)
    return out


# ---------- cursor ----------
class _Cursor:
    def __init__(self, docs: List[Dict[str, Any]], projection: Optional[Dict[str, Any]] = None):
        self._docs = docs
        self._projection = projection
        self._sort: Optional[Tuple[str, int]] = None
        self._skip = 0
        self._limit = 0

    def sort(self, key, direction: int = 1):
        # Accept ("field", 1) tuple list too
        if isinstance(key, list):
            # only first key supported
            self._sort = (key[0][0], key[0][1])
        else:
            self._sort = (key, direction)
        return self

    def skip(self, n: int):
        self._skip = n; return self

    def limit(self, n: int):
        self._limit = n; return self

    async def to_list(self, length: Optional[int] = None):
        docs = list(self._docs)
        if self._sort:
            k, d = self._sort
            docs.sort(key=lambda x: (_get_path(x, k) is None, _get_path(x, k) or ""), reverse=(d == -1))
        if self._skip:
            docs = docs[self._skip:]
        if length:
            docs = docs[:length]
        elif self._limit:
            docs = docs[:self._limit]
        return [_apply_projection(d, self._projection) for d in docs]


# ---------- collection ----------
class _Collection:
    def __init__(self, db: "MongoMySQLDB", name: str):
        self.db = db
        self.name = name

    # ----- sync helpers -----
    def _ensure_table(self, c):
        c.execute(
            f"CREATE TABLE IF NOT EXISTS `{self.name}` ("
            "  doc_id VARCHAR(128) NOT NULL,"
            "  doc JSON NOT NULL,"
            "  PRIMARY KEY (doc_id)"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"
        )

    def _load_all(self) -> List[Dict[str, Any]]:
        conn = self.db.pool.get()
        try:
            with conn.cursor() as c:
                self._ensure_table(c)
                c.execute(f"SELECT doc FROM `{self.name}`")
                rows = c.fetchall()
                out = []
                for r in rows:
                    d = r["doc"]
                    if isinstance(d, (bytes, bytearray)):
                        d = d.decode("utf-8")
                    if isinstance(d, str):
                        d = json.loads(d)
                    out.append(d)
                return out
        finally:
            self.db.pool.put(conn)

    def _resolve_id(self, doc: Dict[str, Any]) -> str:
        # We use "id" from the app domain (UUIDs/strings) when present,
        # otherwise stringify "_id", otherwise generate.
        if "id" in doc and doc["id"] is not None:
            return str(doc["id"])
        if "_id" in doc and doc["_id"] is not None:
            return str(doc["_id"])
        # No id at all → generate (won't happen for current server.py paths)
        import uuid as _uuid
        new_id = str(_uuid.uuid4())
        doc["id"] = new_id
        return new_id

    def _sync_insert(self, doc: Dict[str, Any]) -> str:
        doc_id = self._resolve_id(doc)
        conn = self.db.pool.get()
        try:
            with conn.cursor() as c:
                self._ensure_table(c)
                c.execute(
                    f"INSERT INTO `{self.name}` (doc_id, doc) VALUES (%s, %s)",
                    (doc_id, json.dumps(doc, default=str)),
                )
        finally:
            self.db.pool.put(conn)
        return doc_id

    def _sync_upsert(self, doc_id: str, doc: Dict[str, Any]):
        conn = self.db.pool.get()
        try:
            with conn.cursor() as c:
                self._ensure_table(c)
                c.execute(
                    f"INSERT INTO `{self.name}` (doc_id, doc) VALUES (%s, %s) "
                    f"ON DUPLICATE KEY UPDATE doc = VALUES(doc)",
                    (doc_id, json.dumps(doc, default=str)),
                )
        finally:
            self.db.pool.put(conn)

    def _sync_delete(self, doc_id: str) -> int:
        conn = self.db.pool.get()
        try:
            with conn.cursor() as c:
                self._ensure_table(c)
                return c.execute(f"DELETE FROM `{self.name}` WHERE doc_id=%s", (doc_id,))
        finally:
            self.db.pool.put(conn)

    # ----- async API (Motor-compatible) -----
    async def find_one(self, query: Dict[str, Any], projection: Optional[Dict[str, Any]] = None):
        def _do():
            for d in self._load_all():
                if _matches(d, query):
                    return _apply_projection(d, projection)
            return None
        return await asyncio.to_thread(_do)

    def find(self, query: Dict[str, Any] = None, projection: Optional[Dict[str, Any]] = None):
        # Synchronous load; cursor wraps results
        docs = [d for d in self._load_all() if _matches(d, query or {})]
        return _Cursor(docs, projection)

    async def insert_one(self, doc: Dict[str, Any]):
        def _do():
            d = dict(doc)
            new_id = self._sync_insert(d)
            class _R: pass
            r = _R(); r.inserted_id = new_id
            return r
        return await asyncio.to_thread(_do)

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any], upsert: bool = False):
        def _do():
            docs = self._load_all()
            for d in docs:
                if _matches(d, query):
                    self._resolve_id(d)  # ensure id present
                    new_doc = _apply_update(d, update)
                    self._sync_upsert(self._resolve_id(new_doc), new_doc)
                    class _R: pass
                    r = _R(); r.matched_count = 1; r.modified_count = 1; r.upserted_id = None
                    return r
            if upsert:
                # build new doc from query (only direct equality keys) + $set
                base = {k: v for k, v in query.items() if not isinstance(v, dict) and not k.startswith("$")}
                new_doc = _apply_update(base, update)
                new_id = self._sync_insert(new_doc)
                class _R: pass
                r = _R(); r.matched_count = 0; r.modified_count = 0; r.upserted_id = new_id
                return r
            class _R: pass
            r = _R(); r.matched_count = 0; r.modified_count = 0; r.upserted_id = None
            return r
        return await asyncio.to_thread(_do)

    async def update_many(self, query: Dict[str, Any], update: Dict[str, Any]):
        def _do():
            n = 0
            for d in self._load_all():
                if _matches(d, query):
                    new_doc = _apply_update(d, update)
                    self._sync_upsert(self._resolve_id(new_doc), new_doc)
                    n += 1
            class _R: pass
            r = _R(); r.matched_count = n; r.modified_count = n
            return r
        return await asyncio.to_thread(_do)

    async def delete_one(self, query: Dict[str, Any]):
        def _do():
            for d in self._load_all():
                if _matches(d, query):
                    n = self._sync_delete(self._resolve_id(d))
                    class _R: pass
                    r = _R(); r.deleted_count = n
                    return r
            class _R: pass
            r = _R(); r.deleted_count = 0
            return r
        return await asyncio.to_thread(_do)

    async def count_documents(self, query: Dict[str, Any]):
        def _do():
            return sum(1 for d in self._load_all() if _matches(d, query or {}))
        return await asyncio.to_thread(_do)

    async def find_one_and_update(self, query: Dict[str, Any], update: Dict[str, Any],
                                  upsert: bool = False, return_document: Any = False):
        # return_document=True (or pymongo's ReturnDocument.AFTER) → return new doc
        want_after = bool(return_document)
        def _do():
            for d in self._load_all():
                if _matches(d, query):
                    before = json.loads(json.dumps(d))
                    new_doc = _apply_update(d, update)
                    self._sync_upsert(self._resolve_id(new_doc), new_doc)
                    return new_doc if want_after else before
            if upsert:
                base = {k: v for k, v in query.items() if not isinstance(v, dict) and not k.startswith("$")}
                if "_id" in query:
                    base["_id"] = query["_id"]
                new_doc = _apply_update(base, update)
                self._sync_insert(new_doc)
                return new_doc if want_after else None
            return None
        return await asyncio.to_thread(_do)

    async def create_index(self, *args, **kwargs):
        # We don't need MySQL indexes for these volumes — uniqueness is enforced
        # by application logic (server.py already checks duplicates before insert).
        return None


# ---------- DB ----------
class MongoMySQLDB:
    def __init__(self, host: str, port: int, user: str, password: str, db: str):
        self.pool = _Pool(host, port, user, password, db)

    def __getattr__(self, name):
        # Lazy collection access: db.users, db.agents, etc.
        coll = _Collection(self, name)
        setattr(self, name, coll)
        return coll


# ---------- helper to parse a MYSQL_URL or individual env vars ----------
def db_from_env() -> MongoMySQLDB:
    """
    Reads either:
      MYSQL_URL=mysql://user:pass@host:port/dbname   (single URL)
    or:
      MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
    """
    url = os.environ.get("MYSQL_URL")
    if url:
        # very small parser: mysql://user:pass@host:port/dbname
        m = re.match(r"^mysql://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(.+)$", url)
        if not m:
            raise RuntimeError("MYSQL_URL malformed. Expected mysql://user:pass@host:port/dbname")
        user, password, host, port, dbn = m.groups()
        return MongoMySQLDB(host, int(port or 3306), user, password, dbn)
    return MongoMySQLDB(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ["MYSQL_USER"],
        password=os.environ["MYSQL_PASSWORD"],
        db=os.environ["MYSQL_DB"],
    )
