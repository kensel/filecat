"""MySQL/MariaDB backend: pymysql, `document` stored as JSON.

The driver import happens inside __init__ so importing this module does
not require pymysql unless the mysql backend is actually used.

`rel_path` can be longer than MySQL's index key-length limit (InnoDB caps
an index at 3072 bytes, less for older configurations, and that is shared
across the whole key), so uniqueness is enforced on a `rel_hash` column
(sha256 hex of rel_path) instead of rel_path itself: UNIQUE (root_id,
rel_hash). The same trick is used for `agg_dir.dir`, which can also be an
arbitrarily long path. `get()`/`put()` compute rel_hash from rel_path, so
callers never see the hash.

`list()` and `list_programs()` use an unbuffered cursor (SSCursor) so a
multi-million row table is streamed rather than pulled into memory.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Iterable, Iterator

from ..record import root_id
from .base import Backend, Document

BATCH_SIZE = 500
BATCH_SECONDS = 2.0

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS files (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        root_id VARCHAR(32) NOT NULL,
        root TEXT NOT NULL,
        rel_path TEXT NOT NULL,
        rel_hash CHAR(64) NOT NULL,
        name VARCHAR(512),
        size BIGINT,
        mtime_ns BIGINT,
        kind VARCHAR(32),
        suffix VARCHAR(190),
        mime VARCHAR(190),
        sha256 CHAR(64),
        sha256_partial VARCHAR(255),
        document JSON NOT NULL,
        UNIQUE KEY uq_files_root_relhash (root_id, rel_hash),
        KEY idx_files_root_id (root_id),
        KEY idx_files_sha256 (sha256),
        KEY idx_files_kind (kind),
        KEY idx_files_suffix (suffix),
        KEY idx_files_mime (mime)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS programs (
        program_id VARCHAR(255) PRIMARY KEY,
        document JSON NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS roots (
        root_id VARCHAR(32) PRIMARY KEY,
        root TEXT NOT NULL,
        document JSON NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS treemaps (
        id VARCHAR(32) PRIMARY KEY,
        root_id VARCHAR(32) NOT NULL,
        meta JSON NOT NULL,
        data LONGTEXT NOT NULL,
        KEY idx_treemaps_root (root_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS agg_suffix (
        root_id VARCHAR(32) NOT NULL, root TEXT NOT NULL,
        suffix VARCHAR(190) NOT NULL, description TEXT,
        files BIGINT, bytes BIGINT, percent DOUBLE,
        PRIMARY KEY (root_id, suffix)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS agg_mime (
        root_id VARCHAR(32) NOT NULL, root TEXT NOT NULL,
        mime VARCHAR(190) NOT NULL, files BIGINT, bytes BIGINT, percent DOUBLE,
        PRIMARY KEY (root_id, mime)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS agg_dir (
        root_id VARCHAR(32) NOT NULL, root TEXT NOT NULL,
        dir TEXT NOT NULL, dir_hash CHAR(64) NOT NULL,
        files BIGINT, bytes BIGINT, percent DOUBLE,
        PRIMARY KEY (root_id, dir_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS agg_meta (
        root_id VARCHAR(32) PRIMARY KEY, root TEXT NOT NULL,
        total_files BIGINT, total_bytes BIGINT, unreadable BIGINT,
        depth INT, built_at VARCHAR(64)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS dropped (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        root_id VARCHAR(32) NOT NULL,
        root TEXT NOT NULL,
        rel_path TEXT NOT NULL,
        rel_hash CHAR(64) NOT NULL,
        dropped_at VARCHAR(40) NOT NULL,
        document JSON NOT NULL,
        KEY idx_dropped_at (dropped_at),
        KEY idx_dropped_root (root_id, rel_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS members (
        root_id VARCHAR(32) NOT NULL,
        archive_hash CHAR(64) NOT NULL,
        archive_rel_path TEXT NOT NULL,
        idx INT NOT NULL,
        path TEXT,
        path_hash CHAR(64),
        size BIGINT,
        csize BIGINT,
        role VARCHAR(32),
        kind VARCHAR(32),
        document JSON NOT NULL,
        PRIMARY KEY (root_id, archive_hash, idx),
        KEY idx_members_role (role),
        KEY idx_members_path_hash (path_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS samples (
        sample_id VARCHAR(64) PRIMARY KEY,
        document JSON NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS member_sets (
        members_id VARCHAR(64) PRIMARY KEY,
        document JSON NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS set_members (
        members_id VARCHAR(64) NOT NULL,
        idx INT NOT NULL,
        path TEXT,
        path_hash CHAR(64),
        size BIGINT,
        csize BIGINT,
        role VARCHAR(32),
        kind VARCHAR(32),
        document JSON NOT NULL,
        PRIMARY KEY (members_id, idx),
        KEY idx_set_members_role (role),
        KEY idx_set_members_path_hash (path_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
]

_UPSERT_SQL = """
INSERT INTO files (root_id, root, rel_path, rel_hash, name, size, mtime_ns, kind,
                    suffix, mime, sha256, sha256_partial, document)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON DUPLICATE KEY UPDATE
    root=VALUES(root), rel_path=VALUES(rel_path), name=VALUES(name),
    size=VALUES(size), mtime_ns=VALUES(mtime_ns), kind=VALUES(kind),
    suffix=VALUES(suffix), mime=VALUES(mime), sha256=VALUES(sha256),
    sha256_partial=VALUES(sha256_partial), document=VALUES(document)
"""


def _rel_hash(rel_path: str) -> str:
    return hashlib.sha256(rel_path.encode("utf-8")).hexdigest()


_INT64 = 2 ** 63


def _json_safe(value: Any) -> Any:
    """`value` with every int outside int64 as a string: MySQL's JSON type
    would store it as a double and lose digits."""
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, int) and not isinstance(value, bool) and not -_INT64 <= value < _INT64:
        return str(value)
    return value


def connect(dsn: str, **extra: Any):
    """Accept either a pymysql-style kwargs DSN ("host=...;user=...;...")
    or a mysql://user:pass@host:port/db URL. `extra` goes to pymysql.connect."""
    import pymysql
    if "://" in dsn:
        from urllib.parse import urlparse, unquote
        u = urlparse(dsn)
        return pymysql.connect(
            host=u.hostname or "localhost", port=u.port or 3306,
            user=unquote(u.username) if u.username else None,
            password=unquote(u.password) if u.password else None,
            database=(u.path or "").lstrip("/") or None,
            charset="utf8mb4", autocommit=False, **extra,
        )
    kwargs: dict[str, Any] = {}
    for part in dsn.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        kwargs[key.strip().lower()] = value.strip()
    if "db" in kwargs and "database" not in kwargs:
        kwargs["database"] = kwargs.pop("db")
    if "port" in kwargs:
        kwargs["port"] = int(kwargs["port"])
    kwargs.setdefault("charset", "utf8mb4")
    kwargs.update(extra)
    return pymysql.connect(autocommit=False, **kwargs)


def ping(dsn: str, timeout: float = 5.0) -> dict[str, Any]:
    """Read-only connection check for `filecat config test`."""
    conn = connect(dsn, connect_timeout=max(1, int(timeout)))
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION(), DATABASE(), CURRENT_USER()")
            version, database, user = cur.fetchone()
            info: dict[str, Any] = {"server": f"MySQL {version}", "database": database, "user": user}
            if not database:
                info["warning"] = "no database selected; add /<db> to the DSN"
                return info
            cur.execute("SELECT table_name, table_rows FROM information_schema.tables "
                        "WHERE table_schema = DATABASE() AND table_name IN ('files', 'members')")
            tables = {name.lower(): rows for name, rows in cur.fetchall()}
            info["tables"] = sorted(tables)
            if "files" in tables:
                info["files_estimate"] = tables["files"]
            return info
    finally:
        conn.close()


class MysqlBackend(Backend):
    name = "mysql"
    stores_samples = True
    batches_samples = True
    stores_member_sets = True

    def __init__(self, dsn: str) -> None:
        import pymysql  # lazy: only needed when this backend is used
        self._pymysql = pymysql
        self.dsn = dsn
        self.conn = connect(dsn)
        with self.conn.cursor() as cur:
            for stmt in _SCHEMA:
                cur.execute(stmt)
        self.conn.commit()
        self._buffer: list[Document] = []
        self._last_flush = time.monotonic()

    def _row(self, doc: Document) -> tuple:
        sha_partial = doc.get("sha256_partial")
        if sha_partial is not None and not isinstance(sha_partial, str):
            sha_partial = json.dumps(sha_partial, ensure_ascii=False)
        rel_path = doc["rel_path"]
        return (
            doc["root_id"], doc["root"], rel_path, _rel_hash(rel_path), doc.get("name"),
            doc.get("size"), doc.get("mtime_ns"), doc.get("kind"),
            doc.get("suffix"), doc.get("mime"), doc.get("sha256"), sha_partial,
            json.dumps(doc, ensure_ascii=False),
        )

    def put(self, document: Document) -> None:
        self._buffer.append(document)
        if (len(self._buffer) >= BATCH_SIZE
                or (time.monotonic() - self._last_flush) >= BATCH_SECONDS):
            self.flush()

    def flush(self) -> None:
        self.flush_samples()    # a record never lands before the sample it names
        if not self._buffer:
            return
        rows = [self._row(d) for d in self._buffer]
        with self.conn.cursor() as cur:
            cur.executemany(_UPSERT_SQL, rows)
        self.conn.commit()
        self._buffer.clear()
        self._last_flush = time.monotonic()

    def get(self, root: str, rel_path: str) -> Document | None:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("SELECT document FROM files WHERE root_id=%s AND rel_hash=%s",
                        (root_id(root), _rel_hash(rel_path)))
            row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        self.flush()
        clauses, params = [], []
        if kind is not None:
            clauses.append("kind = %s")
            params.append(kind)
        if root is not None:
            clauses.append("root_id = %s")
            params.append(root_id(root))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute(f"SELECT document FROM files{where}", params)
            for (doc_json,) in cur:
                yield json.loads(doc_json)
        finally:
            cur.close()

    def query(self, q: dict[str, Any]) -> dict[str, Any]:
        from ..browse import MYSQL, sql_order, sql_where
        self.flush()
        rid = root_id(q["root"]) if q.get("root") is not None else None
        where, params = sql_where(q, MYSQL, rid)
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files{where}", params)
            total, nbytes = cur.fetchone()
            cur.execute(
                f"SELECT document FROM files{where} ORDER BY {sql_order(q, MYSQL)} LIMIT %s OFFSET %s",
                [*params, q["limit"], q["offset"]])
            rows = [json.loads(r[0]) for r in cur.fetchall()]
        return {"total": int(total), "bytes": int(nbytes), "rows": rows}

    def subtree(self, root: str, parent: str) -> list[dict[str, Any]]:
        from ..browse import MYSQL, sql_subtree
        self.flush()
        sql, params = sql_subtree(parent, MYSQL, root_id(root))
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        return sorted(({"name": n, "files": int(f), "bytes": int(b)} for n, f, b in rows),
                      key=lambda r: (-r["bytes"], r["name"]))

    def sizes(self, root: str, prefix: str = "") -> Iterator[tuple[str, int, str, str]]:
        from ..browse import MYSQL, sql_sizes
        self.flush()
        sql, params = sql_sizes(prefix, MYSQL, root_id(root))
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute(sql, params)
            for rel, size, suffix, mime in cur:
                yield rel, int(size), suffix, mime
        finally:
            cur.close()

    def delete(self, root: str, rel_path: str) -> None:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM files WHERE root_id=%s AND rel_hash=%s",
                        (root_id(root), _rel_hash(rel_path)))
        self.conn.commit()
        self.delete_members(root, rel_path)

    # --- archive members -------------------------------------------
    def put_members(self, root: str, rel_path: str, members: list) -> None:
        self.flush()
        rid = root_id(root)
        ahash = _rel_hash(rel_path)
        rows = []
        for i, m in enumerate(members):
            full = {**m, "index": m.get("index", i), "root_id": rid, "root": root,
                     "archive_rel_path": rel_path}
            path = full.get("path")
            rows.append((
                rid, ahash, rel_path, full["index"], path,
                _rel_hash(path) if path else None, full.get("size"), full.get("csize"),
                full.get("role"), full.get("kind"), json.dumps(_json_safe(full), ensure_ascii=False),
            ))
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM members WHERE root_id=%s AND archive_hash=%s", (rid, ahash))
            if rows:
                cur.executemany(
                    "INSERT INTO members (root_id, archive_hash, archive_rel_path, idx, path, "
                    "path_hash, size, csize, role, kind, document) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", rows)
        self.conn.commit()

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        self.flush()
        rid = root_id(root)
        ahash = _rel_hash(rel_path)
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute(
                "SELECT document FROM members WHERE root_id=%s AND archive_hash=%s ORDER BY idx",
                (rid, ahash))
            for (doc_json,) in cur:
                yield json.loads(doc_json)
        finally:
            cur.close()

    def iter_all_members(self) -> Iterator[Document]:
        self.flush()
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute("SELECT document FROM members ORDER BY root_id, archive_hash, idx")
            for (doc_json,) in cur:
                yield json.loads(doc_json)
        finally:
            cur.close()

    def delete_members(self, root: str, rel_path: str) -> None:
        rid = root_id(root)
        ahash = _rel_hash(rel_path)
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM members WHERE root_id=%s AND archive_hash=%s", (rid, ahash))
        self.conn.commit()

    def roots(self) -> list[str]:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("SELECT DISTINCT root FROM files ORDER BY root")
            return [r[0] for r in cur.fetchall()]

    # --- aggregates --------------------------------------------------
    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        self.flush()
        where = " WHERE root = %s" if root is not None else ""
        params = (root,) if root is not None else ()
        roots_out: dict[str, Any] = {}
        with self.conn.cursor() as cur:
            cur.execute("SELECT root_id, root, total_files, total_bytes, unreadable, depth, built_at "
                        f"FROM agg_meta{where}", params)
            metas = cur.fetchall()
            for rid, rname, total_files, total_bytes, unreadable, depth, built_at in metas:
                cur.execute(
                    "SELECT suffix, description, files, bytes, percent FROM agg_suffix "
                    "WHERE root_id=%s ORDER BY bytes DESC, suffix ASC", (rid,))
                suffix = [{"suffix": r[0], "description": r[1], "files": int(r[2]), "bytes": int(r[3]), "percent": r[4]}
                          for r in cur.fetchall()]
                cur.execute(
                    "SELECT mime, files, bytes, percent FROM agg_mime "
                    "WHERE root_id=%s ORDER BY bytes DESC, mime ASC", (rid,))
                mime = [{"mime": r[0], "files": int(r[1]), "bytes": int(r[2]), "percent": r[3]} for r in cur.fetchall()]
                cur.execute(
                    "SELECT dir, files, bytes, percent FROM agg_dir "
                    "WHERE root_id=%s ORDER BY bytes DESC, dir ASC", (rid,))
                dirs = [{"dir": r[0], "files": int(r[1]), "bytes": int(r[2]), "percent": r[3]} for r in cur.fetchall()]
                roots_out[rname] = {
                    "suffix": suffix, "mime": mime, "dir": dirs,
                    "total_files": int(total_files), "total_bytes": int(total_bytes),
                    "unreadable": int(unreadable), "depth": depth, "built_at": built_at,
                }
        return roots_out

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        where = " WHERE root_id = %s" if root is not None else ""
        params = (root_id(root),) if root is not None else ()
        with self.conn.cursor() as cur:
            for table in ("agg_suffix", "agg_mime", "agg_dir", "agg_meta"):
                cur.execute(f"DELETE FROM {table}{where}", params)
            for rname, e in entries.items():
                rid = root_id(rname)
                if e["suffix"]:
                    cur.executemany(
                        "INSERT INTO agg_suffix (root_id, root, suffix, description, files, bytes, percent) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        [(rid, rname, r["suffix"], r.get("description"), r["files"], r["bytes"], r["percent"])
                         for r in e["suffix"]])
                if e["mime"]:
                    cur.executemany(
                        "INSERT INTO agg_mime (root_id, root, mime, files, bytes, percent) VALUES (%s,%s,%s,%s,%s,%s)",
                        [(rid, rname, r["mime"], r["files"], r["bytes"], r["percent"]) for r in e["mime"]])
                if e["dir"]:
                    cur.executemany(
                        "INSERT INTO agg_dir (root_id, root, dir, dir_hash, files, bytes, percent) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                        [(rid, rname, r["dir"], _rel_hash(r["dir"]), r["files"], r["bytes"], r["percent"]) for r in e["dir"]])
                cur.execute(
                    "INSERT INTO agg_meta (root_id, root, total_files, total_bytes, unreadable, depth, built_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (rid, rname, e["total_files"], e["total_bytes"], e["unreadable"], depth, built_at))
        self.conn.commit()

    # --- dropped records ------------------------------------------------
    def put_dropped(self, document: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO dropped (root_id, root, rel_path, rel_hash, dropped_at, document) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (document["root_id"], document["root"], document["rel_path"],
                 _rel_hash(document["rel_path"]), document["dropped_at"],
                 json.dumps(document, ensure_ascii=False)),
            )
        self.conn.commit()

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        where, params = (" WHERE root_id=%s", (root_id(root),)) if root is not None else ("", ())
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT document FROM dropped{where} ORDER BY dropped_at DESC, id DESC", params)
            rows = cur.fetchall()
        self.conn.commit()
        for (doc,) in rows:
            yield json.loads(doc) if isinstance(doc, (str, bytes)) else doc

    def purge_dropped(self, before: str) -> int:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM dropped WHERE dropped_at < %s", (before,))
            n = cur.rowcount
        self.conn.commit()
        return n

    # --- root index ----------------------------------------------------
    def put_root_info(self, info: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO roots (root_id, root, document) VALUES (%s, %s, %s) "
                "ON DUPLICATE KEY UPDATE root=VALUES(root), document=VALUES(document)",
                (info["root_id"], info.get("root") or "", json.dumps(info, ensure_ascii=False)),
            )
        self.conn.commit()

    def list_root_info(self) -> Iterator[Document]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT document FROM roots")
            rows = cur.fetchall()
        self.conn.commit()
        docs = [json.loads(d) if isinstance(d, (str, bytes)) else d for (d,) in rows]
        yield from sorted(docs, key=lambda d: d.get("root") or "")

    def get_root_info(self, root: str) -> Document | None:
        with self.conn.cursor() as cur:
            cur.execute("SELECT document FROM roots WHERE root_id=%s", (root_id(root),))
            row = cur.fetchone()
        self.conn.commit()
        if row is None:
            return None
        doc = row[0]
        return json.loads(doc) if isinstance(doc, (str, bytes)) else doc

    # --- stored treemaps ---------------------------------------------
    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        with self.conn.cursor() as cur:
            if data is None:
                cur.execute("UPDATE treemaps SET meta=%s WHERE id=%s",
                            (json.dumps(meta, ensure_ascii=False), meta["id"]))
            else:
                cur.execute(
                    "INSERT INTO treemaps (id, root_id, meta, data) VALUES (%s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE root_id=VALUES(root_id), meta=VALUES(meta), data=VALUES(data)",
                    (meta["id"], meta["root_id"], json.dumps(meta, ensure_ascii=False),
                     json.dumps(data, ensure_ascii=False)))
        self.conn.commit()

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        with self.conn.cursor() as cur:
            if root is None:
                cur.execute("SELECT meta FROM treemaps")
            else:
                cur.execute("SELECT meta FROM treemaps WHERE root_id=%s", (root_id(root),))
            rows = cur.fetchall()
        self.conn.commit()
        return [json.loads(m) if isinstance(m, (str, bytes)) else m for (m,) in rows]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        with self.conn.cursor() as cur:
            cur.execute("SELECT meta, data FROM treemaps WHERE id=%s", (treemap_id,))
            row = cur.fetchone()
        self.conn.commit()
        if row is None:
            return None
        meta = json.loads(row[0]) if isinstance(row[0], (str, bytes)) else row[0]
        return meta, json.loads(row[1])

    def delete_treemap(self, treemap_id: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM treemaps WHERE id=%s", (treemap_id,))
        self.conn.commit()

    # --- installed programs -------------------------------------------
    def put_program(self, record: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO programs (program_id, document) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE document=VALUES(document)",
                (record["program_id"], json.dumps(record, ensure_ascii=False)),
            )
        self.conn.commit()

    def list_programs(self) -> Iterator[Document]:
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute("SELECT document FROM programs")
            for (doc_json,) in cur:
                yield json.loads(doc_json)
        finally:
            cur.close()

    def clear_programs(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM programs")
        self.conn.commit()

    # --- samples ---------------------------------------------------
    def add_samples(self, samples: list[Document]) -> None:
        with self.conn.cursor() as cur:
            cur.executemany(
                "INSERT IGNORE INTO samples (sample_id, document) VALUES (%s, %s)",
                [(x["sample_id"], json.dumps(_json_safe(x), ensure_ascii=False)) for x in samples])
        self.conn.commit()

    def _reader(self) -> Any:
        """A second, autocommit connection for sample lookups: list() reads
        with an unbuffered cursor, and no other statement may run on its
        connection until that listing is finished."""
        if getattr(self, "_side_conn", None) is None:
            self._side_conn = connect(self.dsn)
            self._side_conn.autocommit(True)
        return self._side_conn

    def get_samples(self, ids: Iterable[str]) -> dict[str, Document]:
        ids = list(ids)
        out: dict[str, Document] = {}
        if not ids:
            return out
        with self._reader().cursor() as cur:
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                cur.execute(f"SELECT document FROM samples WHERE sample_id IN ({','.join(['%s'] * len(chunk))})",
                            chunk)
                for (doc_json,) in cur.fetchall():
                    doc = json.loads(doc_json)
                    out[doc["sample_id"]] = doc
        return out

    def set_sample_llm(self, sample_id: str, llm: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute("UPDATE samples SET document = JSON_SET(document, '$.llm', CAST(%s AS JSON)) "
                        "WHERE sample_id = %s", (json.dumps(_json_safe(llm), ensure_ascii=False), sample_id))
        self.conn.commit()

    def iter_samples(self) -> Iterator[Document]:
        self.flush_samples()
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute("SELECT document FROM samples")
            for (doc_json,) in cur:
                yield json.loads(doc_json)
        finally:
            cur.close()

    def page_records(self, after: Any, limit: int) -> tuple[list[Document], Any]:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("SELECT id, document FROM files WHERE id > %s ORDER BY id LIMIT %s",
                        (after or 0, limit))
            rows = cur.fetchall()
        self.conn.commit()
        return [json.loads(d) for _, d in rows], (rows[-1][0] if rows else after)

    def prune_samples(self) -> int:
        self.flush()
        with self.conn.cursor() as cur:
            n = cur.execute("DELETE FROM samples WHERE NOT EXISTS "
                            "(SELECT 1 FROM files f WHERE f.document->>'$.sample_id' = samples.sample_id)")
        self.conn.commit()
        return n

    # --- member sets -------------------------------------------------
    def put_member_set(self, header: Document, rows: list[Document]) -> bool:
        mid = header["members_id"]
        with self.conn.cursor() as cur:
            cur.execute("SELECT document->>'$.digest' FROM member_sets WHERE members_id=%s", (mid,))
            old = cur.fetchone()
            if old and old[0] == header["digest"]:
                self.conn.commit()
                return False
            cur.execute("DELETE FROM member_sets WHERE members_id=%s", (mid,))
            cur.execute("DELETE FROM set_members WHERE members_id=%s", (mid,))
            if rows:
                cur.executemany(
                    "INSERT INTO set_members (members_id, idx, path, path_hash, size, csize, role, kind, "
                    "document) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    [(mid, r["index"], r.get("path"), _rel_hash(r["path"]) if r.get("path") else None,
                      r.get("size"), r.get("csize"), r.get("role"), r.get("kind"),
                      json.dumps(_json_safe({**r, "members_id": mid}), ensure_ascii=False)) for r in rows])
            cur.execute("INSERT INTO member_sets (members_id, document) VALUES (%s, %s)",
                        (mid, json.dumps(header, ensure_ascii=False)))
        self.conn.commit()
        return True

    def list_member_set(self, members_id: str) -> Iterator[Document]:
        self.flush()
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute("SELECT document FROM set_members WHERE members_id=%s ORDER BY idx", (members_id,))
            for (doc_json,) in cur:
                yield json.loads(doc_json)
        finally:
            cur.close()

    def iter_member_sets(self) -> Iterator[Document]:
        self.flush()
        cur = self.conn.cursor(self._pymysql.cursors.SSCursor)
        try:
            cur.execute("SELECT document FROM member_sets")
            for (doc_json,) in cur:
                yield json.loads(doc_json)
        finally:
            cur.close()

    def prune_member_sets(self) -> int:
        self.flush()
        with self.conn.cursor() as cur:
            n = cur.execute("DELETE FROM member_sets WHERE NOT EXISTS (SELECT 1 FROM files f "
                            "WHERE f.document->>'$.members_id' = member_sets.members_id)")
            cur.execute("DELETE FROM set_members WHERE NOT EXISTS "
                        "(SELECT 1 FROM member_sets m WHERE m.members_id = set_members.members_id)")
        self.conn.commit()
        return n

    # --- lifecycle -------------------------------------------------
    def close(self) -> None:
        self.flush()
        self.conn.close()
        if getattr(self, "_side_conn", None) is not None:
            self._side_conn.close()
