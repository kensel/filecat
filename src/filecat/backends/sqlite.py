"""SQLite backend: stdlib sqlite3, the default backend.

Table `files` holds one row per record with indexed columns mirroring
record.INDEXED_FIELDS (root_id, rel_path, sha256, kind, suffix, mime) plus
the full document as JSON text. UNIQUE(root_id, rel_path); writes are
upserts via INSERT ... ON CONFLICT DO UPDATE.

Because a scan can produce millions of rows (a 218 MB JSONL import is the
first real stress test), `put()` does not hit the database per call: rows
are buffered and written with `executemany()` every BATCH_SIZE puts or
every BATCH_SECONDS, whichever comes first, and again at flush()/close().
WAL mode is enabled so readers (e.g. a concurrent `summary`) are not
blocked by an in-progress scan's writes.

`list()` streams via `cursor.fetchmany()` in a generator -- it never calls
fetchall() on the full table.

Aggregates (`agg_suffix`, `agg_mime`, `agg_dir`, `agg_meta`) are rebuilt
with SQL GROUP BY. The directory cut uses a registered SQL function
(`dirkey`) that calls the exact same `filecat.aggregate.dir_key()` the
other backends and the in-Python fallback use, so the grouping rule is
defined in one place. agg_meta records each root's depth and built_at;
Backend.summary() reads a root from the stored tables when they were built
at the requested `--depth` and computes the others with
`filecat.aggregate.build_aggregates()` over that root's `list()`.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..record import root_id
from .base import Backend, Document, chunks, dropped_now

BATCH_SIZE = 500
BATCH_SECONDS = 2.0
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    root_id TEXT NOT NULL,
    root TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    name TEXT,
    size INTEGER,
    mtime_ns INTEGER,
    kind TEXT,
    suffix TEXT,
    mime TEXT,
    sha256 TEXT,
    sha256_partial TEXT,
    document TEXT NOT NULL,
    UNIQUE (root_id, rel_path)
);
CREATE INDEX IF NOT EXISTS idx_files_root_id ON files(root_id);
CREATE INDEX IF NOT EXISTS idx_files_rel_path ON files(rel_path);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);
CREATE INDEX IF NOT EXISTS idx_files_kind ON files(kind);
CREATE INDEX IF NOT EXISTS idx_files_suffix ON files(suffix);
CREATE INDEX IF NOT EXISTS idx_files_mime ON files(mime);

CREATE TABLE IF NOT EXISTS programs (
    program_id TEXT PRIMARY KEY,
    document TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roots (
    root_id TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    document TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS treemaps (
    id TEXT PRIMARY KEY,
    root_id TEXT NOT NULL,
    meta TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_treemaps_root ON treemaps(root_id);

CREATE TABLE IF NOT EXISTS dropped (
    id INTEGER PRIMARY KEY,
    root_id TEXT NOT NULL,
    root TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    dropped_at TEXT NOT NULL,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dropped_at ON dropped(dropped_at);
CREATE INDEX IF NOT EXISTS idx_dropped_root ON dropped(root_id, rel_path);

CREATE TABLE IF NOT EXISTS redactions (
    id TEXT PRIMARY KEY,
    root_id TEXT NOT NULL,
    path_hash TEXT NOT NULL,
    document TEXT NOT NULL,
    UNIQUE (root_id, path_hash)
);

CREATE TABLE IF NOT EXISTS storage_topology (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS storage_topology_history (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_storage_history_host ON storage_topology_history(host, scanned_at);
CREATE TABLE IF NOT EXISTS server_jobs (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS server_state (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agg_suffix (
    root_id TEXT NOT NULL, root TEXT NOT NULL,
    suffix TEXT, description TEXT, files INTEGER, bytes INTEGER, percent REAL,
    PRIMARY KEY (root_id, suffix)
);
CREATE TABLE IF NOT EXISTS agg_mime (
    root_id TEXT NOT NULL, root TEXT NOT NULL,
    mime TEXT, files INTEGER, bytes INTEGER, percent REAL,
    PRIMARY KEY (root_id, mime)
);
CREATE TABLE IF NOT EXISTS agg_dir (
    root_id TEXT NOT NULL, root TEXT NOT NULL,
    dir TEXT, files INTEGER, bytes INTEGER, percent REAL,
    PRIMARY KEY (root_id, dir)
);
CREATE TABLE IF NOT EXISTS agg_meta (
    root_id TEXT PRIMARY KEY, root TEXT NOT NULL,
    total_files INTEGER, total_bytes INTEGER, unreadable INTEGER,
    depth INTEGER, built_at TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS members (
    root_id TEXT NOT NULL,
    archive_rel_path TEXT NOT NULL,
    idx INTEGER NOT NULL,
    path TEXT,
    size INTEGER,
    csize INTEGER,
    role TEXT,
    kind TEXT,
    document TEXT NOT NULL,
    PRIMARY KEY (root_id, archive_rel_path, idx)
);
CREATE INDEX IF NOT EXISTS idx_members_role ON members(role);
CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    document TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_members_path ON members(path);

CREATE TABLE IF NOT EXISTS member_sets (
    members_id TEXT PRIMARY KEY,
    document TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS set_members (
    members_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    path TEXT,
    size INTEGER,
    csize INTEGER,
    role TEXT,
    kind TEXT,
    document TEXT NOT NULL,
    PRIMARY KEY (members_id, idx)
);
CREATE INDEX IF NOT EXISTS idx_set_members_role ON set_members(role);
CREATE INDEX IF NOT EXISTS idx_set_members_path ON set_members(path);
"""

_UPSERT_SQL = """
INSERT INTO files (root_id, root, rel_path, name, size, mtime_ns, kind,
                    suffix, mime, sha256, sha256_partial, document)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (root_id, rel_path) DO UPDATE SET
    root=excluded.root, name=excluded.name, size=excluded.size,
    mtime_ns=excluded.mtime_ns, kind=excluded.kind, suffix=excluded.suffix,
    mime=excluded.mime, sha256=excluded.sha256,
    sha256_partial=excluded.sha256_partial, document=excluded.document
"""


def _dirkey_sql(rel_path: str | None, depth: int) -> str:
    from ..aggregate import dir_key
    return dir_key(rel_path or "", depth)


class SqliteBackend(Backend):
    name = "sqlite"
    stores_samples = True
    batches_samples = True
    stores_member_sets = True

    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=30.0)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        # a deleted record's text is overwritten, not left in a free page: a purged
        # [REDACTED] name must not survive in the file (docs/rollups.md section 3.5)
        self.conn.execute("PRAGMA secure_delete=ON")
        self.conn.create_function("dirkey", 2, _dirkey_sql, deterministic=True)
        self.conn.executescript(_SCHEMA)
        self.conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()
        # Pending upserts keyed by (root_id, rel_path); a later put of the same
        # key replaces the earlier one. get() reads from here first so a
        # get/put loop does not commit once per record.
        self._buffer: dict[tuple[str, str], tuple] = {}
        self._last_flush = time.monotonic()

    # --- documents -------------------------------------------------
    def _row_for(self, document: Document) -> tuple:
        sha_partial = document.get("sha256_partial")
        if sha_partial is not None and not isinstance(sha_partial, str):
            sha_partial = json.dumps(sha_partial, ensure_ascii=False)
        return (
            document["root_id"], document["root"], document["rel_path"],
            document.get("name"), document.get("size"), document.get("mtime_ns"),
            document.get("kind"), document.get("suffix"), document.get("mime"),
            document.get("sha256"), sha_partial,
            json.dumps(document, ensure_ascii=False),
        )

    def put(self, document: Document) -> None:
        row = self._row_for(document)
        self._buffer[(row[0], row[2])] = row
        if (len(self._buffer) >= BATCH_SIZE
                or (time.monotonic() - self._last_flush) >= BATCH_SECONDS):
            self._flush_buffer()

    def _flush_buffer(self) -> None:
        self.flush_samples()    # a record never lands before the sample it names
        if not self._buffer:
            return
        self.conn.executemany(_UPSERT_SQL, list(self._buffer.values()))
        self.conn.commit()
        self._buffer.clear()
        self._last_flush = time.monotonic()

    def get(self, root: str, rel_path: str) -> Document | None:
        key = (root_id(root), rel_path)
        pending = self._buffer.get(key)
        if pending is not None:
            return json.loads(pending[-1])
        cur = self.conn.execute(
            "SELECT document FROM files WHERE root_id=? AND rel_path=?", key,
        )
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def get_stats(self, root: str, rel_paths: list[str]) -> dict[str, Document]:
        rid, out = root_id(root), {}
        for part in chunks(rel_paths):
            marks = ", ".join("?" * len(part))
            cur = self.conn.execute(
                f"SELECT rel_path, document FROM files WHERE root_id=? AND rel_path IN ({marks})",
                (rid, *part))
            out.update((rel, json.loads(doc)) for rel, doc in cur.fetchall())
        for p in rel_paths:     # buffered upserts, keyed like the table
            pending = self._buffer.get((rid, p))
            if pending is not None:
                out[p] = json.loads(pending[-1])
        return out

    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        self._flush_buffer()
        clauses, params = [], []
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        if root is not None:
            clauses.append("root_id = ?")
            params.append(root_id(root))
        query = "SELECT document FROM files"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        cur = self.conn.execute(query, params)
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def query(self, q: dict[str, Any]) -> dict[str, Any]:
        from ..browse import SQLITE, sql_order, sql_where
        self._flush_buffer()
        rid = root_id(q["root"]) if q.get("root") is not None else None
        where, params = sql_where(q, SQLITE, rid)
        total, nbytes = self.conn.execute(
            f"SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files{where}", params).fetchone()
        rows = self.conn.execute(
            f"SELECT document FROM files{where} ORDER BY {sql_order(q)} LIMIT ? OFFSET ?",
            [*params, q["limit"], q["offset"]]).fetchall()
        return {"total": total, "bytes": nbytes, "rows": [json.loads(r[0]) for r in rows]}

    def subtree(self, root: str, parent: str) -> list[dict[str, Any]]:
        from ..browse import SQLITE, sql_subtree
        self._flush_buffer()
        sql, params = sql_subtree(parent, SQLITE, root_id(root))
        rows = self.conn.execute(sql, params).fetchall()
        return sorted(({"name": n, "files": f, "bytes": b} for n, f, b in rows),
                      key=lambda r: (-r["bytes"], r["name"]))

    def sizes(self, root: str, prefix: str = "") -> Iterator[tuple[str, int, str, str]]:
        from ..browse import SQLITE, sql_sizes
        self._flush_buffer()
        sql, params = sql_sizes(prefix, SQLITE, root_id(root))
        cur = self.conn.execute(sql, params)
        while True:
            rows = cur.fetchmany(5000)
            if not rows:
                break
            yield from rows

    def delete(self, root: str, rel_path: str) -> None:
        self._flush_buffer()
        self.conn.execute(
            "DELETE FROM files WHERE root_id=? AND rel_path=?",
            (root_id(root), rel_path),
        )
        self.conn.commit()
        self.delete_members(root, rel_path)

    def delete_many(self, root: str, rel_paths: Iterable[str]) -> int:
        """One transaction for the whole batch."""
        self._flush_buffer()
        rid, n = root_id(root), 0
        cur = self.conn.cursor()
        for part in chunks(list(rel_paths)):
            marks = ", ".join("?" * len(part))
            cur.execute(f"DELETE FROM files WHERE root_id=? AND rel_path IN ({marks})", (rid, *part))
            n += cur.rowcount
            cur.execute(f"DELETE FROM members WHERE root_id=? AND archive_rel_path IN ({marks})",
                        (rid, *part))
        self.conn.commit()
        return n

    # --- archive members -------------------------------------------
    def put_members(self, root: str, rel_path: str, members: list) -> None:
        self._flush_buffer()
        rid = root_id(root)
        rows = []
        for i, m in enumerate(members):
            full = {**m, "index": m.get("index", i), "root_id": rid, "root": root,
                     "archive_rel_path": rel_path}
            rows.append((
                rid, rel_path, full["index"], full.get("path"), full.get("size"),
                full.get("csize"), full.get("role"), full.get("kind"),
                json.dumps(full, ensure_ascii=False),
            ))
        cur = self.conn.cursor()
        cur.execute("DELETE FROM members WHERE root_id=? AND archive_rel_path=?", (rid, rel_path))
        if rows:
            cur.executemany(
                "INSERT INTO members (root_id, archive_rel_path, idx, path, size, csize, "
                "role, kind, document) VALUES (?,?,?,?,?,?,?,?,?)", rows)
        self.conn.commit()

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        self._flush_buffer()
        rid = root_id(root)
        cur = self.conn.execute(
            "SELECT document FROM members WHERE root_id=? AND archive_rel_path=? ORDER BY idx",
            (rid, rel_path),
        )
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def iter_all_members(self) -> Iterator[Document]:
        self._flush_buffer()
        cur = self.conn.execute(
            "SELECT document FROM members ORDER BY root_id, archive_rel_path, idx")
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def delete_members(self, root: str, rel_path: str) -> None:
        rid = root_id(root)
        self.conn.execute(
            "DELETE FROM members WHERE root_id=? AND archive_rel_path=?", (rid, rel_path))
        self.conn.commit()

    def roots(self) -> list[str]:
        self._flush_buffer()
        cur = self.conn.execute("SELECT DISTINCT root FROM files ORDER BY root")
        return [r[0] for r in cur.fetchall()]

    # --- aggregates --------------------------------------------------
    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        self._flush_buffer()
        where = " WHERE root = ?" if root is not None else ""
        params = (root,) if root is not None else ()
        roots_out: dict[str, Any] = {}
        for rid, rname, total_files, total_bytes, unreadable, depth, built_at in self.conn.execute(
                "SELECT root_id, root, total_files, total_bytes, unreadable, depth, built_at "
                f"FROM agg_meta{where}", params).fetchall():
            suffix = [
                {"suffix": r[0], "description": r[1], "files": r[2], "bytes": r[3], "percent": r[4]}
                for r in self.conn.execute(
                    "SELECT suffix, description, files, bytes, percent FROM agg_suffix "
                    "WHERE root_id=? ORDER BY bytes DESC, suffix ASC", (rid,))
            ]
            mime = [
                {"mime": r[0], "files": r[1], "bytes": r[2], "percent": r[3]}
                for r in self.conn.execute(
                    "SELECT mime, files, bytes, percent FROM agg_mime "
                    "WHERE root_id=? ORDER BY bytes DESC, mime ASC", (rid,))
            ]
            dirs = [
                {"dir": r[0], "files": r[1], "bytes": r[2], "percent": r[3]}
                for r in self.conn.execute(
                    "SELECT dir, files, bytes, percent FROM agg_dir "
                    "WHERE root_id=? ORDER BY bytes DESC, dir ASC", (rid,))
            ]
            roots_out[rname] = {
                "suffix": suffix, "mime": mime, "dir": dirs,
                "total_files": total_files, "total_bytes": total_bytes, "unreadable": unreadable,
                "depth": depth, "built_at": built_at,
            }
        return roots_out

    def _clear_aggregates(self, cur: sqlite3.Cursor, root: str | None) -> None:
        where = " WHERE root_id = ?" if root is not None else ""
        params = (root_id(root),) if root is not None else ()
        for table in ("agg_suffix", "agg_mime", "agg_dir", "agg_meta"):
            cur.execute(f"DELETE FROM {table}{where}", params)

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        cur = self.conn.cursor()
        self._clear_aggregates(cur, root)
        for rname, e in entries.items():
            rid = root_id(rname)
            cur.executemany(
                "INSERT INTO agg_suffix (root_id, root, suffix, description, files, bytes, percent) "
                "VALUES (?,?,?,?,?,?,?)",
                [(rid, rname, r["suffix"], r.get("description"), r["files"], r["bytes"], r["percent"])
                 for r in e["suffix"]])
            cur.executemany(
                "INSERT INTO agg_mime (root_id, root, mime, files, bytes, percent) VALUES (?,?,?,?,?,?)",
                [(rid, rname, r["mime"], r["files"], r["bytes"], r["percent"]) for r in e["mime"]])
            cur.executemany(
                "INSERT INTO agg_dir (root_id, root, dir, files, bytes, percent) VALUES (?,?,?,?,?,?)",
                [(rid, rname, r["dir"], r["files"], r["bytes"], r["percent"]) for r in e["dir"]])
            cur.execute(
                "INSERT INTO agg_meta (root_id, root, total_files, total_bytes, unreadable, depth, built_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (rid, rname, e["total_files"], e["total_bytes"], e["unreadable"], depth, built_at))
        self.conn.commit()

    def rebuild_aggregates(self, depth: int = 2, root: str | None = None) -> None:
        self._flush_buffer()
        cur = self.conn.cursor()
        self._clear_aggregates(cur, root)

        readable = "NOT (size IS NULL AND json_extract(document, '$.errors') IS NOT NULL)"
        if root is not None:
            roots = cur.execute("SELECT DISTINCT root_id, root FROM files WHERE root_id=? AND kind NOT IN ('dir', 'rollup')",
                                (root_id(root),)).fetchall()
        else:
            roots = cur.execute("SELECT DISTINCT root_id, root FROM files "
                                "WHERE kind NOT IN ('dir', 'rollup')").fetchall()

        for rid, rname in roots:
            total_bytes = cur.execute(
                "SELECT COALESCE(SUM(size), 0) FROM files WHERE root_id=? AND kind NOT IN ('dir', 'rollup')", (rid,)
            ).fetchone()[0]
            total_files = cur.execute(
                "SELECT COUNT(*) FROM files WHERE root_id=? AND kind NOT IN ('dir', 'rollup')", (rid,)
            ).fetchone()[0]
            unreadable = cur.execute(
                "SELECT COUNT(*) FROM files WHERE root_id=? AND kind NOT IN ('dir', 'rollup') "
                "AND size IS NULL AND json_extract(document, '$.errors') IS NOT NULL", (rid,)
            ).fetchone()[0]

            cur.execute(f"""
                INSERT INTO agg_suffix (root_id, root, suffix, description, files, bytes, percent)
                SELECT ?, ?,
                       CASE WHEN suffix IS NULL OR suffix='' THEN '(none)' ELSE suffix END,
                       MAX(json_extract(document, '$.probe.mime_glob_desc')),
                       COUNT(*), COALESCE(SUM(size), 0),
                       CASE WHEN ? > 0 THEN COALESCE(SUM(size), 0) * 100.0 / ? ELSE 0.0 END
                FROM files
                WHERE root_id = ? AND kind NOT IN ('dir', 'rollup') AND {readable}
                GROUP BY CASE WHEN suffix IS NULL OR suffix='' THEN '(none)' ELSE suffix END
            """, (rid, rname, total_bytes, total_bytes, rid))

            cur.execute(f"""
                INSERT INTO agg_mime (root_id, root, mime, files, bytes, percent)
                SELECT ?, ?,
                       COALESCE(NULLIF(mime, ''), kind, 'unknown'),
                       COUNT(*), COALESCE(SUM(size), 0),
                       CASE WHEN ? > 0 THEN COALESCE(SUM(size), 0) * 100.0 / ? ELSE 0.0 END
                FROM files
                WHERE root_id = ? AND kind NOT IN ('dir', 'rollup') AND {readable}
                GROUP BY COALESCE(NULLIF(mime, ''), kind, 'unknown')
            """, (rid, rname, total_bytes, total_bytes, rid))

            cur.execute(f"""
                INSERT INTO agg_dir (root_id, root, dir, files, bytes, percent)
                SELECT ?, ?,
                       dirkey(rel_path, {int(depth)}),
                       COUNT(*), COALESCE(SUM(size), 0),
                       CASE WHEN ? > 0 THEN COALESCE(SUM(size), 0) * 100.0 / ? ELSE 0.0 END
                FROM files
                WHERE root_id = ? AND kind NOT IN ('dir', 'rollup') AND {readable}
                GROUP BY dirkey(rel_path, {int(depth)})
            """, (rid, rname, total_bytes, total_bytes, rid))

            cur.execute(
                "INSERT INTO agg_meta (root_id, root, total_files, total_bytes, unreadable, depth, built_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (rid, rname, total_files, total_bytes, unreadable, depth,
                 datetime.now(timezone.utc).isoformat()),
            )

        self.conn.commit()

    # --- root index ------------------------------------------------
    def put_root_info(self, info: Document) -> None:
        self.conn.execute(
            "INSERT INTO roots(root_id, root, document) VALUES (?, ?, ?) "
            "ON CONFLICT(root_id) DO UPDATE SET root=excluded.root, document=excluded.document",
            (info["root_id"], info["root"], json.dumps(info, ensure_ascii=False)),
        )
        self.conn.commit()

    def list_root_info(self) -> Iterator[Document]:
        for (doc_json,) in self.conn.execute("SELECT document FROM roots ORDER BY root").fetchall():
            yield json.loads(doc_json)

    def get_root_info(self, root: str) -> Document | None:
        row = self.conn.execute("SELECT document FROM roots WHERE root_id=?", (root_id(root),)).fetchone()
        return json.loads(row[0]) if row else None

    def delete_root_info(self, root: str) -> None:
        self.conn.execute("DELETE FROM roots WHERE root_id=?", (root_id(root),))
        self.conn.commit()

    # --- stored treemaps ---------------------------------------------
    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        if data is None:
            self.conn.execute("UPDATE treemaps SET meta=? WHERE id=?",
                              (json.dumps(meta, ensure_ascii=False), meta["id"]))
        else:
            self.conn.execute(
                "INSERT OR REPLACE INTO treemaps(id, root_id, meta, data) VALUES (?, ?, ?, ?)",
                (meta["id"], meta["root_id"], json.dumps(meta, ensure_ascii=False),
                 json.dumps(data, ensure_ascii=False)))
        self.conn.commit()

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        if root is None:
            rows = self.conn.execute("SELECT meta FROM treemaps").fetchall()
        else:
            rows = self.conn.execute("SELECT meta FROM treemaps WHERE root_id=?", (root_id(root),)).fetchall()
        return [json.loads(m) for (m,) in rows]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        row = self.conn.execute("SELECT meta, data FROM treemaps WHERE id=?", (treemap_id,)).fetchone()
        return (json.loads(row[0]), json.loads(row[1])) if row else None

    def delete_treemap(self, treemap_id: str) -> None:
        self.conn.execute("DELETE FROM treemaps WHERE id=?", (treemap_id,))
        self.conn.commit()

    # --- dropped records --------------------------------------------
    _DROPPED_SQL = ("INSERT INTO dropped (root_id, root, rel_path, dropped_at, document) "
                    "VALUES (?,?,?,?,?)")

    def put_dropped(self, document: Document) -> None:
        self.conn.execute(self._DROPPED_SQL, (
            document["root_id"], document["root"], document["rel_path"], document["dropped_at"],
            json.dumps(document, ensure_ascii=False)))
        self.conn.commit()

    def drop_many(self, root: str, rel_paths: Iterable[str], reason: str = "vanished") -> int:
        """One transaction: a vanished mail folder can be thousands of records."""
        self._flush_buffer()
        rid, at, n = root_id(root), dropped_now(), 0
        cur = self.conn.cursor()
        for rel_path in rel_paths:
            row = cur.execute("SELECT document FROM files WHERE root_id=? AND rel_path=?",
                              (rid, rel_path)).fetchone()
            if row is None:
                continue
            doc = {**json.loads(row[0]), "dropped_at": at, "drop_reason": reason}
            cur.execute(self._DROPPED_SQL, (rid, doc["root"], rel_path, at,
                                            json.dumps(doc, ensure_ascii=False)))
            cur.execute("DELETE FROM files WHERE root_id=? AND rel_path=?", (rid, rel_path))
            cur.execute("DELETE FROM members WHERE root_id=? AND archive_rel_path=?", (rid, rel_path))
            n += 1
        self.conn.commit()
        return n

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        where, params = (" WHERE root_id=?", (root_id(root),)) if root is not None else ("", ())
        cur = self.conn.execute(
            f"SELECT document FROM dropped{where} ORDER BY dropped_at DESC, id DESC", params)
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def purge_dropped(self, before: str) -> int:
        n = self.conn.execute("DELETE FROM dropped WHERE dropped_at < ?", (before,)).rowcount
        self.conn.commit()
        return n

    def purge_dropped_paths(self, root: str, rel_paths: Iterable[str]) -> int:
        rid, paths = root_id(root), list(rel_paths)
        gone = [i for i, rel in self.conn.execute(
            "SELECT id, rel_path FROM dropped WHERE root_id=?", (rid,))
            if any(rel == p or rel.startswith(p + "/") for p in paths)]
        for part in chunks(gone):
            self.conn.execute(f"DELETE FROM dropped WHERE id IN ({', '.join('?' * len(part))})", part)
        self.conn.commit()
        return len(gone)

    # --- sticky redactions ---------------------------------------------
    def _redaction_rows(self, root: str | None = None) -> list[Document]:
        return [json.loads(d) for (d,) in self.conn.execute("SELECT document FROM redactions")]

    def _redaction_put(self, entry: Document) -> None:
        self.conn.execute(
            "INSERT INTO redactions(id, root_id, path_hash, document) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET root_id=excluded.root_id, path_hash=excluded.path_hash, "
            "document=excluded.document",
            (entry["id"], entry["root_id"], entry["path_hash"], json.dumps(entry, ensure_ascii=False)))
        self.conn.commit()

    def _redaction_remove(self, entry: Document) -> None:
        self.conn.execute("DELETE FROM redactions WHERE id=?", (entry["id"],))
        self.conn.commit()

    # --- storage topology ------------------------------------------------
    def _topology_rows(self, store: str) -> list[Document]:
        assert store in self.DOC_STORES
        return [json.loads(d) for (d,) in self.conn.execute(f"SELECT document FROM {store}")]

    def _topology_put(self, store: str, doc: Document) -> None:
        assert store in self.DOC_STORES
        self.conn.execute(
            f"INSERT INTO {store}(doc_key, host, scanned_at, document) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(doc_key) DO UPDATE SET host=excluded.host, scanned_at=excluded.scanned_at, "
            "document=excluded.document",
            (doc["key"], doc["host"], doc.get("scanned_at"), json.dumps(doc, ensure_ascii=False)))
        self.conn.commit()

    def _topology_remove(self, store: str, key: str) -> None:
        assert store in self.DOC_STORES
        self.conn.execute(f"DELETE FROM {store} WHERE doc_key=?", (key,))
        self.conn.commit()

    # --- installed programs -------------------------------------------
    def put_program(self, record: Document) -> None:
        self.conn.execute(
            "INSERT INTO programs(program_id, document) VALUES (?, ?) "
            "ON CONFLICT(program_id) DO UPDATE SET document=excluded.document",
            (record["program_id"], json.dumps(record, ensure_ascii=False)),
        )
        self.conn.commit()

    def list_programs(self) -> Iterator[Document]:
        cur = self.conn.execute("SELECT document FROM programs")
        while True:
            rows = cur.fetchmany(500)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def clear_programs(self) -> None:
        self.conn.execute("DELETE FROM programs")
        self.conn.commit()

    # --- samples ---------------------------------------------------
    def add_samples(self, samples: list[Document]) -> None:
        self.conn.executemany(
            "INSERT OR IGNORE INTO samples(sample_id, document) VALUES (?, ?)",
            [(x["sample_id"], json.dumps(x, ensure_ascii=False)) for x in samples])
        self.conn.commit()

    def get_samples(self, ids: Iterable[str]) -> dict[str, Document]:
        ids = list(ids)
        out: dict[str, Document] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for (doc_json,) in self.conn.execute(
                    f"SELECT document FROM samples WHERE sample_id IN ({marks})", chunk):
                doc = json.loads(doc_json)
                out[doc["sample_id"]] = doc
        return out

    def set_sample_llm(self, sample_id: str, llm: Document) -> None:
        stored = self.get_samples([sample_id]).get(sample_id)
        if stored is None:
            return
        stored["llm"] = llm
        self.conn.execute("UPDATE samples SET document=? WHERE sample_id=?",
                          (json.dumps(stored, ensure_ascii=False), sample_id))
        self.conn.commit()

    def iter_samples(self) -> Iterator[Document]:
        self.flush_samples()
        cur = self.conn.execute("SELECT document FROM samples")
        while True:
            rows = cur.fetchmany(500)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def page_records(self, after: Any, limit: int) -> tuple[list[Document], Any]:
        self._flush_buffer()
        rows = self.conn.execute("SELECT id, document FROM files WHERE id > ? ORDER BY id LIMIT ?",
                                 (after or 0, limit)).fetchall()
        return [json.loads(d) for _, d in rows], (rows[-1][0] if rows else after)

    def prune_samples(self) -> int:
        self._flush_buffer()
        n = self.conn.execute(
            "DELETE FROM samples WHERE sample_id NOT IN (SELECT json_extract(document, '$.sample_id') "
            "FROM files WHERE json_extract(document, '$.sample_id') IS NOT NULL)").rowcount
        self.conn.commit()
        return n

    # --- member sets -------------------------------------------------
    def put_member_set(self, header: Document, rows: list[Document]) -> bool:
        mid = header["members_id"]
        old = self.conn.execute("SELECT document FROM member_sets WHERE members_id=?", (mid,)).fetchone()
        if old and json.loads(old[0]).get("digest") == header["digest"]:
            return False
        cur = self.conn.cursor()
        cur.execute("DELETE FROM member_sets WHERE members_id=?", (mid,))
        cur.execute("DELETE FROM set_members WHERE members_id=?", (mid,))
        cur.executemany(
            "INSERT INTO set_members (members_id, idx, path, size, csize, role, kind, document) "
            "VALUES (?,?,?,?,?,?,?,?)",
            [(mid, r["index"], r.get("path"), r.get("size"), r.get("csize"), r.get("role"), r.get("kind"),
              json.dumps({**r, "members_id": mid}, ensure_ascii=False)) for r in rows])
        cur.execute("INSERT INTO member_sets (members_id, document) VALUES (?,?)",
                    (mid, json.dumps(header, ensure_ascii=False)))
        self.conn.commit()
        return True

    def list_member_set(self, members_id: str) -> Iterator[Document]:
        cur = self.conn.execute("SELECT document FROM set_members WHERE members_id=? ORDER BY idx",
                                (members_id,))
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def iter_member_sets(self) -> Iterator[Document]:
        cur = self.conn.execute("SELECT document FROM member_sets")
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def prune_member_sets(self) -> int:
        self._flush_buffer()
        n = self.conn.execute(
            "DELETE FROM member_sets WHERE members_id NOT IN (SELECT json_extract(document, '$.members_id') "
            "FROM files WHERE json_extract(document, '$.members_id') IS NOT NULL)").rowcount
        self.conn.execute("DELETE FROM set_members WHERE members_id NOT IN (SELECT members_id FROM member_sets)")
        self.conn.commit()
        return n

    # --- lifecycle -------------------------------------------------
    def scrub(self) -> None:
        """After a purge: rebuild the file, so that no free page, index key or
        write-ahead frame still holds a purged name."""
        self._flush_buffer()
        self.conn.commit()
        self.conn.execute("VACUUM")
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()

    def flush(self) -> None:
        self._flush_buffer()

    def close(self) -> None:
        self.flush()
        self.conn.close()
