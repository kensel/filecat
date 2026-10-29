"""PostgreSQL backend: psycopg v3, `document` stored as jsonb.

The driver import happens inside __init__ (not at module scope) so that
`import filecat.backends.postgres` -- which `filecat.backends.open_backend`
only does when the postgres backend is actually selected -- does not
require psycopg to be installed for the base jsonl/sqlite install.

Schema mirrors the sqlite backend: table `files` with indexed columns for
record.INDEXED_FIELDS, UNIQUE (root_id, rel_path), upserts via
INSERT ... ON CONFLICT DO UPDATE, batched with executemany(). `list()` and
`list_programs()` use a named (server-side) psycopg cursor so a million-row
table is streamed rather than materialized client-side.
"""
from __future__ import annotations

import json
import time
from typing import Any, Iterable, Iterator

from ..record import root_id
from .base import Backend, Document, chunks

BATCH_SIZE = 500
BATCH_SECONDS = 2.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id BIGSERIAL PRIMARY KEY,
    root_id TEXT NOT NULL,
    root TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    name TEXT,
    size BIGINT,
    mtime_ns BIGINT,
    kind TEXT,
    suffix TEXT,
    mime TEXT,
    sha256 TEXT,
    sha256_partial TEXT,
    document JSONB NOT NULL,
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
    document JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS roots (
    root_id TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    document JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS treemaps (
    id TEXT PRIMARY KEY,
    root_id TEXT NOT NULL,
    meta JSONB NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_treemaps_root ON treemaps(root_id);

CREATE TABLE IF NOT EXISTS dropped (
    id BIGSERIAL PRIMARY KEY,
    root_id TEXT NOT NULL,
    root TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    dropped_at TEXT NOT NULL,
    document JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dropped_at ON dropped(dropped_at);
CREATE INDEX IF NOT EXISTS idx_dropped_root ON dropped(root_id, rel_path);

CREATE TABLE IF NOT EXISTS agg_suffix (
    root_id TEXT NOT NULL, root TEXT NOT NULL, suffix TEXT,
    description TEXT, files BIGINT, bytes BIGINT, percent DOUBLE PRECISION,
    PRIMARY KEY (root_id, suffix)
);
CREATE TABLE IF NOT EXISTS agg_mime (
    root_id TEXT NOT NULL, root TEXT NOT NULL, mime TEXT,
    files BIGINT, bytes BIGINT, percent DOUBLE PRECISION,
    PRIMARY KEY (root_id, mime)
);
CREATE TABLE IF NOT EXISTS agg_dir (
    root_id TEXT NOT NULL, root TEXT NOT NULL, dir TEXT,
    files BIGINT, bytes BIGINT, percent DOUBLE PRECISION,
    PRIMARY KEY (root_id, dir)
);
CREATE TABLE IF NOT EXISTS agg_meta (
    root_id TEXT PRIMARY KEY, root TEXT NOT NULL,
    total_files BIGINT, total_bytes BIGINT, unreadable BIGINT,
    depth INTEGER, built_at TEXT
);

CREATE TABLE IF NOT EXISTS members (
    root_id TEXT NOT NULL,
    archive_rel_path TEXT NOT NULL,
    idx INTEGER NOT NULL,
    path TEXT,
    size BIGINT,
    csize BIGINT,
    role TEXT,
    kind TEXT,
    document JSONB NOT NULL,
    PRIMARY KEY (root_id, archive_rel_path, idx)
);
CREATE INDEX IF NOT EXISTS idx_members_role ON members(role);
CREATE INDEX IF NOT EXISTS idx_members_path ON members(path);
CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    document JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS member_sets (
    members_id TEXT PRIMARY KEY,
    document JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS set_members (
    members_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    path TEXT,
    size BIGINT,
    csize BIGINT,
    role TEXT,
    kind TEXT,
    document JSONB NOT NULL,
    PRIMARY KEY (members_id, idx)
);
CREATE INDEX IF NOT EXISTS idx_set_members_role ON set_members(role);
CREATE INDEX IF NOT EXISTS idx_set_members_path ON set_members(path);

CREATE TABLE IF NOT EXISTS redactions (
    id TEXT PRIMARY KEY,
    root_id TEXT NOT NULL,
    path_hash TEXT NOT NULL,
    document JSONB NOT NULL,
    UNIQUE (root_id, path_hash)
);

CREATE TABLE IF NOT EXISTS storage_topology (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS storage_topology_history (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_storage_history_host ON storage_topology_history(host, scanned_at);
CREATE TABLE IF NOT EXISTS server_jobs (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS server_state (
    doc_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    scanned_at TEXT,
    document JSONB NOT NULL
);
"""

_UPSERT_SQL = """
INSERT INTO files (root_id, root, rel_path, name, size, mtime_ns, kind,
                    suffix, mime, sha256, sha256_partial, document)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
ON CONFLICT (root_id, rel_path) DO UPDATE SET
    root=excluded.root, name=excluded.name, size=excluded.size,
    mtime_ns=excluded.mtime_ns, kind=excluded.kind, suffix=excluded.suffix,
    mime=excluded.mime, sha256=excluded.sha256,
    sha256_partial=excluded.sha256_partial, document=excluded.document
"""


def ping(dsn: str, timeout: float = 5.0) -> dict[str, Any]:
    """Read-only connection check for `filecat config test`."""
    import psycopg
    with psycopg.connect(dsn, connect_timeout=max(1, int(timeout)), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_setting('server_version'), current_database(), current_user, "
                        "has_schema_privilege(current_schema(), 'CREATE'), current_schema()")
            version, database, user, schema_create, schema = cur.fetchone()
            info: dict[str, Any] = {"server": f"PostgreSQL {version}", "database": database,
                                    "user": user, "schema": schema}
            cur.execute("SELECT c.relname, c.reltuples::bigint FROM pg_class c "
                        "WHERE c.oid IN (to_regclass('files'), to_regclass('members'))")
            tables = dict(cur.fetchall())
            info["tables"] = sorted(tables)
            if "files" in tables:
                info["files_estimate"] = max(0, tables["files"])
            elif not schema_create:
                # PostgreSQL 15+ no longer grants CREATE on public to everyone
                info["warning"] = (f"{user} cannot CREATE in schema {schema}; "
                                   f"GRANT CREATE ON SCHEMA {schema} TO {user} (or make it the owner)")
            return info


class PostgresBackend(Backend):
    name = "postgres"
    stores_samples = True
    batches_samples = True
    stores_member_sets = True

    def __init__(self, dsn: str) -> None:
        import psycopg  # lazy: only needed when this backend is used
        self._psycopg = psycopg
        self.dsn = dsn
        self.conn = psycopg.connect(dsn, autocommit=False)
        with self.conn.cursor() as cur:
            cur.execute(_SCHEMA)
        self.conn.commit()
        self._buffer: list[Document] = []
        self._last_flush = time.monotonic()

    def _row(self, doc: Document) -> tuple:
        sha_partial = doc.get("sha256_partial")
        if sha_partial is not None and not isinstance(sha_partial, str):
            sha_partial = json.dumps(sha_partial, ensure_ascii=False)
        return (
            doc["root_id"], doc["root"], doc["rel_path"], doc.get("name"),
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
            cur.execute("SELECT document FROM files WHERE root_id=%s AND rel_path=%s",
                        (root_id(root), rel_path))
            row = cur.fetchone()
        return row[0] if row else None

    def get_stats(self, root: str, rel_paths: list[str]) -> dict[str, Document]:
        rid, out = root_id(root), {}
        with self.conn.cursor() as cur:
            for part in chunks(rel_paths):
                cur.execute("SELECT rel_path, document FROM files WHERE root_id=%s AND rel_path = ANY(%s)",
                            (rid, part))
                out.update((rel, doc) for rel, doc in cur.fetchall())
        self._overlay_buffer(root, rel_paths, out)
        return out

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
        with self.conn.cursor(name="filecat_list") as cur:
            cur.itersize = 1000
            cur.execute(f"SELECT document FROM files{where}", params)
            for (doc,) in cur:
                yield doc
        self.conn.commit()

    def query(self, q: dict[str, Any]) -> dict[str, Any]:
        from ..browse import POSTGRES, sql_order, sql_where
        self.flush()
        rid = root_id(q["root"]) if q.get("root") is not None else None
        where, params = sql_where(q, POSTGRES, rid)
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files{where}", params)
            total, nbytes = cur.fetchone()
            cur.execute(
                f"SELECT document FROM files{where} ORDER BY {sql_order(q, POSTGRES)} LIMIT %s OFFSET %s",
                [*params, q["limit"], q["offset"]])
            rows = [r[0] for r in cur.fetchall()]
        self.conn.commit()
        return {"total": int(total), "bytes": int(nbytes), "rows": rows}

    def search_names(self, q: dict[str, Any]) -> dict[str, Any]:
        from ..browse import POSTGRES, sql_order, sql_where
        self.flush()
        rid = root_id(q["root"]) if q.get("root") is not None else None
        where, params = sql_where(q, POSTGRES, rid)
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT document FROM files{where} ORDER BY {sql_order(q, POSTGRES)} "
                        "LIMIT %s OFFSET %s", [*params, q["limit"] + 1, q["offset"]])
            rows = [r[0] for r in cur.fetchall()]
        self.conn.commit()
        return {"rows": rows[:q["limit"]], "more": len(rows) > q["limit"]}

    def subtree(self, root: str, parent: str) -> list[dict[str, Any]]:
        from ..browse import POSTGRES, sql_subtree
        self.flush()
        sql, params = sql_subtree(parent, POSTGRES, root_id(root))
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        self.conn.commit()
        return sorted(({"name": n, "files": int(f), "bytes": int(b)} for n, f, b in rows),
                      key=lambda r: (-r["bytes"], r["name"]))

    def sizes(self, root: str, prefix: str = "") -> Iterator[tuple[str, int, str, str]]:
        from ..browse import POSTGRES, sql_sizes
        self.flush()
        sql, params = sql_sizes(prefix, POSTGRES, root_id(root))
        with self.conn.cursor(name="filecat_sizes") as cur:
            cur.itersize = 5000
            cur.execute(sql, params)
            for rel, size, suffix, mime in cur:
                yield rel, int(size), suffix, mime
        self.conn.commit()

    def delete(self, root: str, rel_path: str) -> None:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM files WHERE root_id=%s AND rel_path=%s",
                        (root_id(root), rel_path))
        self.conn.commit()
        self.delete_members(root, rel_path)

    def delete_many(self, root: str, rel_paths: Iterable[str]) -> int:
        self.flush()
        rid, n = root_id(root), 0
        with self.conn.cursor() as cur:
            for part in chunks(list(rel_paths)):
                cur.execute("DELETE FROM files WHERE root_id=%s AND rel_path = ANY(%s)", (rid, part))
                n += cur.rowcount
                cur.execute("DELETE FROM members WHERE root_id=%s AND archive_rel_path = ANY(%s)",
                            (rid, part))
        self.conn.commit()
        return n

    # --- archive members -------------------------------------------
    def put_members(self, root: str, rel_path: str, members: list) -> None:
        self.flush()
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
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM members WHERE root_id=%s AND archive_rel_path=%s", (rid, rel_path))
            if rows:
                cur.executemany(
                    "INSERT INTO members (root_id, archive_rel_path, idx, path, size, csize, "
                    "role, kind, document) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)", rows)
        self.conn.commit()

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        self.flush()
        rid = root_id(root)
        with self.conn.cursor(name="filecat_members") as cur:
            cur.itersize = 1000
            cur.execute(
                "SELECT document FROM members WHERE root_id=%s AND archive_rel_path=%s ORDER BY idx",
                (rid, rel_path))
            for (doc,) in cur:
                yield doc
        self.conn.commit()

    def iter_all_members(self) -> Iterator[Document]:
        self.flush()
        with self.conn.cursor(name="filecat_all_members") as cur:
            cur.itersize = 1000
            cur.execute("SELECT document FROM members ORDER BY root_id, archive_rel_path, idx")
            for (doc,) in cur:
                yield doc
        self.conn.commit()

    def delete_members(self, root: str, rel_path: str) -> None:
        rid = root_id(root)
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM members WHERE root_id=%s AND archive_rel_path=%s", (rid, rel_path))
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

    def stored_totals(self, root: str | None = None) -> dict[str, Any]:
        self.flush()
        where = " WHERE root = %s" if root is not None else ""
        params = (root,) if root is not None else ()
        with self.conn.cursor() as cur:
            cur.execute("SELECT root, total_files, total_bytes, unreadable, depth, built_at "
                        f"FROM agg_meta{where}", params)
            return {rname: {"total_files": int(f), "total_bytes": int(b), "unreadable": int(u), "depth": d,
                            "built_at": at} for rname, f, b, u, d, at in cur.fetchall()}

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
                        "INSERT INTO agg_dir (root_id, root, dir, files, bytes, percent) VALUES (%s,%s,%s,%s,%s,%s)",
                        [(rid, rname, r["dir"], r["files"], r["bytes"], r["percent"]) for r in e["dir"]])
                cur.execute(
                    "INSERT INTO agg_meta (root_id, root, total_files, total_bytes, unreadable, depth, built_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (rid, rname, e["total_files"], e["total_bytes"], e["unreadable"], depth, built_at))
        self.conn.commit()

    # --- dropped records ------------------------------------------------
    def put_dropped(self, document: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO dropped (root_id, root, rel_path, dropped_at, document) "
                "VALUES (%s, %s, %s, %s, %s::jsonb)",
                (document["root_id"], document["root"], document["rel_path"],
                 document["dropped_at"], json.dumps(document, ensure_ascii=False)),
            )
        self.conn.commit()

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        where, params = (" WHERE root_id=%s", (root_id(root),)) if root is not None else ("", ())
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT document FROM dropped{where} ORDER BY dropped_at DESC, id DESC", params)
            rows = cur.fetchall()
        self.conn.commit()
        for (doc,) in rows:
            yield doc if isinstance(doc, dict) else json.loads(doc)

    def purge_dropped(self, before: str) -> int:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM dropped WHERE dropped_at < %s", (before,))
            n = cur.rowcount
        self.conn.commit()
        return n

    def purge_dropped_paths(self, root: str, rel_paths: Iterable[str]) -> int:
        rid, paths = root_id(root), list(rel_paths)
        with self.conn.cursor() as cur:
            cur.execute("SELECT id, rel_path FROM dropped WHERE root_id=%s", (rid,))
            gone = [i for i, rel in cur.fetchall()
                    if any(rel == p or rel.startswith(p + "/") for p in paths)]
            for part in chunks(gone):
                cur.execute("DELETE FROM dropped WHERE id = ANY(%s)", (part,))
        self.conn.commit()
        return len(gone)

    # --- sticky redactions ---------------------------------------------
    def _redaction_rows(self, root: str | None = None) -> list[Document]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT document FROM redactions")
            rows = cur.fetchall()
        self.conn.commit()
        return [d if isinstance(d, dict) else json.loads(d) for (d,) in rows]

    def _redaction_put(self, entry: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO redactions (id, root_id, path_hash, document) VALUES (%s, %s, %s, %s::jsonb) "
                "ON CONFLICT (id) DO UPDATE SET root_id=excluded.root_id, "
                "path_hash=excluded.path_hash, document=excluded.document",
                (entry["id"], entry["root_id"], entry["path_hash"],
                 json.dumps(entry, ensure_ascii=False)))
        self.conn.commit()

    def _redaction_remove(self, entry: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM redactions WHERE id=%s", (entry["id"],))
        self.conn.commit()

    # --- storage topology ------------------------------------------------
    def _topology_rows(self, store: str) -> list[Document]:
        assert store in self.DOC_STORES
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT document FROM {store}")
            rows = cur.fetchall()
        self.conn.commit()
        return [d if isinstance(d, dict) else json.loads(d) for (d,) in rows]

    def _topology_put(self, store: str, doc: Document) -> None:
        assert store in self.DOC_STORES
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {store} (doc_key, host, scanned_at, document) VALUES (%s, %s, %s, %s::jsonb) "
                "ON CONFLICT (doc_key) DO UPDATE SET host=excluded.host, "
                "scanned_at=excluded.scanned_at, document=excluded.document",
                (doc["key"], doc["host"], doc.get("scanned_at"), json.dumps(doc, ensure_ascii=False)))
        self.conn.commit()

    def _topology_claim(self, store: str, doc: Document, holder: str, now: str, takeover: bool) -> bool:
        """One INSERT ... ON CONFLICT DO UPDATE ... WHERE: row-locked by PostgreSQL, so of two
        racing servers exactly one inserts or updates (rowcount 1); the other changes nothing."""
        assert store in self.DOC_STORES
        cond = f"{store}.document->>'holder' = %s"
        args: list[Any] = [holder]
        if takeover:
            cond += f" OR {store}.document->>'expires_at' < %s"
            args.append(now)
        import psycopg.errors
        for attempt in range(8):
            try:
                with self.conn.cursor() as cur:
                    cur.execute(
                        f"INSERT INTO {store} (doc_key, host, scanned_at, document) VALUES (%s, %s, %s, %s::jsonb) "
                        "ON CONFLICT (doc_key) DO UPDATE SET host=excluded.host, scanned_at=excluded.scanned_at, "
                        f"document=excluded.document WHERE {cond}",
                        (doc["key"], doc["host"], doc.get("scanned_at"), json.dumps(doc, ensure_ascii=False), *args))
                    won = cur.rowcount == 1
                self.conn.commit()
                return won
            except (psycopg.errors.DeadlockDetected, psycopg.errors.SerializationFailure):    # 40P01, 40001
                self.conn.rollback()
                time.sleep(0.01 * (attempt + 1))
        return False                # still deadlocked: not won; the caller tries again on its next beat

    def _topology_remove(self, store: str, key: str) -> None:
        assert store in self.DOC_STORES
        with self.conn.cursor() as cur:
            cur.execute(f"DELETE FROM {store} WHERE doc_key=%s", (key,))
        self.conn.commit()

    # --- root index ----------------------------------------------------
    def put_root_info(self, info: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO roots (root_id, root, document) VALUES (%s, %s, %s::jsonb) "
                "ON CONFLICT (root_id) DO UPDATE SET root=excluded.root, document=excluded.document",
                (info["root_id"], info.get("root") or "", json.dumps(info, ensure_ascii=False)),
            )
        self.conn.commit()

    def list_root_info(self) -> Iterator[Document]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT document FROM roots ORDER BY root")
            rows = cur.fetchall()
        self.conn.commit()
        for (doc,) in rows:
            yield doc if isinstance(doc, dict) else json.loads(doc)

    def get_root_info(self, root: str) -> Document | None:
        with self.conn.cursor() as cur:
            cur.execute("SELECT document FROM roots WHERE root_id=%s", (root_id(root),))
            row = cur.fetchone()
        self.conn.commit()
        if row is None:
            return None
        return row[0] if isinstance(row[0], dict) else json.loads(row[0])

    def delete_root_info(self, root: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM roots WHERE root_id=%s", (root_id(root),))
        self.conn.commit()

    # --- stored treemaps ---------------------------------------------
    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        with self.conn.cursor() as cur:
            if data is None:
                cur.execute("UPDATE treemaps SET meta=%s::jsonb WHERE id=%s",
                            (json.dumps(meta, ensure_ascii=False), meta["id"]))
            else:
                cur.execute(
                    "INSERT INTO treemaps (id, root_id, meta, data) VALUES (%s, %s, %s::jsonb, %s) "
                    "ON CONFLICT (id) DO UPDATE SET root_id=excluded.root_id, meta=excluded.meta, "
                    "data=excluded.data",
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
        return [m if isinstance(m, dict) else json.loads(m) for (m,) in rows]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        with self.conn.cursor() as cur:
            cur.execute("SELECT meta, data FROM treemaps WHERE id=%s", (treemap_id,))
            row = cur.fetchone()
        self.conn.commit()
        if row is None:
            return None
        return (row[0] if isinstance(row[0], dict) else json.loads(row[0])), json.loads(row[1])

    def delete_treemap(self, treemap_id: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM treemaps WHERE id=%s", (treemap_id,))
        self.conn.commit()

    # --- installed programs -------------------------------------------
    def put_program(self, record: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO programs (program_id, document) VALUES (%s, %s::jsonb) "
                "ON CONFLICT (program_id) DO UPDATE SET document=excluded.document",
                (record["program_id"], json.dumps(record, ensure_ascii=False)),
            )
        self.conn.commit()

    def list_programs(self) -> Iterator[Document]:
        with self.conn.cursor(name="filecat_programs") as cur:
            cur.itersize = 500
            cur.execute("SELECT document FROM programs")
            for (doc,) in cur:
                yield doc
        self.conn.commit()

    def clear_programs(self) -> None:
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM programs")
        self.conn.commit()

    # --- samples ---------------------------------------------------
    def add_samples(self, samples: list[Document]) -> None:
        with self.conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO samples (sample_id, document) VALUES (%s, %s::jsonb) "
                "ON CONFLICT (sample_id) DO NOTHING",
                [(x["sample_id"], json.dumps(x, ensure_ascii=False)) for x in samples])
        self.conn.commit()

    def get_samples(self, ids: Iterable[str]) -> dict[str, Document]:
        ids = list(ids)
        if not ids:
            return {}
        with self.conn.cursor() as cur:
            cur.execute("SELECT document FROM samples WHERE sample_id = ANY(%s)", (ids,))
            rows = cur.fetchall()
        # no commit: it would close a list() cursor still being read
        return {d["sample_id"]: d for (d,) in rows}

    def set_sample_llm(self, sample_id: str, llm: Document) -> None:
        with self.conn.cursor() as cur:
            cur.execute("UPDATE samples SET document = jsonb_set(document, '{llm}', %s::jsonb) "
                        "WHERE sample_id = %s", (json.dumps(llm, ensure_ascii=False), sample_id))
        self.conn.commit()

    def iter_samples(self) -> Iterator[Document]:
        self.flush_samples()
        with self.conn.cursor(name="filecat_samples") as cur:
            cur.itersize = 500
            cur.execute("SELECT document FROM samples")
            for (doc,) in cur:
                yield doc
        self.conn.commit()

    def page_records(self, after: Any, limit: int) -> tuple[list[Document], Any]:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("SELECT id, document FROM files WHERE id > %s ORDER BY id LIMIT %s",
                        (after or 0, limit))
            rows = cur.fetchall()
        self.conn.commit()
        return [d for _, d in rows], (rows[-1][0] if rows else after)

    def prune_samples(self) -> int:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM samples s WHERE NOT EXISTS "
                        "(SELECT 1 FROM files f WHERE f.document->>'sample_id' = s.sample_id)")
            n = cur.rowcount
        self.conn.commit()
        return n

    # --- member sets -------------------------------------------------
    def put_member_set(self, header: Document, rows: list[Document]) -> bool:
        mid = header["members_id"]
        with self.conn.cursor() as cur:
            cur.execute("SELECT document->>'digest' FROM member_sets WHERE members_id=%s", (mid,))
            old = cur.fetchone()
            if old and old[0] == header["digest"]:
                self.conn.commit()
                return False
            cur.execute("DELETE FROM member_sets WHERE members_id=%s", (mid,))
            cur.execute("DELETE FROM set_members WHERE members_id=%s", (mid,))
            cur.executemany(
                "INSERT INTO set_members (members_id, idx, path, size, csize, role, kind, document) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
                [(mid, r["index"], r.get("path"), r.get("size"), r.get("csize"), r.get("role"),
                  r.get("kind"), json.dumps({**r, "members_id": mid}, ensure_ascii=False)) for r in rows])
            cur.execute("INSERT INTO member_sets (members_id, document) VALUES (%s, %s::jsonb)",
                        (mid, json.dumps(header, ensure_ascii=False)))
        self.conn.commit()
        return True

    def list_member_set(self, members_id: str) -> Iterator[Document]:
        self.flush()
        with self.conn.cursor(name="filecat_member_set") as cur:
            cur.itersize = 1000
            cur.execute("SELECT document FROM set_members WHERE members_id=%s ORDER BY idx", (members_id,))
            for (doc,) in cur:
                yield doc
        self.conn.commit()

    def iter_member_sets(self) -> Iterator[Document]:
        self.flush()
        with self.conn.cursor(name="filecat_member_sets") as cur:
            cur.itersize = 1000
            cur.execute("SELECT document FROM member_sets")
            for (doc,) in cur:
                yield doc
        self.conn.commit()

    def prune_member_sets(self) -> int:
        self.flush()
        with self.conn.cursor() as cur:
            cur.execute("DELETE FROM member_sets m WHERE NOT EXISTS "
                        "(SELECT 1 FROM files f WHERE f.document->>'members_id' = m.members_id)")
            n = cur.rowcount
            cur.execute("DELETE FROM set_members r WHERE NOT EXISTS "
                        "(SELECT 1 FROM member_sets m WHERE m.members_id = r.members_id)")
        self.conn.commit()
        return n

    # --- lifecycle -------------------------------------------------
    def close(self) -> None:
        self.flush()
        self.conn.close()
