"""SQL Server backend: pyodbc, `document` stored as NVARCHAR(MAX) (UTF-8
JSON text, decoded/encoded through the ODBC driver like any other string).

The driver import happens inside __init__ so importing this module does
not require pyodbc unless the mssql backend is actually used.

Like the mysql backend, `rel_path` (and the aggregate `dir` key) can be
longer than a nonclustered index key supports, so uniqueness is enforced
on a `rel_hash` CHAR(64) column (sha256 hex of rel_path) rather than on
rel_path itself.

SQL Server has no native "INSERT ... ON CONFLICT"; upserts use MERGE.
`list()`/`list_programs()` fetch with `cursor.fetchmany()` in a generator
so a large table is streamed rather than pulled into memory.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Iterable, Iterator

from ..record import root_id
from .base import Backend, Document, chunks

BATCH_SIZE = 500
BATCH_SECONDS = 2.0

_TABLES = {
    "files": """
        CREATE TABLE files (
            id BIGINT IDENTITY PRIMARY KEY,
            root_id VARCHAR(32) NOT NULL,
            root NVARCHAR(MAX) NOT NULL,
            rel_path NVARCHAR(MAX) NOT NULL,
            rel_hash CHAR(64) NOT NULL,
            name NVARCHAR(512),
            size BIGINT,
            mtime_ns BIGINT,
            kind VARCHAR(32),
            suffix VARCHAR(190),
            mime VARCHAR(190),
            sha256 CHAR(64),
            sha256_partial VARCHAR(255),
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "programs": """
        CREATE TABLE programs (
            program_id VARCHAR(255) PRIMARY KEY,
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "dropped": """
        CREATE TABLE dropped (
            id BIGINT IDENTITY(1,1) PRIMARY KEY,
            root_id VARCHAR(32) NOT NULL,
            root NVARCHAR(MAX) NOT NULL,
            rel_path NVARCHAR(MAX) NOT NULL,
            rel_hash CHAR(64) NOT NULL,
            dropped_at VARCHAR(40) NOT NULL,
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "roots": """
        CREATE TABLE roots (
            root_id VARCHAR(32) PRIMARY KEY,
            root NVARCHAR(MAX) NOT NULL,
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "treemaps": """
        CREATE TABLE treemaps (
            id VARCHAR(32) PRIMARY KEY,
            root_id VARCHAR(32) NOT NULL,
            meta NVARCHAR(MAX) NOT NULL,
            data NVARCHAR(MAX) NOT NULL
        )
    """,
    "agg_suffix": """
        CREATE TABLE agg_suffix (
            root_id VARCHAR(32) NOT NULL, root NVARCHAR(MAX) NOT NULL,
            suffix VARCHAR(190) NOT NULL, description NVARCHAR(MAX),
            files BIGINT, bytes BIGINT, [percent] FLOAT,
            PRIMARY KEY (root_id, suffix)
        )
    """,
    "agg_mime": """
        CREATE TABLE agg_mime (
            root_id VARCHAR(32) NOT NULL, root NVARCHAR(MAX) NOT NULL,
            mime VARCHAR(190) NOT NULL, files BIGINT, bytes BIGINT, [percent] FLOAT,
            PRIMARY KEY (root_id, mime)
        )
    """,
    "agg_dir": """
        CREATE TABLE agg_dir (
            root_id VARCHAR(32) NOT NULL, root NVARCHAR(MAX) NOT NULL,
            dir NVARCHAR(MAX) NOT NULL, dir_hash CHAR(64) NOT NULL,
            files BIGINT, bytes BIGINT, [percent] FLOAT,
            PRIMARY KEY (root_id, dir_hash)
        )
    """,
    "agg_meta": """
        CREATE TABLE agg_meta (
            root_id VARCHAR(32) PRIMARY KEY, root NVARCHAR(MAX) NOT NULL,
            total_files BIGINT, total_bytes BIGINT, unreadable BIGINT,
            depth INT, built_at VARCHAR(64)
        )
    """,
    "members": """
        CREATE TABLE members (
            root_id VARCHAR(32) NOT NULL,
            archive_hash CHAR(64) NOT NULL,
            archive_rel_path NVARCHAR(MAX) NOT NULL,
            idx INT NOT NULL,
            path NVARCHAR(MAX),
            path_hash CHAR(64),
            size BIGINT,
            csize BIGINT,
            role VARCHAR(32),
            kind VARCHAR(32),
            document NVARCHAR(MAX) NOT NULL,
            PRIMARY KEY (root_id, archive_hash, idx)
        )
    """,
    "redactions": """
        CREATE TABLE redactions (
            id VARCHAR(16) PRIMARY KEY,
            root_id VARCHAR(32) NOT NULL,
            path_hash CHAR(32) NOT NULL,
            document NVARCHAR(MAX) NOT NULL,
            UNIQUE (root_id, path_hash)
        )
    """,
    "storage_topology": """
        CREATE TABLE storage_topology (
            doc_key NVARCHAR(400) PRIMARY KEY,
            host NVARCHAR(400) NOT NULL,
            scanned_at VARCHAR(40),
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "server_jobs": """
        CREATE TABLE server_jobs (
            doc_key NVARCHAR(400) PRIMARY KEY,
            host NVARCHAR(400) NOT NULL,
            scanned_at VARCHAR(40),
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "server_state": """
        CREATE TABLE server_state (
            doc_key NVARCHAR(400) PRIMARY KEY,
            host NVARCHAR(400) NOT NULL,
            scanned_at VARCHAR(40),
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "storage_topology_history": """
        CREATE TABLE storage_topology_history (
            doc_key NVARCHAR(400) PRIMARY KEY,
            host NVARCHAR(400) NOT NULL,
            scanned_at VARCHAR(40),
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "samples": """
        CREATE TABLE samples (
            sample_id VARCHAR(64) PRIMARY KEY,
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "member_sets": """
        CREATE TABLE member_sets (
            members_id VARCHAR(64) PRIMARY KEY,
            document NVARCHAR(MAX) NOT NULL
        )
    """,
    "set_members": """
        CREATE TABLE set_members (
            members_id VARCHAR(64) NOT NULL,
            idx INT NOT NULL,
            path NVARCHAR(MAX),
            path_hash CHAR(64),
            size BIGINT,
            csize BIGINT,
            role VARCHAR(32),
            kind VARCHAR(32),
            document NVARCHAR(MAX) NOT NULL,
            PRIMARY KEY (members_id, idx)
        )
    """,
}

_INDEXES = [
    ("idx_files_root_relhash", "files", "(root_id, rel_hash)", True),
    ("idx_files_sha256", "files", "(sha256)", False),
    ("idx_files_kind", "files", "(kind)", False),
    ("idx_files_suffix", "files", "(suffix)", False),
    ("idx_files_mime", "files", "(mime)", False),
    ("idx_members_role", "members", "(role)", False),
    ("idx_dropped_at", "dropped", "(dropped_at)", False),
    ("idx_treemaps_root", "treemaps", "(root_id)", False),
    ("idx_dropped_root", "dropped", "(root_id, rel_hash)", False),
    ("idx_members_path_hash", "members", "(path_hash)", False),
    ("idx_set_members_role", "set_members", "(role)", False),
    ("idx_set_members_path_hash", "set_members", "(path_hash)", False),
]

_MERGE_SQL = """
MERGE files AS target
USING (SELECT ? AS root_id, ? AS rel_hash) AS src
    ON target.root_id = src.root_id AND target.rel_hash = src.rel_hash
WHEN MATCHED THEN UPDATE SET
    root=?, rel_path=?, name=?, size=?, mtime_ns=?, kind=?, suffix=?, mime=?,
    sha256=?, sha256_partial=?, document=?
WHEN NOT MATCHED THEN INSERT
    (root_id, rel_hash, root, rel_path, name, size, mtime_ns, kind, suffix, mime,
     sha256, sha256_partial, document)
    VALUES (src.root_id, src.rel_hash, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""


def _rel_hash(rel_path: str) -> str:
    return hashlib.sha256(rel_path.encode("utf-8")).hexdigest()


def ping(dsn: str, timeout: float = 5.0) -> dict[str, Any]:
    """Read-only connection check for `filecat config test`."""
    import pyodbc
    conn = pyodbc.connect(dsn, timeout=max(1, int(timeout)), autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)), "
                    "CAST(SERVERPROPERTY('Edition') AS nvarchar(128)), DB_NAME(), SUSER_SNAME(), "
                    "HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE TABLE')")
        version, edition, database, user, can_create = cur.fetchone()
        info: dict[str, Any] = {"server": f"SQL Server {version} ({edition})",
                                "database": database, "user": user}
        if database in ("master", "tempdb", "model", "msdb"):
            info["warning"] = f"connected to system database {database}; add DATABASE=filecat to the DSN"
        cur.execute("SELECT t.name, SUM(p.rows) FROM sys.tables t JOIN sys.partitions p "
                    "ON p.object_id = t.object_id AND p.index_id IN (0, 1) "
                    "WHERE t.name IN ('files', 'members') GROUP BY t.name")
        tables = {name.lower(): rows for name, rows in cur.fetchall()}
        info["tables"] = sorted(tables)
        if "files" in tables:
            info["files_estimate"] = int(tables["files"])
        elif not can_create:
            info["warning"] = f"{user} lacks CREATE TABLE in {database}"
        return info
    finally:
        conn.close()


class MssqlBackend(Backend):
    name = "mssql"
    stores_samples = True
    batches_samples = True
    stores_member_sets = True

    def __init__(self, dsn: str) -> None:
        import pyodbc  # lazy: only needed when this backend is used
        self._pyodbc = pyodbc
        self.dsn = dsn
        self.conn = pyodbc.connect(dsn, autocommit=False)
        try:
            self._init_schema()
        except Exception:
            self.conn.close()  # else its open transaction blocks the next connection's DDL
            raise
        self._buffer: list[Document] = []
        self._last_flush = time.monotonic()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        for name, ddl in _TABLES.items():
            guarded = f"IF OBJECT_ID('{name}', 'U') IS NULL BEGIN {ddl} END"
            cur.execute(guarded)
        for idx_name, table, cols, unique in _INDEXES:
            kind = "UNIQUE " if unique else ""
            guarded = (
                f"IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = '{idx_name}') "
                f"CREATE {kind}INDEX {idx_name} ON {table}{cols}"
            )
            cur.execute(guarded)
        self.conn.commit()

    def _row(self, doc: Document) -> tuple:
        sha_partial = doc.get("sha256_partial")
        if sha_partial is not None and not isinstance(sha_partial, str):
            sha_partial = json.dumps(sha_partial, ensure_ascii=False)
        rel_path = doc["rel_path"]
        values = (
            doc["root"], rel_path, doc.get("name"), doc.get("size"), doc.get("mtime_ns"),
            doc.get("kind"), doc.get("suffix"), doc.get("mime"), doc.get("sha256"),
            sha_partial, json.dumps(doc, ensure_ascii=False),
        )
        # (root_id, rel_hash) for the USING clause, then the UPDATE SET values,
        # then the INSERT VALUES (same business values again).
        return (doc["root_id"], _rel_hash(rel_path)) + values + values

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
        cur = self.conn.cursor()
        try:
            cur.fast_executemany = True
        except AttributeError:
            pass
        cur.executemany(_MERGE_SQL, rows)
        self.conn.commit()
        self._buffer.clear()
        self._last_flush = time.monotonic()

    def get(self, root: str, rel_path: str) -> Document | None:
        self.flush()
        cur = self.conn.cursor()
        cur.execute("SELECT document FROM files WHERE root_id=? AND rel_hash=?",
                    (root_id(root), _rel_hash(rel_path)))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def get_stats(self, root: str, rel_paths: list[str]) -> dict[str, Document]:
        rid, out = root_id(root), {}
        cur = self.conn.cursor()
        for part in chunks(rel_paths):
            marks = ", ".join(["?"] * len(part))
            cur.execute(f"SELECT rel_path, document FROM files WHERE root_id=? AND rel_hash IN ({marks})",
                        (rid, *[_rel_hash(p) for p in part]))
            out.update((rel, json.loads(doc)) for rel, doc in cur.fetchall())
        self._overlay_buffer(root, rel_paths, out)
        return out

    def list(self, kind: str | None = None, root: str | None = None) -> Iterator[Document]:
        self.flush()
        clauses, params = [], []
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        if root is not None:
            clauses.append("root_id = ?")
            params.append(root_id(root))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        cur = self.conn.cursor()
        cur.execute(f"SELECT document FROM files{where}", params)
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def query(self, q: dict[str, Any]) -> dict[str, Any]:
        from ..browse import MSSQL, sql_order, sql_where
        self.flush()
        rid = root_id(q["root"]) if q.get("root") is not None else None
        where, params = sql_where(q, MSSQL, rid)
        cur = self.conn.cursor()
        cur.execute(f"SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files{where}", params)
        total, nbytes = cur.fetchone()
        cur.execute(
            f"SELECT document FROM files{where} ORDER BY {sql_order(q, MSSQL)} "
            "OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            [*params, q["offset"], q["limit"]])
        rows = [json.loads(r[0]) for r in cur.fetchall()]
        return {"total": int(total), "bytes": int(nbytes), "rows": rows}

    def subtree(self, root: str, parent: str) -> list[dict[str, Any]]:
        from ..browse import MSSQL, sql_subtree
        self.flush()
        sql, params = sql_subtree(parent, MSSQL, root_id(root))
        cur = self.conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        return sorted(({"name": n, "files": int(f), "bytes": int(b)} for n, f, b in rows),
                      key=lambda r: (-r["bytes"], r["name"]))

    def sizes(self, root: str, prefix: str = "") -> Iterator[tuple[str, int, str, str]]:
        from ..browse import MSSQL, sql_sizes
        self.flush()
        sql, params = sql_sizes(prefix, MSSQL, root_id(root))
        cur = self.conn.cursor()
        cur.execute(sql, params)
        while True:
            rows = cur.fetchmany(5000)
            if not rows:
                break
            for rel, size, suffix, mime in rows:
                yield rel, int(size), suffix, mime

    def delete(self, root: str, rel_path: str) -> None:
        self.flush()
        cur = self.conn.cursor()
        cur.execute("DELETE FROM files WHERE root_id=? AND rel_hash=?",
                    (root_id(root), _rel_hash(rel_path)))
        self.conn.commit()
        self.delete_members(root, rel_path)

    def delete_many(self, root: str, rel_paths: Iterable[str]) -> int:
        self.flush()
        rid, n = root_id(root), 0
        cur = self.conn.cursor()
        for part in chunks([_rel_hash(p) for p in rel_paths]):
            marks = ",".join("?" * len(part))
            cur.execute(f"DELETE FROM files WHERE root_id=? AND rel_hash IN ({marks})", (rid, *part))
            n += cur.rowcount
            cur.execute(f"DELETE FROM members WHERE root_id=? AND archive_hash IN ({marks})", (rid, *part))
        self.conn.commit()
        return n

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
                full.get("role"), full.get("kind"), json.dumps(full, ensure_ascii=False),
            ))
        cur = self.conn.cursor()
        cur.execute("DELETE FROM members WHERE root_id=? AND archive_hash=?", (rid, ahash))
        if rows:
            try:
                cur.fast_executemany = True
            except AttributeError:
                pass
            cur.executemany(
                "INSERT INTO members (root_id, archive_hash, archive_rel_path, idx, path, "
                "path_hash, size, csize, role, kind, document) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
        self.conn.commit()

    def list_members(self, root: str, rel_path: str) -> Iterator[Document]:
        self.flush()
        rid = root_id(root)
        ahash = _rel_hash(rel_path)
        cur = self.conn.cursor()
        cur.execute(
            "SELECT document FROM members WHERE root_id=? AND archive_hash=? ORDER BY idx",
            (rid, ahash))
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def iter_all_members(self) -> Iterator[Document]:
        self.flush()
        cur = self.conn.cursor()
        cur.execute("SELECT document FROM members ORDER BY root_id, archive_hash, idx")
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def delete_members(self, root: str, rel_path: str) -> None:
        rid = root_id(root)
        ahash = _rel_hash(rel_path)
        cur = self.conn.cursor()
        cur.execute("DELETE FROM members WHERE root_id=? AND archive_hash=?", (rid, ahash))
        self.conn.commit()

    def roots(self) -> list[str]:
        self.flush()
        cur = self.conn.cursor()
        cur.execute("SELECT DISTINCT root FROM files ORDER BY root")
        return [r[0] for r in cur.fetchall()]

    # --- aggregates --------------------------------------------------
    def stored_aggregates(self, root: str | None = None) -> dict[str, Any]:
        self.flush()
        where = " WHERE root = ?" if root is not None else ""
        params = (root,) if root is not None else ()
        roots_out: dict[str, Any] = {}
        cur = self.conn.cursor()
        cur.execute("SELECT root_id, root, total_files, total_bytes, unreadable, depth, built_at "
                    f"FROM agg_meta{where}", params)
        metas = cur.fetchall()
        for rid, rname, total_files, total_bytes, unreadable, depth, built_at in metas:
            cur.execute(
                "SELECT suffix, description, files, bytes, [percent] FROM agg_suffix "
                "WHERE root_id=? ORDER BY bytes DESC, suffix ASC", (rid,))
            suffix = [{"suffix": r[0], "description": r[1], "files": int(r[2]), "bytes": int(r[3]), "percent": r[4]}
                      for r in cur.fetchall()]
            cur.execute(
                "SELECT mime, files, bytes, [percent] FROM agg_mime "
                "WHERE root_id=? ORDER BY bytes DESC, mime ASC", (rid,))
            mime = [{"mime": r[0], "files": int(r[1]), "bytes": int(r[2]), "percent": r[3]} for r in cur.fetchall()]
            cur.execute(
                "SELECT dir, files, bytes, [percent] FROM agg_dir "
                "WHERE root_id=? ORDER BY bytes DESC, dir ASC", (rid,))
            dirs = [{"dir": r[0], "files": int(r[1]), "bytes": int(r[2]), "percent": r[3]} for r in cur.fetchall()]
            roots_out[rname] = {
                "suffix": suffix, "mime": mime, "dir": dirs,
                "total_files": int(total_files), "total_bytes": int(total_bytes),
                "unreadable": int(unreadable), "depth": depth, "built_at": built_at,
            }
        return roots_out

    def replace_aggregates(self, entries: dict[str, Any], depth: int, built_at: str,
                           root: str | None) -> None:
        where = " WHERE root_id = ?" if root is not None else ""
        params = (root_id(root),) if root is not None else ()
        cur = self.conn.cursor()
        for table in ("agg_suffix", "agg_mime", "agg_dir", "agg_meta"):
            cur.execute(f"DELETE FROM {table}{where}", params)
        cur.fast_executemany = True
        for rname, e in entries.items():
            rid = root_id(rname)
            if e["suffix"]:
                cur.executemany(
                    "INSERT INTO agg_suffix (root_id, root, suffix, description, files, bytes, [percent]) "
                    "VALUES (?,?,?,?,?,?,?)",
                    [(rid, rname, r["suffix"], r.get("description"), r["files"], r["bytes"], r["percent"])
                     for r in e["suffix"]])
            if e["mime"]:
                cur.executemany(
                    "INSERT INTO agg_mime (root_id, root, mime, files, bytes, [percent]) VALUES (?,?,?,?,?,?)",
                    [(rid, rname, r["mime"], r["files"], r["bytes"], r["percent"]) for r in e["mime"]])
            if e["dir"]:
                cur.executemany(
                    "INSERT INTO agg_dir (root_id, root, dir, dir_hash, files, bytes, [percent]) VALUES (?,?,?,?,?,?,?)",
                    [(rid, rname, r["dir"], _rel_hash(r["dir"]), r["files"], r["bytes"], r["percent"]) for r in e["dir"]])
            cur.execute(
                "INSERT INTO agg_meta (root_id, root, total_files, total_bytes, unreadable, depth, built_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (rid, rname, e["total_files"], e["total_bytes"], e["unreadable"], depth, built_at))
        self.conn.commit()

    # --- dropped records ------------------------------------------------
    def put_dropped(self, document: Document) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO dropped (root_id, root, rel_path, rel_hash, dropped_at, document) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (document["root_id"], document["root"], document["rel_path"],
             _rel_hash(document["rel_path"]), document["dropped_at"],
             json.dumps(document, ensure_ascii=False)),
        )
        self.conn.commit()

    def list_dropped(self, root: str | None = None) -> Iterator[Document]:
        where, params = (" WHERE root_id=?", (root_id(root),)) if root is not None else ("", ())
        cur = self.conn.cursor()
        cur.execute(f"SELECT document FROM dropped{where} ORDER BY dropped_at DESC, id DESC", params)
        for (doc_json,) in cur.fetchall():
            yield json.loads(doc_json)

    def purge_dropped(self, before: str) -> int:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM dropped WHERE dropped_at < ?", (before,))
        n = cur.rowcount
        self.conn.commit()
        return n

    def purge_dropped_paths(self, root: str, rel_paths: Iterable[str]) -> int:
        rid, paths = root_id(root), list(rel_paths)
        cur = self.conn.cursor()
        cur.execute("SELECT id, rel_path FROM dropped WHERE root_id=?", (rid,))
        gone = [i for i, rel in cur.fetchall() if any(rel == p or rel.startswith(p + "/") for p in paths)]
        for part in chunks(gone):
            cur.execute(f"DELETE FROM dropped WHERE id IN ({','.join('?' * len(part))})", part)
        self.conn.commit()
        return len(gone)

    # --- sticky redactions ---------------------------------------------
    def _redaction_rows(self, root: str | None = None) -> list[Document]:
        cur = self.conn.cursor()
        cur.execute("SELECT document FROM redactions")
        return [json.loads(d) for (d,) in cur.fetchall()]

    def _redaction_put(self, entry: Document) -> None:
        doc = json.dumps(entry, ensure_ascii=False)
        cur = self.conn.cursor()
        cur.execute(
            "MERGE redactions AS target USING (SELECT ? AS id) AS src ON target.id = src.id "
            "WHEN MATCHED THEN UPDATE SET root_id=?, path_hash=?, document=? "
            "WHEN NOT MATCHED THEN INSERT (id, root_id, path_hash, document) VALUES (?, ?, ?, ?);",
            (entry["id"], entry["root_id"], entry["path_hash"], doc,
             entry["id"], entry["root_id"], entry["path_hash"], doc))
        self.conn.commit()

    def _redaction_remove(self, entry: Document) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM redactions WHERE id=?", (entry["id"],))
        self.conn.commit()

    # --- storage topology ------------------------------------------------
    def _topology_rows(self, store: str) -> list[Document]:
        assert store in self.DOC_STORES
        cur = self.conn.cursor()
        cur.execute(f"SELECT document FROM {store}")
        return [json.loads(d) for (d,) in cur.fetchall()]

    def _topology_put(self, store: str, doc: Document) -> None:
        assert store in self.DOC_STORES
        text = json.dumps(doc, ensure_ascii=False)
        cur = self.conn.cursor()
        cur.execute(
            f"MERGE {store} AS target USING (SELECT ? AS doc_key) AS src ON target.doc_key = src.doc_key "
            "WHEN MATCHED THEN UPDATE SET host=?, scanned_at=?, document=? "
            "WHEN NOT MATCHED THEN INSERT (doc_key, host, scanned_at, document) VALUES (?, ?, ?, ?);",
            (doc["key"], doc["host"], doc.get("scanned_at"), text,
             doc["key"], doc["host"], doc.get("scanned_at"), text))
        self.conn.commit()

    def _topology_remove(self, store: str, key: str) -> None:
        assert store in self.DOC_STORES
        cur = self.conn.cursor()
        cur.execute(f"DELETE FROM {store} WHERE doc_key=?", (key,))
        self.conn.commit()

    # --- root index ----------------------------------------------------
    def put_root_info(self, info: Document) -> None:
        doc = json.dumps(info, ensure_ascii=False)
        rname = info.get("root") or ""
        cur = self.conn.cursor()
        cur.execute(
            "MERGE roots AS target USING (SELECT ? AS root_id) AS src "
            "ON target.root_id = src.root_id "
            "WHEN MATCHED THEN UPDATE SET root=?, document=? "
            "WHEN NOT MATCHED THEN INSERT (root_id, root, document) VALUES (?, ?, ?);",
            (info["root_id"], rname, doc, info["root_id"], rname, doc),
        )
        self.conn.commit()

    def list_root_info(self) -> Iterator[Document]:
        cur = self.conn.cursor()
        cur.execute("SELECT document FROM roots")
        rows = cur.fetchall()
        for (doc_json,) in sorted(rows, key=lambda r: (json.loads(r[0]).get("root") or "")):
            yield json.loads(doc_json)

    def get_root_info(self, root: str) -> Document | None:
        cur = self.conn.cursor()
        cur.execute("SELECT document FROM roots WHERE root_id=?", (root_id(root),))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def delete_root_info(self, root: str) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM roots WHERE root_id=?", (root_id(root),))
        self.conn.commit()

    # --- stored treemaps ---------------------------------------------
    def put_treemap(self, meta: Document, data: Document | None = None) -> None:
        cur = self.conn.cursor()
        m = json.dumps(meta, ensure_ascii=False)
        if data is None:
            cur.execute("UPDATE treemaps SET meta=? WHERE id=?", (m, meta["id"]))
        else:
            d = json.dumps(data, ensure_ascii=False)
            cur.execute(
                "MERGE treemaps AS target USING (SELECT ? AS id) AS src ON target.id = src.id "
                "WHEN MATCHED THEN UPDATE SET root_id=?, meta=?, data=? "
                "WHEN NOT MATCHED THEN INSERT (id, root_id, meta, data) VALUES (?, ?, ?, ?);",
                (meta["id"], meta["root_id"], m, d, meta["id"], meta["root_id"], m, d))
        self.conn.commit()

    def list_treemaps(self, root: str | None = None) -> list[Document]:
        cur = self.conn.cursor()
        if root is None:
            cur.execute("SELECT meta FROM treemaps")
        else:
            cur.execute("SELECT meta FROM treemaps WHERE root_id=?", (root_id(root),))
        return [json.loads(m) for (m,) in cur.fetchall()]

    def get_treemap(self, treemap_id: str) -> tuple[Document, Document] | None:
        cur = self.conn.cursor()
        cur.execute("SELECT meta, data FROM treemaps WHERE id=?", (treemap_id,))
        row = cur.fetchone()
        return (json.loads(row[0]), json.loads(row[1])) if row else None

    def delete_treemap(self, treemap_id: str) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM treemaps WHERE id=?", (treemap_id,))
        self.conn.commit()

    # --- installed programs -------------------------------------------
    def put_program(self, record: Document) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "MERGE programs AS target USING (SELECT ? AS program_id) AS src "
            "ON target.program_id = src.program_id "
            "WHEN MATCHED THEN UPDATE SET document=? "
            "WHEN NOT MATCHED THEN INSERT (program_id, document) VALUES (?, ?);",
            (record["program_id"], json.dumps(record, ensure_ascii=False),
             record["program_id"], json.dumps(record, ensure_ascii=False)),
        )
        self.conn.commit()

    def list_programs(self) -> Iterator[Document]:
        cur = self.conn.cursor()
        cur.execute("SELECT document FROM programs")
        while True:
            rows = cur.fetchmany(500)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def clear_programs(self) -> None:
        cur = self.conn.cursor()
        cur.execute("DELETE FROM programs")
        self.conn.commit()

    # --- samples ---------------------------------------------------
    def add_samples(self, samples: list[Document]) -> None:
        cur = self.conn.cursor()
        cur.executemany(
            "INSERT INTO samples (sample_id, document) SELECT ?, ? "
            "WHERE NOT EXISTS (SELECT 1 FROM samples WHERE sample_id = ?)",
            [(x["sample_id"], json.dumps(x, ensure_ascii=False), x["sample_id"]) for x in samples])
        self.conn.commit()

    def _reader(self) -> Any:
        """A second, autocommit connection for sample lookups: SQL Server
        runs one statement at a time per connection, and samples are looked
        up while a list() of the records is still being read."""
        if getattr(self, "_side_conn", None) is None:
            self._side_conn = self._pyodbc.connect(self.dsn, autocommit=True)
        return self._side_conn

    def get_samples(self, ids: Iterable[str]) -> dict[str, Document]:
        ids = list(ids)
        out: dict[str, Document] = {}
        if not ids:
            return out
        cur = self._reader().cursor()
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            cur.execute(f"SELECT document FROM samples WHERE sample_id IN ({','.join('?' * len(chunk))})",
                        chunk)
            for (doc_json,) in cur.fetchall():
                doc = json.loads(doc_json)
                out[doc["sample_id"]] = doc
        return out

    def set_sample_llm(self, sample_id: str, llm: Document) -> None:
        cur = self.conn.cursor()
        cur.execute("UPDATE samples SET document = JSON_MODIFY(document, '$.llm', JSON_QUERY(?)) "
                    "WHERE sample_id = ?", (json.dumps(llm, ensure_ascii=False), sample_id))
        self.conn.commit()

    def iter_samples(self) -> Iterator[Document]:
        self.flush_samples()
        rows = self.conn.cursor().execute("SELECT document FROM samples").fetchall()
        self.conn.commit()
        for (doc_json,) in rows:
            yield json.loads(doc_json)

    def page_records(self, after: Any, limit: int) -> tuple[list[Document], Any]:
        self.flush()
        cur = self.conn.cursor()
        rows = cur.execute("SELECT TOP (?) id, document FROM files WHERE id > ? ORDER BY id",
                           (limit, after or 0)).fetchall()
        self.conn.commit()
        return [json.loads(d) for _, d in rows], (rows[-1][0] if rows else after)

    def prune_samples(self) -> int:
        self.flush()
        cur = self.conn.cursor()
        cur.execute("DELETE FROM samples WHERE NOT EXISTS (SELECT 1 FROM files f "
                    "WHERE JSON_VALUE(f.document, '$.sample_id') = samples.sample_id)")
        n = cur.rowcount
        self.conn.commit()
        return n

    # --- member sets -------------------------------------------------
    def put_member_set(self, header: Document, rows: list[Document]) -> bool:
        mid = header["members_id"]
        cur = self.conn.cursor()
        old = cur.execute("SELECT JSON_VALUE(document, '$.digest') FROM member_sets WHERE members_id=?",
                          (mid,)).fetchone()
        if old and old[0] == header["digest"]:
            self.conn.commit()
            return False
        cur.execute("DELETE FROM member_sets WHERE members_id=?", (mid,))
        cur.execute("DELETE FROM set_members WHERE members_id=?", (mid,))
        if rows:
            try:
                cur.fast_executemany = True
            except AttributeError:
                pass
            cur.executemany(
                "INSERT INTO set_members (members_id, idx, path, path_hash, size, csize, role, kind, "
                "document) VALUES (?,?,?,?,?,?,?,?,?)",
                [(mid, r["index"], r.get("path"), _rel_hash(r["path"]) if r.get("path") else None,
                  r.get("size"), r.get("csize"), r.get("role"), r.get("kind"),
                  json.dumps({**r, "members_id": mid}, ensure_ascii=False)) for r in rows])
        cur.execute("INSERT INTO member_sets (members_id, document) VALUES (?, ?)",
                    (mid, json.dumps(header, ensure_ascii=False)))
        self.conn.commit()
        return True

    def list_member_set(self, members_id: str) -> Iterator[Document]:
        self.flush()
        cur = self.conn.cursor()
        cur.execute("SELECT document FROM set_members WHERE members_id=? ORDER BY idx", (members_id,))
        while True:
            rows = cur.fetchmany(1000)
            if not rows:
                break
            for (doc_json,) in rows:
                yield json.loads(doc_json)

    def iter_member_sets(self) -> Iterator[Document]:
        self.flush()
        rows = self.conn.cursor().execute("SELECT document FROM member_sets").fetchall()
        self.conn.commit()
        for (doc_json,) in rows:
            yield json.loads(doc_json)

    def prune_member_sets(self) -> int:
        self.flush()
        cur = self.conn.cursor()
        cur.execute("DELETE FROM member_sets WHERE NOT EXISTS (SELECT 1 FROM files f "
                    "WHERE JSON_VALUE(f.document, '$.members_id') = member_sets.members_id)")
        n = cur.rowcount
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
