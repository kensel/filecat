"""Command line. Each subcommand dispatches to `run(args) -> int` in its module."""
from __future__ import annotations

import argparse
import importlib
import os
import sys

from .backends import BACKENDS

COMMANDS = {
    "scan": "filecat.scan",
    "summary": "filecat.summary",
    "show": "filecat.show",
    "programs": "filecat.programs",
    "signatures": "filecat.signatures",
    "import": "filecat.importer",
    "enrich": "filecat.enrich",
    "migrate": "filecat.migrate",
    "members": "filecat.members_cmd",
    "samples": "filecat.samples",
    "member-sets": "filecat.member_sets",
    "mongo-rebuild": "filecat.mongo_rebuild",
    "config": "filecat.config",
    "serve": "filecat.serve",
    "server": "filecat.server",
    "roots": "filecat.roots_cmd",
    "dropped": "filecat.dropped_cmd",
    "backups": "filecat.backups_cmd",
    "databases": "filecat.databases_cmd",
    "dupes": "filecat.dupes_cmd",
    "scan-everything": "filecat.everything",
    "agents": "filecat.agents_cmd",
    "rollups": "filecat.rollups_cmd",
    "storage": "filecat.storage_cmd",
}


def _storage(p: argparse.ArgumentParser) -> None:
    p.add_argument("--backend", choices=BACKENDS, help="default: filecat.toml's backend, else sqlite")
    p.add_argument("--out", help="sqlite catalog file, or jsonl catalog: a directory of per-root files, "
                                 "or one .jsonl file (default catalog-jsonl / catalog.sqlite)")
    p.add_argument("--dsn", help="connection string for server backends (default $FILECAT_DSN)")


def _measure(p: argparse.ArgumentParser) -> None:
    """Options that control how a file is measured (scan and enrich)."""
    p.add_argument("--hash", choices=("auto", "full", "none"), default="auto",
                   help="auto: full SHA-256 up to 64 MiB, partial above")
    p.add_argument("--identify", choices=("local", "always", "never"), default="local",
                   help="run libmagic on the first 8 KiB (local: not on UNC roots)")
    p.add_argument("--timeout", type=float, help="per-entry seconds (default 30 local, 120 UNC)")
    p.add_argument("--workers", type=int, default=4, help="parallel file measurements")
    p.add_argument("--pronom", action="store_true", help="identify with Siegfried (sf) / PRONOM")
    p.add_argument("--trid-defs", dest="trid_defs", metavar="PATH", help="TrID definitions file")
    p.add_argument("--magika", action="store_true", help="Magika for unknown / disagreeing files")
    p.add_argument("--list-zip-cap", dest="list_zip_cap", type=int, default=100)
    p.add_argument("--expand-dat", dest="expand_dat", action="store_true")
    p.add_argument("--member-cap", dest="member_cap", type=int, default=1000,
                   help="x3 .dat members sniffed with --expand-dat")
    p.add_argument("--archive-scan-cap", dest="archive_scan_cap", type=lambda s: int(float(s) * 1024 * 1024),
                   metavar="MIB", help="MiB decompressed to list a .tar.gz/.tar.bz2/.tar.xz (default 64)")
    p.add_argument("--deep-archives", dest="deep_archives", action="store_true",
                   help="decompress compressed tarballs to the end to list every member")
    p.add_argument("--max-members", dest="max_members", type=int, default=100_000,
                   help="member rows stored per archive")
    p.add_argument("--expand-compound", dest="expand_compound", action="store_true",
                   help="store every entry of compound documents (.docx, .jar, ...), "
                        "not only the anomalies")
    p.add_argument("--disk-scan-cap", dest="disk_scan_cap", type=lambda s: int(float(s) * 1024 * 1024),
                   metavar="MIB", help="MiB read per volume for the disk-image content scan "
                                       "(default 8, 0 disables)")
    p.add_argument("--ollama", action="store_true", help="summarise a bounded set of files with Ollama")
    p.add_argument("--model", help="Ollama model name (required with --ollama)")
    p.add_argument("--ollama-url", dest="ollama_url", help="default $OLLAMA_HOST or http://127.0.0.1:11434")
    p.add_argument("--ollama-kinds", dest="ollama_kinds", type=lambda s: s.split(","),
                   help="comma-separated kinds sent to the model (default unknown)")
    p.add_argument("--ollama-max-files", dest="ollama_max_files", type=int, default=200)


def _verify_level(text: str) -> int:
    """--verify-backups=N: 0 and 1 exist; 2 and 3 are refused with what to use instead."""
    try:
        level = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a level (0 or 1)") from None
    if level in (2, 3):
        raise argparse.ArgumentTypeError(
            f"level {level} is not available in v0.2.0 (it needs a per-file check of the store); "
            "use --measure-backups to scan a store per file, or --verify-backups=1 for the totals")
    if level not in (0, 1):
        raise argparse.ArgumentTypeError(f"{level} is not a verify level (0 or 1)")
    return level


def _scan_options(p: argparse.ArgumentParser) -> None:
    """Everything `scan` takes besides its roots (scan and scan-everything)."""
    _storage(p)
    _measure(p)
    p.add_argument("--force", action="store_true", help="remeasure every entry")
    p.add_argument("--no-default-skips", dest="no_default_skips", action="store_true")
    p.add_argument("--measure-backups", dest="measure_backups", action="store_true",
                   help="read and hash the data files of recognised backup stores (ABB pools, "
                        "Windows Backup zips, system-image VHDs, duplicity volumes); by default "
                        "they are recorded from the directory listing only")
    p.add_argument("--verify-backups", dest="verify_backups", nargs="?", const=1, default=None,
                   type=_verify_level, metavar="N",
                   help="how far a backup store is checked against its own manifest: 0 nothing "
                        "(the default; probe.backup.checked is \"none\"), 1 (also a bare "
                        "--verify-backups) the rolled-up data's total bytes and file count "
                        "(checked is \"totals\"). 2 (every file the manifest names exists with its "
                        "size) and 3 (their hashes) are not in v0.2.0; --measure-backups gives "
                        "per-file rows for a store. Veeam's and Google Workspace's own metadata "
                        "checks run from level 1")
    p.add_argument("--measure-databases", dest="measure_databases", action="store_true",
                   help="read and hash the data files of recognised database folders (PostgreSQL, "
                        "MySQL/MariaDB, MongoDB, SQL Server) when they are quiet: unmodified for 90 "
                        "days and at least 1 MiB, or for SQL Server files 1 hour; by default they "
                        "are recorded from the directory listing only")
    p.add_argument("--alias", action="append", metavar="PATH=ROOT",
                   help="read roots under PATH but record them under ROOT, e.g. "
                        "\\\\192.0.2.13=\\\\nas-main (repeatable; also [aliases] in filecat.toml)")
    p.add_argument("--keep-dropped", dest="keep_dropped", type=int, metavar="DAYS",
                   help="records of vanished files are moved to the dropped table and purged "
                        "this many days later (default 90)")
    p.add_argument("--check", dest="check_only", action="store_true",
                   help="only the preflight: open every root, show the account each is read "
                        "with and warn when it differs from the last scan; scan nothing")
    p.add_argument("--exclude", action="append", metavar="PATH",
                   help="folder or file not to scan, e.g. C:\\code\\filecat, or a whole root "
                        "(repeatable; matched as read or as recorded under an alias)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--agent", metavar="NAME",
                   help="read the roots that [[agents]] NAME covers through that agent, even when "
                        "another agent covers them more closely (by default a root is read through "
                        "the agent whose alias or shares match it)")
    g.add_argument("--no-agent", dest="no_agent", action="store_true",
                   help="read every root over SMB, even when an agent covers it")
    p.add_argument("--agent-fallback", dest="agent_fallback", action="store_true",
                   help="a root whose agent cannot be reached is read over SMB instead of failing")
    p.add_argument("--rollup", action="append", metavar="TYPE=MODE",
                   help="override one [rollups] mode for this scan: backup, database, cache, synology, "
                        "windows or redacted = automatic, manual or disabled (repeatable; redacted "
                        "cannot be disabled), e.g. --rollup cache=automatic")
    p.add_argument("--rollup-workers", dest="rollup_workers", type=int, metavar="N",
                   help="threads that sum rolled-up folders on an SMB or local scan (default 4)")
    p.add_argument("--new-redaction-key", dest="new_redaction_key", action="store_true",
                   help="scan although redact.key is missing for the sticky redactions of a root: write a "
                        "new key and leave the old entries to be matched by inode only")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="filecat", description="File catalog for local drives and NAS shares.")
    parser.add_argument("--config", metavar="PATH",
                        help="filecat.toml to use (default $FILECAT_CONFIG, ./filecat.toml, then the user file)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="walk roots and record every file and directory")
    p.add_argument("roots", nargs="+", metavar="ROOT")
    _scan_options(p)

    p = sub.add_parser("scan-everything",
                       help="scan every disk share of the [everything] servers and the local drives")
    p.add_argument("--server", action="append", metavar="SERVER",
                   help="server whose disk shares are scanned (repeatable; replaces [everything])")
    p.add_argument("--drive", action="append", metavar="DRIVE",
                   help="local drive, e.g. C: (repeatable; replaces [everything])")
    p.add_argument("--list", action="store_true", help="print the roots that would be scanned and stop")
    p.add_argument("--unfinished", action="store_true",
                   help="only roots whose last scan did not finish (left in the resume file, never "
                        "scanned, interrupted, failed, unreachable); finished roots are not walked again")
    _scan_options(p)

    p = sub.add_parser("summary", help="WinDirStat-style totals by extension, type and directory")
    _storage(p)
    p.add_argument("--by", action="append", choices=("extension", "mime", "dir"))
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--root", help="limit to one root")
    p.add_argument("--disagree", action="store_true", help="list files whose glob and magic types disagree")
    p.add_argument("--rebuild", action="store_true", help="recompute stored agg_* tables (only --root's when given)")
    p.add_argument("--top", type=int, default=50, help="rows per table (0 = all)")

    p = sub.add_parser("show", help="print one record")
    p.add_argument("rel_path", metavar="REL_PATH")
    p.add_argument("--root", required=True)
    _storage(p)

    p = sub.add_parser("programs", help="inventory installed software on this PC")
    _storage(p)
    p.add_argument("--reg", action="append", metavar="FILE",
                   help="read uninstall keys from a .reg export instead of the live registry")
    p.add_argument("--no-path", dest="no_path", action="store_true")
    p.add_argument("--no-start-menu", dest="no_start_menu", action="store_true")

    p = sub.add_parser("signatures", help="signature database files")
    p.add_argument("action", choices=("status",))
    p.add_argument("--dir", help="signatures directory (default $FILECAT_SIGNATURES or <repo>\\signatures)")

    p = sub.add_parser("import", help="load JSONL listings (PowerShell Get-ChildItem export or filecat jsonl)")
    p.add_argument("files", nargs="+", metavar="FILE")
    _storage(p)
    p.add_argument("--format", choices=("auto", "powershell", "filecat"), default="auto")
    p.add_argument("--root", help="root to record under (default: \\\\server\\share or drive of each path)")
    p.add_argument("--no-dirs", dest="no_dirs", action="store_true",
                   help="do not synthesize directory records from file paths")

    p = sub.add_parser("enrich", help="fill missing hashes, kinds and types on existing records")
    _storage(p)
    _measure(p)
    p.add_argument("--root", action="append", help="limit to these roots (repeatable)")
    p.add_argument("--what", default="names,hash,probe,identify",
                   help="comma list of: names (glob table only, no I/O), hash, probe, identify")
    p.add_argument("--limit", type=int, help="stop after N records")
    p.add_argument("--kind", action="append", help="only records of these kinds")
    p.add_argument("--path-map", dest="path_map", action="append", metavar="ROOT=LOCAL",
                   help="read ROOT's files from LOCAL instead (e.g. a mapped drive)")
    p.add_argument("--alias", action="append", metavar="PATH=ROOT",
                   help="as scan --alias: ROOT's records are read through PATH")
    p.add_argument("--force", action="store_true", help="remeasure even when fields are present")
    p.add_argument("--measure-backups", dest="measure_backups", action="store_true",
                   help="also read the data files of recognised backup stores, which are "
                        "otherwise left as listed")
    p.add_argument("--path", action="append", metavar="GLOB",
                   help="only records whose path in the root matches, e.g. 'Work/*.pdf' or a "
                        "folder like 'Work/DA' (repeatable)")
    p.add_argument("--hydrate", action="store_true",
                   help="also read cloud files that are not on this device (OneDrive/iCloud "
                        "online-only), which downloads each one; narrow it with --path/--root/--limit")
    p.add_argument("--free-after", dest="free_after", action="store_true",
                   help="with --hydrate: mark each downloaded file 'Free up space' again, so the "
                        "provider removes the local copy")

    p = sub.add_parser("migrate", help="copy a catalog from one backend to another")
    p.add_argument("--from", dest="src_backend", choices=BACKENDS, required=True)
    p.add_argument("--from-out", dest="src_out", help="source jsonl/sqlite file")
    p.add_argument("--from-dsn", dest="src_dsn", help="source DSN (server backends)")
    p.add_argument("--to", dest="dst_backend", choices=BACKENDS, required=True)
    p.add_argument("--to-out", dest="dst_out", help="target jsonl/sqlite file")
    p.add_argument("--to-dsn", dest="dst_dsn", help="target DSN (default $FILECAT_DSN)")
    p.add_argument("--root", action="append", help="copy only these roots (repeatable)")
    p.add_argument("--batch", type=int, default=2000)
    p.add_argument("--no-programs", dest="no_programs", action="store_true")
    p.add_argument("--no-members", dest="no_members", action="store_true")
    p.add_argument("--verify", action="store_true", help="re-read every copied record and compare")

    p = sub.add_parser("members", help="list the members recorded for one archive")
    p.add_argument("rel_path", metavar="REL_PATH")
    p.add_argument("--root", required=True)
    _storage(p)
    p.add_argument("--role", action="append", help="only members with these roles")
    p.add_argument("--json", action="store_true", help="one JSON row per line")

    for name, what, help_ in (
            ("samples", "samples", "content-keyed text samples: move inline samples into the samples "
                                   "store, remove those no record names, or count what is there"),
            ("member-sets", "members", "archive members filed by content hash: move the rows of existing "
                                       "archives into member sets, remove sets no record names, or count")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("action", choices=("migrate", "prune", "stats"))
        _storage(p)
        p.add_argument("--batch", type=int, default=1000, help="records per batch (default 1000)")
        p.add_argument("--limit", type=int, help="stop after N records (a trial run; rerun to continue)")
        p.add_argument("--checkpoint", metavar="PATH",
                       help=f"progress file (default <catalog>.{what}-migrate.json, or "
                            f".filecat-<backend>.{what}-migrate.json here for a server)")
        p.add_argument("--progress-interval", dest="progress_interval", type=float, default=5.0)
        p.add_argument("--force", action="store_true", help="prune even while a scan is running")
        if name == "member-sets":
            p.add_argument("--expand-compound", dest="expand_compound", action="store_true",
                           help="keep every entry of compound documents listed before v0.1.1")

    p = sub.add_parser("mongo-rebuild",
                       help="rebuild MongoDB collections in place with zstd compression and the "
                            "partial sha256 index, one at a time")
    _storage(p)
    p.add_argument("--collection", action="append", choices=("files", "members", "samples",
                                                             "member_sets", "set_members"),
                   help="only these collections (repeatable; default all five)")
    p.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="show sizes, compression and what would be rebuilt; change nothing")
    p.add_argument("--force", action="store_true", help="rebuild even while a scan is running")

    p = sub.add_parser("roots", help="root index: last scan, scan in progress, newest file, last error; "
                                     "case-check / case-merge for one share recorded as two roots")
    p.add_argument("action", nargs="?", choices=("list", "case-check", "case-merge"), default="list",
                   help="list (default); case-check: find roots that differ only in the case of "
                        "server\\share and verify a sample of files; case-merge [OLD NEW]: move OLD "
                        "into NEW (NEW's spelling is kept; with no names, every pair whose NAS "
                        "spelling is known)")
    p.add_argument("names", nargs="*", metavar="OLD NEW", help="case-merge: the roots to merge")
    _storage(p)
    p.add_argument("--sample", type=int, default=500, metavar="N",
                   help="case-check / case-merge: files compared to confirm one share, 200..1000 "
                        "(default 500)")
    p.add_argument("--force", action="store_true",
                   help="case-merge: merge although verification fails, a scan is running, or NEW "
                        "is not the NAS's spelling")
    p.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="case-merge: verify and report, move nothing")
    p.add_argument("--root", action="append", help="only these roots (repeatable)")
    p.add_argument("--json", action="store_true", help="one JSON object per root")

    p = sub.add_parser("dropped", help="records of files that vanished from disk (kept 90 days)")
    _storage(p)
    p.add_argument("--root", action="append", help="only these roots (repeatable)")
    p.add_argument("--limit", type=int, default=100, help="rows to print (0 = all; default 100)")
    p.add_argument("--json", action="store_true", help="one JSON document per line")
    p.add_argument("--purge", action="store_true", help="remove entries older than --days now")
    p.add_argument("--days", type=int, default=90, help="age for --purge (default 90; 0 = all)")

    p = sub.add_parser("backups", help="backup stores found by scans: machines, versions, "
                                       "problems, copies and separate jobs of one machine")
    _storage(p)
    p.add_argument("--root", action="append", help="only these roots (repeatable)")
    p.add_argument("--versions", action="store_true", help="list every version, not just the latest")
    p.add_argument("--json", action="store_true", help="one JSON object per store")

    p = sub.add_parser("databases", help="database data folders found by scans (PostgreSQL, MySQL, "
                                         "MongoDB, SQL Server): version, databases, quiet or active")
    _storage(p)
    p.add_argument("--root", action="append", help="only these roots (repeatable)")
    p.add_argument("--json", action="store_true", help="one JSON object per folder")

    p = sub.add_parser("dupes", help="likely duplicates among big files: same size, then a few "
                                     "windows of each file hashed instead of the whole file")
    _storage(p)
    p.add_argument("--root", action="append", help="only these roots (repeatable)")
    p.add_argument("--bands", default="100,50,20,10,1", metavar="GIB,GIB,...",
                   help="size bands, largest first, each lower edge exclusive and upper inclusive; "
                        "files at or below the smallest edge are skipped (default 100,50,20,10,1, "
                        "i.e. >100, 50-100, 20-50, 10-20, 1-10 GiB)")
    p.add_argument("--samples", type=int, default=6,
                   help="windows hashed per file: start, end and evenly spaced between (default 6)")
    p.add_argument("--window", type=float, default=1, metavar="MIB", help="size of each window (default 1)")
    p.add_argument("--full", action="store_true",
                   help="confirm each sparse match with a full SHA-256 (files up to --full-max)")
    p.add_argument("--full-max", dest="full_max", type=float, default=1024, metavar="MIB",
                   help="largest file --full reads whole (default 1024)")
    p.add_argument("--dissect", metavar="EXE", default=os.environ.get("FILECAT_DISSECT"),
                   help="dissect's target-query executable (default $FILECAT_DISSECT): for clusters of "
                        "disk images, list each copy's files from its file system metadata and compare "
                        "path, size and mtime. Run as a separate process, never imported (AGPL). "
                        "Slow: minutes per large image; --top limits which clusters")
    p.add_argument("--include-backups", dest="include_backups", action="store_true",
                   help="also report clusters made only of backup data (generations of one backup, "
                        "copies of a backup folder); by default a backup file is reported only "
                        "when it matches a file outside the backups")
    p.add_argument("--top", type=int, default=100, help="clusters to print, most wasted space first (0 = all)")
    p.add_argument("--workers", type=int, default=4, help="files read in parallel")
    p.add_argument("--path-map", dest="path_map", action="append", metavar="ROOT=LOCAL",
                   help="read ROOT's files from LOCAL instead (e.g. a mapped drive)")
    p.add_argument("--alias", action="append", metavar="PATH=ROOT",
                   help="as scan --alias: ROOT's records are read through PATH")
    p.add_argument("--json", action="store_true", help="one JSON cluster per line")

    p = sub.add_parser("agents", help="filecat-agent hosts from filecat.toml: list them, or check "
                                      "each one's certificate fingerprint, token and protocol")
    asub = p.add_subparsers(dest="action", required=True)
    a = asub.add_parser("list", help="the configured [[agents]], tokens masked")
    a.add_argument("--json", action="store_true", help="one JSON object per agent")
    a = asub.add_parser("test", help="connect to each agent: TLS, fingerprint, hello, token; "
                                     "exit 1 if any fails")
    a.add_argument("names", nargs="*", metavar="NAME", help="agents to test (default: all)")
    a.add_argument("--timeout", type=float, default=5.0, help="seconds per connection and request")
    a.add_argument("--json", action="store_true", help="one JSON object per agent")
    a = asub.add_parser("status", help="hello and capabilities of each agent: version, certificate pin, "
                                       "allowed roots, run ids, and whether its allowlist and deny list "
                                       "are the ones this filecat expects")
    a.add_argument("names", nargs="*", metavar="NAME", help="agents to check (default: all)")
    a.add_argument("--timeout", type=float, default=5.0, help="seconds per connection and request")
    a.add_argument("--json", action="store_true", help="one JSON object per agent")
    a.add_argument("--strict", action="store_true",
                   help="exit 1 on an allowlist/deny list mismatch or any warning too")
    a = asub.add_parser("enroll", help="make a token and print the agent's .env lines and the [[agents]] "
                                       "stanza; fetch the certificate fingerprint once (trust on first use)")
    a.add_argument("name", metavar="NAME")
    a.add_argument("--host", required=True, metavar="HOST[:PORT]", help="the agent's address (default port 9876)")
    a.add_argument("--alias", dest="agent_alias", metavar="\\\\SERVER", help="the server name SMB scans record the shares under")
    a.add_argument("--write", action="store_true",
                   help="append the stanza to filecat.toml (refuses when NAME exists); the token is never written")
    a.add_argument("--cert-sha256", dest="cert_sha256", metavar="HEX",
                   help="use this fingerprint instead of connecting to fetch it")
    a.add_argument("--no-connect", dest="no_connect", action="store_true", help="do not connect to the agent")
    a.add_argument("--timeout", type=float, default=5.0, help="seconds to connect")
    a = asub.add_parser("fingerprint", help="print the certificate fingerprint the agent at HOST[:PORT] presents")
    a.add_argument("target", metavar="HOST[:PORT]")
    a.add_argument("--timeout", type=float, default=5.0, help="seconds to connect")

    p = sub.add_parser("rollups", help="rollup groups: the rules and modes in force, what the catalog "
                                       "holds, what a scan would suggest, and the sticky redactions")
    rsub = p.add_subparsers(dest="action", required=True)
    r = rsub.add_parser("rules", help="the built-in rules with each type's mode, and the user's rules "
                                      "(counts, never patterns)")
    r.add_argument("--json", action="store_true", help="one JSON object")
    r = rsub.add_parser("list", help="the rollup records in the catalog: counts by tag and parent folder")
    _storage(r)
    r.add_argument("--root", action="append", help="only these roots (repeatable)")
    r.add_argument("--json", action="store_true", help="one JSON object per root")
    r = rsub.add_parser("suggest", help="folders a built-in rule of a type that is not automatic would "
                                        "match, found by the last complete scan of each root")
    _storage(r)
    r.add_argument("--root", action="append", help="only these roots (repeatable)")
    r.add_argument("--json", action="store_true", help="one JSON object per root")
    r = rsub.add_parser("migrate", help="turn the rows an existing catalog holds for what rollups now "
                                        "replace (stores' bulk folders, what the rules match) into rollups, "
                                        "without a rescan; safe to stop and run again")
    _storage(r)
    r.add_argument("--tags", nargs="+", metavar="TAG", help="only these tags, e.g. [BACKUP] [REDACTED]")
    r.add_argument("--root", action="append", help="only these roots (repeatable)")
    r.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="report, per target, the rows and bytes and the rollup it would write; change nothing")
    r.add_argument("--batch", type=int, default=1000, metavar="N", help="rows per page and per delete (max 1000)")
    r.add_argument("--checkpoint", metavar="FILE", help="where to report where a run stopped "
                                                          "(default beside the catalog)")
    r.add_argument("--progress-interval", dest="progress_interval", type=float, default=5.0, metavar="SECONDS")
    r.add_argument("--rollup", action="append", metavar="TYPE=MODE",
                   help="override one [rollups] mode for this run, e.g. --rollup backup=automatic")
    r.add_argument("--new-redaction-key", dest="new_redaction_key", action="store_true",
                   help="proceed although redact.key is missing for existing sticky redactions")
    red = rsub.add_parser("redacted", help="sticky redactions: list them, or release one in two steps")
    dsub = red.add_subparsers(dest="redacted_action", required=True)
    r = dsub.add_parser("list", help="ids, status, folder they sit in and counts; never names or hashes")
    _storage(r)
    r.add_argument("--root", action="append", help="only these roots (repeatable)")
    r.add_argument("--json", action="store_true", help="one JSON object per entry")
    r = dsub.add_parser("release", help="step one: mark a redacted folder pending (still redacted)")
    r.add_argument("path", metavar="PATH", help="the folder, as a UNC, local or agent path")
    _storage(r)
    r = dsub.add_parser("approve", help="step two, a separate command: forget a pending redaction, so "
                                        "the next scan lists the folder unless a marker or rule matches")
    r.add_argument("ref", metavar="PATH_OR_ID")
    r.add_argument("--yes", action="store_true", help="do not ask (required without a terminal)")
    _storage(r)

    p = sub.add_parser("storage", help="the storage topology of the hosts: collect it through the agents, "
                                       "show what is stored, check the links between hosts")
    ssub = p.add_subparsers(dest="action", required=True)
    s = ssub.add_parser("collect", help="read each [[agents]] host's raw storage sources, build the "
                                        "topology in Python and store it in the catalog (a history row "
                                        "when the structure changed); exit 1 if an agent fails")
    s.add_argument("--agent", metavar="NAME", help="only this [[agents]] host")
    s.add_argument("--platform", choices=("synology", "linux"),
                   help="collector to use (default: detected from the host)")
    s.add_argument("--measure-shares", dest="measure_shares", action="store_true",
                   help="also sum each share with the agent for its used bytes (minutes on a big share)")
    s.add_argument("--dry-run", dest="dry_run", action="store_true", help="collect and validate, store nothing")
    s.add_argument("--json", action="store_true", help="one JSON object per agent")
    _storage(s)
    s = ssub.add_parser("show", help="the stored snapshots and the hosts written by hand; with a host, "
                                     "its hierarchy from the disks up to the shares and LUNs")
    s.add_argument("host", nargs="?", metavar="HOST")
    s.add_argument("--json", action="store_true", help="JSON instead of text")
    _storage(s)
    s = ssub.add_parser("links", help="the [[storage.hosts]] and [[storage.links]], resolved over the stored "
                                      "snapshots (or --snapshot files); exit 1 if a link is unresolved "
                                      "or in conflict")
    s.add_argument("--snapshot", action="append", metavar="FILE",
                   help="a saved topology (or a reply holding one); repeat for each host; used instead "
                        "of the stored snapshots")
    s.add_argument("--json", action="store_true", help="one JSON object")
    _storage(s)

    p = sub.add_parser("server", help="the coordinator: checks the agents' health and runs the scheduled "
                                      "[[server.jobs]] (scans, storage collects, store re-sums), records "
                                      "every run in the catalog; --serve also runs the web viewer")
    _storage(p)
    p.add_argument("--serve", nargs="?", const="", default=None, metavar="HOST:PORT",
                   help="also run the web viewer in this process (default 127.0.0.1:8765, or [server] serve); "
                        "it gets live /api/agents and /api/jobs")
    p.add_argument("--once", action="store_true",
                   help="run every job that is due now once, then exit (for Task Scheduler or cron)")
    p.add_argument("--job", action="append", metavar="NAME",
                   help="with --once: run this job whatever its schedule says (repeatable)")
    p.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="print the plan (agents, jobs, next due times) and exit; touches nothing")

    p = sub.add_parser("serve", help="web viewer: browse the summary and drill into the records")
    _storage(p)
    p.add_argument("--host", default="127.0.0.1", help="address to bind (default 127.0.0.1; no auth)")
    p.add_argument("--port", type=int, default=8765, help="port (default 8765, 0 = any free port)")
    p.add_argument("--open", action="store_true", help="open the page in the default browser")
    p.add_argument("--quiet", action="store_true", help="do not log each request")
    p.add_argument("--no-save", dest="no_save", action="store_true",
                   help="never write: do not save computed summaries to the catalog")
    p.add_argument("--graph-max-age", dest="graph_max_age", type=float, default=120, metavar="MINUTES",
                   help="reuse a saved Graph treemap until it is this old (default 120)")

    p = sub.add_parser("config", help="write, show and test filecat.toml (backends, DSNs, Ollama)")
    csub = p.add_subparsers(dest="action", required=True)
    c = csub.add_parser("init", help="write a commented filecat.toml, detecting local database servers")
    c.add_argument("--path", help="file to write (default ./filecat.toml)")
    c.add_argument("--user", action="store_true", help="write the per-user file instead")
    c.add_argument("--backend", choices=BACKENDS, help="default backend to record (default sqlite)")
    c.add_argument("--dsn", help="DSN for --backend (a server backend)")
    c.add_argument("--out", help="catalog file for --backend jsonl/sqlite")
    c.add_argument("--model", help="Ollama model (default gemma4:31b-cloud)")
    c.add_argument("--no-detect", dest="no_detect", action="store_true",
                   help="do not probe 127.0.0.1 for PostgreSQL/MySQL/SQL Server/MongoDB")
    c.add_argument("--force", action="store_true", help="overwrite an existing file")
    c.add_argument("--stdout", action="store_true", help="print the file instead of writing it")
    c = csub.add_parser("show", help="the config file in use and the effective settings")
    c.add_argument("--reveal", action="store_true", help="do not mask passwords")
    for action, text in (("test", "read-only connection check for each configured backend"),
                         ("verify", "test, then create the schema and write/read/delete one record")):
        c = csub.add_parser(action, help=text)
        c.add_argument("targets", nargs="*", metavar="TARGET",
                       help=f"{', '.join(BACKENDS)} or ollama (default: every configured one)")
        c.add_argument("--dsn", help="test this DSN instead (one server TARGET)")
        c.add_argument("--out", help="test this file instead (one jsonl/sqlite TARGET)")
        c.add_argument("--timeout", type=float, default=5.0, help="seconds per connection")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    # a bare --verify-backups means level 1; argparse would take the next word (a ROOT) as its level
    argv = ["--verify-backups=1" if a == "--verify-backups" else a
            for a in (sys.argv[1:] if argv is None else argv)]
    args = build_parser().parse_args(argv)
    if args.command != "config":
        from . import config
        try:
            config.apply(args, config.load(config.find(args.config)))
        except config.ConfigError as exc:
            print(f"filecat: {exc}", file=sys.stderr)
            return 2
    if getattr(args, "ollama", False) and not getattr(args, "model", None):
        print("filecat: --model is required with --ollama", file=sys.stderr)
        return 2
    if "rollup" in (getattr(args, "ollama_kinds", None) or []):
        print("filecat: --ollama-kinds: a rollup is not a file; there is nothing to summarise", file=sys.stderr)
        return 2
    module = importlib.import_module(COMMANDS[args.command])
    try:
        return int(module.run(args) or 0)
    except KeyboardInterrupt:
        # The scan has already marked the root interrupted and saved its
        # resume file on the way out (scan_roots' handlers and finally).
        hint = {"scan": "; run the same command again to resume where it stopped",
                "scan-everything": "; run it again with --unfinished to resume only the roots "
                                   "that have not finished"}.get(args.command, "")
        print(f"\nfilecat: Ctrl+C pressed, {args.command} stopped{hint}", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
