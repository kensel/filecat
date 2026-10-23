# Rollup groups

Design for the rollup groups of research note
[01](research/01-rollup-groups-privacy-indexing.md) and the backup-store
rollups of note [05, section 3](research/05-catalog-tuning-agent-boundary.md):
`[BACKUP]`, `[REDACTED]`, `[CACHE]`, `[SYNOLOGY]` (plus `[WINDOWS]`,
`[DATABASE]` and tags the user defines). A rollup stands for a set of files
and folders that the catalog counts but does not list: one record holds their
totals and none of their names.

This page settles the record, the rules, the privacy guarantees, the
reports, the cost and the agent contract, so that the Rust agent can be
written once and the Python side implemented from it (section 9). Where this
page and the research notes disagree, this page wins; the wire details live
in [agent-protocol.md](agent-protocol.md), which was updated to match.

Contents: [1 Record](#1-the-rollup-record) - [2 Rules](#2-rules) -
[3 REDACTED](#3-redacted-privacy-guarantees) - [4 BACKUP and DATABASE](#4-backup-and-database-stores) -
[5 Default tags](#5-default-tags) - [6 Reporting](#6-reporting-and-measures) -
[7 Cost](#7-cost-change-detection-progress-cancellation) - [8 Agent](#8-what-the-agent-must-provide) -
[9 Python work plan](#9-python-work-plan) - [10 Open questions](#10-open-questions)

## 1. The rollup record

### Identity

`kind: "rollup"`, one record per (parent directory, tag): every child of a
directory that a rule sends to `[CACHE]` is folded into the one record
`<parent>/[CACHE]` (`rel_path`; the UNC form is `<parent>\[CACHE]`). The
record is written like any other: `put()` replaces the stored record of the
same `(root_id, rel_path)`, so a rescan replaces it whole.

```json
{"root_id": "...", "root": "\\\\nas-main\\homes",
 "rel_path": "jdoe/[CACHE]", "name": "[CACHE]", "kind": "rollup", "suffix": "",
 "size": 48291049216, "allocated_size": 48295198720, "mtime_ns": 1761001200000000000,
 "probe": {"unc": "...",
   "rollup": {"tag": "[CACHE]", "rule": "builtin:cache", "matched": 3,
              "total_files": 14820, "total_dirs": 312,
              "newest_mtime_ns": 1761001200000000000, "oldest_mtime_ns": 1500000000000000000,
              "errors": 0, "error_codes": {}, "vanished": 0, "skipped_mounts": 0,
              "hardlink_names": 0, "partial": false,
              "via": "agent", "summed_at": "2026-10-23T09:00:00+00:00", "policy": "a1b2c3d4e5f6"}}}
```

| Field | Meaning |
|---|---|
| `size` | logical bytes of everything folded in, a hard-linked file once per `(dev, ino)` within the record |
| `allocated_size` | `st_blocks * 512` of the same set (agent only; omitted for SMB and local sums) |
| `mtime_ns` | the newest mtime of any non-directory entry inside (0 when none); `ctime_ns`, `ino`, `dev`, `nlink` are never set |
| `rollup.tag` | the tag, canonical upper case |
| `rollup.rule` | which rule made it: `user:<n>` (index in `[[rollups.rule]]`), `builtin:<tag>`, `store:<format id>`. Never the patterns |
| `rollup.matched` | children of the parent folded in (a name pattern matching 3 folders: 3) |
| `rollup.total_files` | names that are not directories (files, links, specials), hard links counted per name |
| `rollup.total_dirs` | directories inside, the matched ones included (see below) |
| `rollup.newest_mtime_ns`, `oldest_mtime_ns` | over non-directory entries; `oldest_mtime_ns` is left out when `total_files` is 0 |
| `rollup.errors` | entries or folders that could not be read (denied included); the totals are then a lower bound |
| `rollup.error_codes` | `{code: count}` with the protocol's codes (`permission_denied`, `io`): codes only, never names or messages |
| `rollup.vanished` | entries that disappeared during the sum (not errors) |
| `rollup.skipped_mounts` | folders on another file system (agent) or reparse points to folders (Python) that were not entered |
| `rollup.hardlink_names` | names beyond the first of a hard-linked file, whose size was not added again (agent; absent for Python sums) |
| `rollup.partial` | true when `errors > 0`; the record is a lower bound |
| `rollup.via`, `summed_at`, `policy` | `agent` or `python`; when; the rule-set id (section 2) it was made under |
| `rollup.store` | `[BACKUP]` and `[DATABASE]` only: `{"format": id, "path": rel_path of the store}` |
| `rollup.fp` | stores only: the fingerprint of section 7 |

`total_dirs` counts every directory in the summed trees, the matched ones
included (a folded `node_modules` is one directory plus its subfolders), and
`sum_subtree` counts the folder it is given the same way (the earlier draft of
the protocol did not), so the agent, Python and a store's `sum_subtree` agree. The record carries a standard `errors` entry
(`{"stage": "rollup", "message": "..."}`, no names) only when some failure
other than `permission_denied` happened (section 3.4), so an expected
`System Volume Information` does not turn every scan's exit code into 1.

A record has no children: nothing is stored beneath `<parent>/[TAG]` and no
record names a file inside it. A directory record's `size` stays 0, so a
parent's own record never double counts what its rollup holds.

### The `[TAG]` name cannot collide with a real child

A tag has the form `\[[A-Z][A-Z0-9_-]{0,31}\]` (brackets, upper case first
letter, then upper case, digits, `_`, `-`; at most 34 characters). A real
entry can be named `[CACHE]` on every file system filecat reads. The rule:

- Tag names are reserved in a folder that gets a rollup with that tag. A real
  child whose name equals the tag, ignoring ASCII case, is **folded into that
  rollup** like any other match (`rollup.matched` counts it) and is never
  recorded under its own name.
- A real `[CACHE]` in a folder where no rule produces a `[CACHE]` rollup is
  an ordinary entry. If a later scan starts producing the rollup there, the
  stored record at that path is replaced by the rollup and everything stored
  beneath it is deleted (hard delete, section 3.5) as stale.
- Because the tag has an upper case letter, and `suffix_of()` lower-cases
  every extension, no extension and no file name pattern the catalog derives
  can equal a tag.

### Aggregates, summaries and the other readers

A rollup is not a file. The single predicate is `record.NON_FILE_KINDS =
("dir", "rollup")`; wherever the code says `kind != "dir"` to mean "a file",
it means `kind NOT IN NON_FILE_KINDS`:

| Reader | Behaviour |
|---|---|
| `aggregate.build_aggregates`, the SQL `rebuild_aggregates` of every backend | skip rollups: the extension, type and directory tables, `total_files`, `total_bytes`, `unreadable` and the percent base are for recorded files only |
| new `Backend.rollup_totals(root=None)` | `{root: [{tag, folders, matched, total_files, total_dirs, size, allocated_size, newest_mtime_ns, oldest_mtime_ns, errors, partial}]}` summed over `kind = "rollup"` records (few; the `kind` column is indexed). `filecat summary`, `roots` and `serve` use it. Nothing is stored; there is no `agg_rollup` table |
| `browse.matches` / `sql_where` `files_only`, `unreadable` | exclude rollups. `kind=rollup` selects them; `parent=` lists them beside the folder's other children (after the folders) |
| `browse.subtree_documents`, `sql_subtree`, Mongo `subtree` | `bytes` and `files` stay recorded files; each row gains `rollup_bytes` (and `rollup_files`) so a folder's total is `bytes + rollup_bytes` |
| `browse.size_rows`, `sql_sizes`, `Backend.sizes` | exclude rollups; the treemap gets them from the new `Backend.rollups(root, prefix)` (below) |
| `Backend.list_sized`, `dupes_cmd.find_duplicates`, Mongo `query kind != dir` | exclude rollups |
| `enrich.needs` | `NO_CONTENT_KINDS` gains `"rollup"`; `enrich` never opens one, whatever `--force`, `--what` or `--measure-backups` say. Rollups have no `names` stage either |
| `ollama` | `ollama_kinds` is a whitelist; "rollup" is rejected in config validation |
| `samples`, `member_sets` | no hash, no sample, no members: never touched. `samples prune` / `member-sets prune` need no change |
| `rootcase` sampling | rollups are left out of the case-check sample (a rollup is a time-dependent sum) |
| `rootinfo.ScanTracker._observe` | counts a rollup in `rollups` and `rollup_bytes` (new progress and `last_scan` fields), not in `files`, `dirs` or `bytes` |
| `programs`, `importer`, `show` | unaffected (`show` prints the record) |

No double counting: nothing is recorded beneath a rollup and the parent
directory record has size 0, so `bytes` (recorded files) and `rollup_bytes`
are disjoint by construction. The one real overlap is a file reachable by two
paths (hard links, handled per rollup) and a share that is also another root
(`\\nas-main\homes` and `\\nas-main\homes\jdoe` as separate roots); that
exists for ordinary files too and is not changed here.

`Backend.rollups(root, prefix) -> Iterator[Document]` yields the rollup
documents beneath `prefix` (`kind = 'rollup'` and `rel_path` prefix), full
documents, because the treemap and the inspector card need `probe.rollup`.

### Treemap tiles and snapshot pins

`treemap.build(rows, prefix, depth, rollups=())` draws a rollup as a tile of
its own, named by the rollup's path:

- A rollup whose path (`parent/[TAG]`) has at most `depth` components below
  `prefix` is a folder entry with `path` = that path, `files` = `total_files`,
  `bytes` = `size`, and an extra `"rollup": {"tag", "matched", "total_dirs",
  "allocated_size", "newest_mtime_ns", "oldest_mtime_ns", "partial"}`. Its
  extension and type splits are one cell, the tag, so the existing colouring
  gives each tag a colour (`keys.suffix` and `keys.mime` gain the tag).
- A deeper one is added to the folder `folder_of()` gives its parent, as a
  file would be, and is visible only in that folder's own treemap.
- The treemap's `files` and `bytes` totals include rollups, so a share's tile
  matches `du`.

Snapshot pins need no change: a pin diff matches tiles by `(root, folder
path)`, and `[CACHE]`'s path is stable between snapshots. A rollup absent
from an older snapshot shows as "new" in the first comparison, which is
correct. `MAX_FOLDERS` merging treats a rollup like a folder; a merged
`...` entry keeps no `rollup` key. Clicking a rollup tile does not zoom (there
is nothing beneath it); it opens the inspector card (section 6).

### Rescans replace and clean up

- Each scan builds the rollup of a folder from scratch (section 7 for the one
  exception, store fingerprints) and `put()`s it over the old one.
- The walker's stale-child pass (`_delete_stale_children`) compares the stored
  children of a changed folder with `current`. `current` is now: names of
  recorded entries plus the names of the rollup records produced here. A
  stored `[CACHE]` record not produced this time is deleted (plain
  `Backend.delete`; a rollup is not a vanished file and does not go to the
  dropped store). A stored entry whose name is now rolled up, and everything
  beneath it, is deleted with the new `Backend.delete_many` (a hard delete, not
  `drop_many`) for every tag, not only `[REDACTED]`: those rows are not gone
  from disk, they are replaced, and moving 500,000 of them to the dropped
  store would be both slow and a leak for `[REDACTED]`.
- Rule changes. The rule-set id (`policy`, a 12 hex digit hash of the
  effective ordered rules, section 2) is stored on the root's directory
  record as `probe.rollup_policy`. When it differs from the current one the
  scan treats every directory as changed (`unchanged = False`, resume markers
  ignored via `resume.forget_root`) so every folder is listed and its stale
  children deleted. Files that match their stored size and mtime are still not
  remeasured. A scan under an unchanged policy keeps today's behaviour.
- A rollup shrinking to nothing (the matched folder was deleted): the parent's
  listing no longer matches anything, no rollup is produced, the stored one is
  stale and deleted by the same pass. If the parent's mtime did not move
  (`unchanged = True`), the stale pass is skipped as for files today; the
  rollup is replaced anyway the next time the folder changes. To close that
  gap `_make_frame` also sets `unchanged = False` when the folder has a stored
  rollup child (the `get_stats` call already reads `[TAG]` names for the
  tags in play) whose tag is not produced this scan.

## 2. Rules

### Where rules come from

A scan uses one ordered list of rules, first match wins:

1. `exclude` (`--exclude`, `[[agents]].exclude`): hard exclusion, as today.
   An excluded path is neither walked nor counted and is never rolled up.
2. User rules: `[[rollups.rule]]` tables of `filecat.toml`, in file order.
3. Store rollups (section 4): the data pool of a detected backup or database
   store.
4. Built-in rules (section 5), unless switched off.

```toml
[rollups]
defaults  = true       # built-in [CACHE], [SYNOLOGY] and (with default skips) [WINDOWS] rules
backups   = true       # roll up backup store data pools   (--rollup-backups / --no-rollup-backups)
databases = true       # roll up database data folders     (--rollup-databases / --no-rollup-databases)
store_resum = "30d"    # at most this long a store's rollup is carried forward when its fingerprint is unchanged
manifest_cap = "256MiB"  # largest manifest file copied through an agent (section 4)

[[rollups.rule]]
tag   = "[REDACTED]"
match = ['\\nas-main\project\private-project', '\\nas-main\homes\jdoe\vault']

[[rollups.rule]]
tag   = "[CACHE]"
match = ["node_modules", "**/AppData/Local/Temp"]
type  = "dir"          # any (default), dir or file
case  = "insensitive"  # default; or sensitive

[[rollups.rule]]
keep  = true           # no tag: matching entries are walked normally, no later rule is tried
match = ["**/keep/node_modules"]
```

`private = true` on a rule applies the `[REDACTED]` guarantees (section 3) to
any tag; `tag = "[REDACTED]"` implies it. `--no-default-rollups` is
`defaults = false`. A user rule can win over a built-in one (first match),
and a `keep` rule opts a path out of a built-in rule or a later user rule.

**`[[agents]].rollup_groups` is removed.** It was never used by a scan (the
walker skipped rollup entries), its patterns were POSIX with a `*` that
crossed `/`, and one global list is what makes a rule mean the same through an
agent and over SMB. A configuration that still has it is an error naming
`[[rollups.rule]]`. `[[agents]].exclude` stays (an agent-specific hard
exclude in POSIX terms, sent as the policy's `exclude`).

### Pattern semantics

A pattern is matched against one **match path** (`mpath`), derived from the
catalog path and independent of how the tree is read:

| Root as recorded | mpath of an entry |
|---|---|
| `\\nas-main\project`, rel `a/b` | `nas-main/project/a/b` |
| `C:\`, rel `Users/x` | `C:/Users/x` |
| `D:\data`, rel `a` | `D:/data/a` |
| `/mnt/data` (Python on Linux), rel `a` | `/mnt/data/a` |

(Backslashes become `/`; the leading `\\` of a UNC root is dropped; the
recorded root is used, so an alias such as `\\nas-main` standing for
`\\192.0.2.13` matches as `nas-main`.) The same string is built by Python for
an SMB or local walk and sent to the agent as a prefix (section 8), so an
agent scan and an SMB scan of one share give one mpath for one file.

Writing a pattern: copy the path the catalog shows (`filecat show`, the web
viewer) and use it. Patterns are normalised first: `\` becomes `/`, a leading
`//` is dropped, repeated `/` collapse, a trailing `/` means "directories
only" (the same as `type = "dir"`).

- **Name pattern**: no `/` after normalisation (`node_modules`, `*.tmp`,
  `@eaDir`). Matches an entry whose **name** matches, at any depth.
- **Path pattern**: contains a `/`. Matches the entry's whole **mpath**,
  anchored at both ends (`nas-main/project/private-project`). It does not
  match "anywhere": to match at any depth begin with `**/`
  (`**/AppData/Local/Temp`).
- Wildcards, and only these: `?` one character that is not `/`; `*` any run
  of characters that is not `/`; `**` as a whole component, zero or more
  components (`a/**/b` matches `a/b` and `a/x/y/b`). `x/**` matches what is
  inside `x` but not `x` itself, so `\\nas\s\x\**` rolls up each child of `x`
  into `x/[TAG]`, where `\\nas\s\x` rolls up `x` into the parent's `[TAG]`.
  There are no character classes and no escapes: `[` is an ordinary
  character in a pattern, so a folder `[x]` is matched by writing `[x]`; a
  name that contains a literal `*` or `?` cannot be matched exactly (such
  names do not exist on Windows or SMB).
- **Case**: ASCII letters compare without regard to case; any other
  character must be equal (no Unicode folding, no normalisation of NFC and
  NFD, so Python and Rust agree byte for byte). `case = "sensitive"` makes
  the whole rule exact. The default favours Windows and SMB, and on a Linux
  NAS errs towards rolling up too much, which for `[REDACTED]` is the safe
  direction.
- **Type**: `type = "dir"` (or a trailing `/`) matches directories only,
  `file` matches non-directories (links and specials count as files), `any`
  both. A link is matched by its own name and is never followed.
- **Order**: rules are tried in order for each entry, first match wins. The
  matched entry is then not entered, so a rule can never apply inside what an
  earlier rule took, and an outer match always wins over an inner one (a
  `[REDACTED]` folder inside a `node_modules` is part of `[CACHE]`, which
  holds no names either).
- **Exclude first**: an entry that matches `exclude` is skipped before any
  rule is tried. Default skips are not a separate stage any more: section 5.

A conformance file, `tests/data/rollup_match_vectors.json` (`{rules, mpath,
is_dir} -> tag | null`, `{rules} -> policy_id`), is read by the Python
tests and copied into the agent's test suite; the matcher is the one place
where the two implementations can drift.

### The rule-set id

`policy_id` is the first 12 hex digits of the SHA-256 of the canonical JSON
of the effective rules after step 2 and 4 (users', then built-ins; tags and
patterns normalised): an array of `{"tag", "match", "type", "case", "keep",
"private"}` in that key order, compact separators, UTF-8. Store rollups are not in it (they
come from detection). It goes on the root's directory record
(`probe.rollup_policy`), on every rollup (`rollup.policy`), is returned by the
agent's `configure_policy` and `list_dir`, and is compared by the client after
`configure_policy` (a mismatch means the two matchers read the rules
differently: the scan fails for that root before it lists anything). 48 bits
are enough to detect a change, and too few to be a useful oracle for guessing
a hidden pattern list.

## 3. [REDACTED] privacy guarantees

The promise: the name of a redacted folder or file, the names beneath it, and
anything derived from them (hashes, extensions, sizes of individual files,
the counts of its children by type) never appear in the places below. What
does appear: the parent folder's path, the tag, and the totals of section 1.

### 3.1 Where names must not appear

Records (including `errors`), the dropped store, archive members, member sets
and samples of redacted files, the root index (`last_error`, `newest_file`,
`last_attempt.progress.last_path`), resume state, treemap snapshots, logs and
progress lines, preflight output, exceptions and tracebacks, checkpoint
files, the agent's wire messages (agent scans), and the agent's own log.

### 3.2 SMB and local scans

Python computes the rollup itself, and names exist only transiently in memory:

1. **Never listed ahead, never recorded.** In `_make_frame` the folder's
   entries are partitioned by the rule set into recorded entries and rolled
   entries. Rolled entries are removed from `frame.entries` before anything
   else reads them: `child_count` (`probe.child_count` is the number of
   recorded entries plus the number of rollup records, the same number the
   agent's listing yields), `resume.mark_dir_complete(child_dirs=...)`,
   `get_stats` lookups, store detection and `_delete_stale_children` see only
   the recorded ones. `_will_enter` (the read-ahead) applies the same
   partition, so a redacted folder is never listed by a background thread.
2. **A separate summing function.** `rollup.sum_tree(path, *, one_fs, private,
   deadline, cancel, progress)` in the new `rollup.py`: an iterative
   `os.scandir` walk with `entry.stat(follow_symlinks=False)` that keeps only
   integers. No path string is passed to a callback, a log call, or an
   exception. It never calls `record.add_error`, `str(exc)` or `repr(exc)`.
3. **Errors without names.** Every `OSError` is caught at the call that raised
   it (`scandir`, `stat`), classified from `exc.errno` / `winerror` into the
   protocol's codes (`permission_denied`, `not_found` counted as `vanished`,
   everything else `io`), counted in `errors` / `error_codes`, and dropped.
   An `OSError` message contains the file name (`[WinError 5] Access is
   denied: 'C:\\x\\secret'`), so the exception object is never formatted,
   chained or re-raised. A non-`OSError` from the summing code is wrapped as
   `RollupError("rollup failed")` raised `from None` (no `__cause__`, no
   context). The walker puts only a counts-only message in the record:
   `"3 entries could not be read (permission_denied 2, io 1); the totals are
   a lower bound"`.
4. **Progress.** The progress callback gets the rollup's own path
   (`<parent>\[REDACTED]`), never the matched child's. `_Progress.last_path`
   and `ScanTracker.last_path` are therefore safe. A sum that takes long
   reports counters only (entries so far), at the progress interval.
5. **No threads leak.** Python sums run in a pool of `rollup_workers` threads
   (default 4); a worker's exception is reduced by the rule in 3 before it
   crosses the future. `faulthandler`/KeyboardInterrupt tracebacks print
   source lines, not locals, and the summing code holds names only in locals.
6. **Nothing is opened.** `sum_tree` only lists and `lstat`s: no probe, no
   identify, no hash, no sample, no member list, no Ollama.
7. **Hard links** on Windows are not detected (`DirEntry.stat()` has no
   `st_nlink`/`st_ino`); `hardlink_names` is left out and the record says
   `via: "python"`. `allocated_size` is also left out.

### 3.3 Agent scans

- The agent matches the rules itself (it receives the `rules` and one `base`
  per scanned root, section 8) and sums locally. `list_dir` returns the
  unmatched children and one rollup entry per tag; the names of matched
  children are not in the response. `sum_subtree` with `private: true` reports
  counters only.
- Rollup entries and `sum_subtree` replies carry no path, no name and no
  error message text; only counters and `{code: count}`. A rollup's `error`
  never exists; failures inside a rollup are counted.
- `private: true` rules additionally forbid every optional breakdown (no
  `by_suffix`, no sub-folder list) and forbid logging: the agent's log never
  mentions a path while summing under a private rule (an `EACCES` on
  `/volume1/project/private/x` is a counter, not a log line).
- The client sends rules once per connection and per root (`configure_policy`
  replaces the policy), so a long-lived connection never holds a stale rule
  set; `list_dir` replies carry `policy_id` so the client can check.

### 3.4 The config names the redacted paths

The patterns are in `filecat.toml`, a local file next to the credentials it
already holds (agent tokens, DSNs). Recommendation: **accept plaintext
patterns, and keep them out of everything else.**

- The catalog stores `policy` (a truncated hash), the rule indexes and counts,
  never a pattern.
- `filecat config show`, `filecat agents list`, error messages from config
  validation, and the start line print `[REDACTED]: 2 patterns` for a private
  rule, not the patterns.
- The patterns are sent to the agent over the pinned TLS channel and the
  agent keeps them in memory only (they are not logged or written).
- Hashed name patterns (`sha256:<hex>` matching the hash of a name) would
  keep names out of the config as well, but cannot express path patterns or
  wildcards and cost a hash per directory entry in the agent; not in
  v0.2.0 (open question 2).

### 3.5 A redacted path inside an already-cataloged tree

Existing records are purged, never moved to the dropped store:

- **On the next scan**: the policy-change rule of section 1 re-lists every
  folder; the stale pass uses `Backend.delete_many` for every name that is now
  rolled up (and for the tree beneath it), deletes their archive members and
  member-set references, and writes the rollup. The root's `rollup_policy` is
  updated only after the root's walk finished, so an interrupted scan repeats
  the purge.
- **Without a scan**: `filecat rollups migrate --tags [REDACTED]` (section 4.4
  and 9) evaluates the current rules against the stored `rel_path`s, builds the
  rollup from the stored records beneath each match, then deletes them. It
  also cleans the other places (below). A scan that follows finds nothing to
  do.

Both then run the same cleanup, which is the part that catches the places a
plain record delete misses:

| Place | Cleanup |
|---|---|
| `dropped` store | entries of this root under a purged path are deleted (`Backend.purge_dropped_paths(root, rel_paths)`, new) |
| samples, member sets | `samples prune` and `member-sets prune` run at the end (they drop what no record names any more). The command reports it |
| treemap snapshots | unpinned snapshots of the root are deleted; a pinned one is rewritten with the folders at or beneath a purged path merged into one `[REDACTED]` folder of the summed size |
| root index | `last_error` and `newest_file` of the root are cleared when their `rel_path` was purged |
| resume file | markers under a purged path are removed (`resume.forget_beneath`) |
| the rollup itself | written before the first delete (section 4.4 phases) |

A catalog backed up or exported before the purge still contains the names;
that is outside filecat.

## 4. Backup and database stores

### 4.1 Which folder becomes the rollup

Store detection stays in Python on the listing (`backup.detect`,
`dbfiles.detect`; note 05 section 3). What is new is that a detected store can
name the children of its root that are bulk data, and a rollup replaces them:

```
NAS-VM_1.hbk/                  dir record, probe.backup = manifest summary (kept)
  Config/  Guard  ...          listed-only rows today; stay recorded (small)
  [BACKUP]                     rollup, rollup.store = {format: synology-hyperbackup}
                               (was: Pool/ and its 500,000 rows)
```

`data/store_formats.json` gets a `rollup_children` list per format (names or
`*`-wildcards of immediate children of the store root; folders only), kept in
step with the code by `tests/test_store_formats.py`:

| Format | `rollup_children` | Not rolled (stays listed-only rows) |
|---|---|---|
| synology-hyperbackup | `Pool` | `Config`, `Guard`, `Versionlog`, `Control` |
| synology-abb | `@data` | `@Fuse` |
| postgres | `base`, `pg_wal`, `pg_xact`, `pg_multixact`, `global` | top-level files |
| mysql/mariadb | `*` (every sub-folder: schemas, `#innodb_*`) | `ibdata*`, `ib_logfile*`, binlogs (top-level files) |
| mongodb | `journal`, `diagnostic.data`, `_tmp` | `*.wt` (top-level files) |
| mssql | none (a few big files: nothing to gain) | all |
| veeam, duplicity, windows backup, system image, thunderbird, abg | none in v0.2.0 (data files sit at the top level or deep in per-set folders) | all |
| abb virtual view | n/a (already not walked) | |

Only folders are rolled; top-level data files keep their listed-only rows.
The rule that makes a store rollup: store detected, and not `--measure-backups`
(or `--measure-databases` for an engine) or `--verify-backups` for that store
(they need the files), and `rollups.backups` / `rollups.databases` on. All
children named by `rollup_children` that are present are folded into one
record, `<store>/[BACKUP]` (backup formats) or `<store>/[DATABASE]` (engines),
with `rollup.store` set.

The store's own `dir` record keeps `probe.backup` / `probe.database` exactly
as today, built from the manifests. Nothing in the format modules changes
except what section 4.3 lists.

### 4.2 Relationship to `backup_data` / `db_data` rows

`probe.backup_data` / `probe.db_data` rows are what a store's data files were
before: `kind: "data"`, no hash. In rollup mode a store's bulk folders produce
no rows; the tags remain for top-level data files and for
`--measure-backups` / `--measure-databases` scans. `dupes_cmd._in_backup` and
`enrich`'s check remain for those. Default: **`rollups.backups = true`** and
**`rollups.databases = true`**: the rows of a 1 TB pool cost 500,000 documents
for no information the sum does not hold. `--measure-backups`,
`--verify-backups` and `--measure-databases` imply per-file mode for the stores
they apply to.

What is lost in rollup mode: the per-file checks of `uses_listing` formats
(Hyper Backup's "every file Guard lists is in the listing with Guard's size").
`summarize()` is passed `rollup_totals` (the bytes and file count of each
rolled child) and `listing=None`; Hyper Backup then checks totals only
(Guard's total bytes against the rollup's) and sets
`probe.backup.checked = "totals"` instead of `"files"`; the `problems` text
says so. `--verify-backups` restores the full check, by scanning that store
per file. Veeam, ABB and the others do not use the pool listing in the roll-up
set.

### 4.3 Manifests through the agent

Today an agent scan records `probe.store_note` ("manifest not read") because the
format modules call `open`/`os.listdir` on a local path. For rollups to be
useful over an agent the manifests must be read there too. Python abstracts
the store's file system: `StoreFS` with `listdir`, `exists`, `size`,
`open_binary` and `sqlite_copy(path) -> local temp path`; the local
implementation is `os`, the agent one uses `fsource.fopen` / `sibling` /
`RemoteFileProxy` (`read_range`, 4 MiB per request). A SQLite manifest
(`target.db`, `file_map.db`, `storage.cache` is JSON) is copied through
`read_range` into a temp file in the system temp directory, together with its
`-wal` and `-journal` sidecars when `list_dir` shows them, up to
`rollups.manifest_cap` (256 MiB), then opened read-only; the size and mtime
from `measure(hash="none", head_bytes=0)` are compared before and after the
copy and the copy is retried once when they moved. The temp file is deleted
at once; a manifest over the cap is skipped with a `problems` entry.

**What the agent must provide: nothing new.** `list_dir`, `measure` (as a
`stat`: `hash: "none"`, `head_bytes: 0`) and `read_range` already do it. The
work is Python's: every `backup/*.py` and `dbfiles/*.py` `summarize()` takes a
`StoreFS` instead of an OS path. That is a separate step from the rollup
itself and can follow it (the rollup works without it; the record then keeps
`probe.store_note`).

### 4.4 Migrating existing catalogs

`filecat rollups migrate [--tags TAG ...] [--root R] [--dry-run] [--batch N]
[--checkpoint FILE]` converts stored records to rollups without a rescan:
listed-only `backup_data` / `db_data` rows under a store, and anything the
current rules match (so it also performs the `[REDACTED]` purge of
section 3.5). Crash-safe and resumable like `samples migrate`, per rollup
target `T` (a store child, or a rule match):

1. **Plan.** Read-only. Find the targets: dir records with
   `probe.backup` / `probe.database` and their `rollup_children`; stored
   records whose mpath a rule matches (first match, same matcher as scans).
2. **Phase 1, totals and the rollup record.** Page through the rows beneath
   `T` (keyset by `rel_path`, `Backend.query(dir=...)`), summing size,
   allocated, files, dirs, newest/oldest mtime (hard links by `(dev, ino)`
   where the rows have them). When done, write the rollup with
   `probe.rollup.migrated = true`. This is a single document write; until it
   exists nothing was changed, and a rerun recomputes.
3. **Phase 2, delete.** With the rollup written (`migrated` set), delete the
   rows beneath `T` in batches (`Backend.delete_many`, members too), saving a
   checkpoint (`{target, after: rel_path}`) after each batch. A rerun finds the
   rollup with `migrated` and goes straight to phase 2; deleting is
   idempotent.
4. **Phase 3, cleanup** (once per run): the table of section 3.5 (dropped
   entries beneath purged paths, prunes, treemaps, root index, resume).
5. **Aggregates** of the root are rebuilt.

Refuses while a scan of the root is running (as `samples prune`). `--dry-run`
prints, per target, the rows, bytes and the rollup it would write. A
scan after the migration with the same rules finds the rollup and the empty
folder and replaces the rollup with an exact sum. Rows scanned over SMB have
no `allocated_size`, `ino` or `nlink`: the migrated rollup has no allocated
size and counts hard links by name.

## 5. Default tags

Built-in rules are tried after the user's, are on unless `defaults = false`
(`--no-default-rollups`), and are listed by `filecat rollups rules`.

| Tag | Built-in patterns (all case-insensitive) | Notes |
|---|---|---|
| `[CACHE]` | `type=dir`: `__pycache__`, `node_modules`, `.cache`, `**/AppData/Local/Temp`, `**/AppData/Local/Microsoft/Windows/INetCache`, `**/AppData/Local/CrashDumps`, `**/.gradle/caches`, `**/.npm/_cacache`, `**/Library/Caches` | the unambiguous ones. Not `Temp` or `tmp` by bare name |
| `[SYNOLOGY]` | `type=dir`, by name: `@eaDir`, `#recycle`, `#snapshot`, `@Recycle`, `@tmp`, `@SynoEAStream`, `@appstore`, `@appdata`, `@apphome`, `@database` | name patterns apply at any depth; these names are harmless off a Synology. `@docker`, `@iSCSI`, `@Repository` are not here: they are `exclude` or the storage topology's business |
| `[WINDOWS]` | `System Volume Information`, `$Recycle.Bin` (dir, any depth); files `?:/pagefile.sys`, `?:/hiberfil.sys`, `?:/swapfile.sys`, `*/*$/pagefile.sys` (the administrative share form), same for the other two | the former default skips (below) |
| `[BACKUP]`, `[DATABASE]` | not patterns: section 4 | |
| `[REDACTED]` | none: only user rules | |

**Existing default skips become `[WINDOWS]`.** `DEFAULT_SKIP_DIRS`
(`$Recycle.Bin`, `System Volume Information`) and `DEFAULT_SKIP_ROOT_FILES`
(`pagefile.sys`, `hiberfil.sys`, `swapfile.sys` at a drive's root) are today
skipped entirely, so the space they take is missing from every total. They
become the built-in `[WINDOWS]` rule, so the space shows as a rollup and is
not read. `--no-default-skips` keeps its meaning and removes this rule (the
folders are walked and measured as before). `should_skip_dir`,
`should_skip_root_file` and the two constants are removed; their tests move to
the matcher vectors. `System Volume Information` is unreadable to a normal
account: its rollup is `size 0` with `partial: true` and
`error_codes.permission_denied: 1`, and (section 1) no `errors` entry, so the
exit code stays 0.

`--exclude` and `[[agents]].exclude` are untouched and still win. Which of
`[CACHE]` and `[SYNOLOGY]` is on is a behaviour change for existing users (no
records for `node_modules` any more); open question 1.

Windows equivalents for local scans (all built in or one line of config):
`C:\Users\*\AppData\Local\Temp` and `INetCache` ([CACHE]), `$Recycle.Bin`,
`System Volume Information`, `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`
([WINDOWS]). `Windows\WinSxS` and `Windows\Installer` are not default: they
are real data a person may want listed; a user rule can roll them up
(`**/Windows/WinSxS`).

## 6. Reporting and measures

### What each report needs

| Report | Needs from rollups |
|---|---|
| `filecat summary` | a Rollups table per root (tag, folders, files, bytes, allocated, newest) and the totals line "recorded files: N, X; rollups: M, Y; together Z" |
| `filecat roots` | one line per root: top rollup tags by bytes, and `rollups`/`rollup_bytes` in `last_scan` |
| web treemap | a tile per rollup; colour per tag; tooltip with files, folders, newest |
| web inspector card | per tag (below); growth since a pinned snapshot |
| `filecat dupes` | nothing is read from a rollup; the summary line "not examined: N rollup folders, X bytes in Y files ([CACHE] a, [BACKUP] b)" so a reader knows what was not deduplicated; in `--json` as `rollups_not_examined` |
| `filecat storage links` | nothing. Physical totals come from the topology (disks and volumes), not from the catalog; rollups add detail within a share and never enter `physical_summary`, so the "a disk with a resolved link is not physical on its own host" rule is unaffected. A guest NAS's shares scanned separately are as they were |
| `filecat backups` / `databases` | read the store's dir record as before; the pool size shown comes from the store's `[BACKUP]` rollup when there is one |

### The inspector card, per tag

All tags: the tag as a badge, the folder it sits in, logical size, allocated
size (when known), files, folders, how many children were folded in, newest
and oldest modification, a "lower bound" warning when `partial`, and the change
in bytes against the active pinned snapshot (the tile's `(root, path)` in the
pin, section 1). Then:

- `[REDACTED]`: "Contents are hidden by a rule. Names are not recorded." Nothing
  else (no type breakdown, no sub-folders).
- `[BACKUP]`: the store's `probe.backup` card (format, machines or tasks,
  versions, latest, problems) with logical protected size against the pool's
  bytes (the dedup ratio), a "checked: totals only" badge, and the command to
  scan that store per file with `--verify-backups`.
- `[CACHE]`, `[SYNOLOGY]`, `[WINDOWS]`, user tags: the footprint, "last
  changed N days ago" from the newest mtime, and a list of the biggest
  rollups of that tag in the current folder subtree (`/api/records?kind=rollup`
  with the existing `q` filter on the tag).

### Measures

| Measure | In | Use | v0.2.0 |
|---|---|---|---|
| `size`, `total_files`, `total_dirs`, `matched` | every rollup | totals, treemap, summary | required |
| `allocated_size` | agent | physical footprint on the card and summary | required (agent), n/a for SMB |
| `newest_mtime_ns` | every | "last changed", tile tooltip | required |
| `oldest_mtime_ns` | every | card "oldest file" | required (one `min` in the walk) |
| `errors`, `error_codes`, `partial` | every | lower-bound warning, exit code | required |
| `skipped_mounts` | every | explains a total lower than `du` | required (one counter) |
| `vanished` | every | files that disappeared during a long sum | required (one counter, keeps them out of `errors`) |
| `hardlink_names` | agent | shows that dedup happened | optional: implemented in the agent when counting hard links anyway; no report reads it |
| size by extension inside a rollup (`by_suffix`, top 8) | `[CACHE]`, `[SYNOLOGY]`, `[WINDOWS]`, user non-private | "what is in this cache" | optional, after v0.2.0; never for private rules |
| age buckets (30 days, 1 year, 3 years, older: bytes and files) | any non-private | "how much is stale" | optional, after v0.2.0 |
| largest matched children (names) | non-private, non-pattern-by-name | find the worst `node_modules` | optional, after v0.2.0; never for private rules |
| sparse bytes | derived | `size - allocated_size` | not stored; the card computes it |

Fields marked optional are not in the v0.2.0 wire; the agent reserves
`detail: ["by_suffix", "age"]` in `sum_subtree` and the rules for them.

## 7. Cost, change detection, progress, cancellation

### Change detection

There is no cheap signal that a subtree is unchanged. Directory mtimes do not
propagate on ext4, btrfs or NTFS, so a parent's mtime says nothing about
a cache five levels down; `max(dir mtime) + count` still needs the walk;
caching per directory in the agent would need a persistent inode-keyed store
and invalidation we cannot get without watching. Recommendation:

- **Rules (`[REDACTED]`, `[CACHE]`, `[SYNOLOGY]`, `[WINDOWS]`, user tags):
  re-sum on every scan.** The sum is `lstat` only (no read, no hash) and the
  alternative, walking those trees as records, is what rollups avoid. A
  correct total each scan is worth more than the saved time; it also keeps
  the growth since a pin honest.
- **Stores (`[BACKUP]`): fingerprint, with a maximum age.** A backup program
  writes its manifest when a run ends, and the manifests are read for
  `probe.backup` anyway. `rollup.fp` is the SHA-256 of the sorted `(name,
  size, mtime_ns)` of the manifest files `summarize()` read, the store root's
  `mtime_ns` and listing, and each rolled child's own `mtime_ns`. When the
  fingerprint equals the stored one, the stored rollup is `complete` and
  younger than `store_resum` (30 days), the sum is skipped and the record is
  left as it is (progress shows "carried"). `--force` re-sums everything. A
  pool that changes without touching its manifest is stale for at most
  `store_resum`. Without a manifest (a format with nothing to read) the
  fingerprint is just the root listing and mtimes, so a rule of thumb applies:
  always re-sum.
- **`[DATABASE]`: re-sum every scan** (it changes constantly and has no
  manifest; a data folder is thousands of files, not millions).

### Cost

The sum is `lstat` bound. Through the agent with 4 threads: about 100-200k
entries/s from the dentry cache, 5-20k/s cold on a spinning RAID (seek bound).
5 million files: 1 to 2 minutes warm, 4 to 15 minutes cold. Over SMB,
`scandir` returns the stat in the listing: about 10-30k entries/s per
directory stream, so 5 million files take 3 to 8 minutes with 4
`rollup_workers`; this is the same price as today's listed-only walk (a 1 TB
pool in about a minute), minus 500,000 database writes. Memory is the depth of
the walk plus the hard-link set (agent: entries with `nlink > 1` only, capped
at 2 million; past the cap it counts without dedup and sets `hardlinks_approx`).
A fingerprint-matching `[BACKUP]` costs nothing.

### Time limits and progress

The protocol is strictly one request, one response. A long sum must not need a
huge fixed timeout, and must be stoppable. Options considered:

- A continuation token (`partial: true, token`) needs the agent to keep the
  walk's state between requests (a stack of open directories) or to serialise
  it; it breaks on a dropped connection and on a rule change. Rejected.
- **Streaming progress lines (chosen).** A `list_dir` or `sum_subtree` request
  may carry `progress_ms`; the agent then writes progress lines (`{"progress":
  {"entries": n, "bytes": n}}`, no `ok` key) at that interval before the final
  response, and only then. The client reads lines until one has `ok`. An agent
  that does not know the field sends none, a client that did not ask never
  sees one, so lockstep and protocol 1 hold. The client's read timeout
  restarts with every line, so an hours-long sum needs only a timeout longer than
  `progress_ms`. The progress lines feed the scan's progress output
  (counts only, section 3.2) and the heartbeat.
- `deadline_ms` bounds a request (agent default 6 hours, maximum 24): at the
  deadline the agent stops and answers `ok: true, complete: false` with the
  totals so far. The client does not store an incomplete rollup as a result: it
  keeps the previous record and records a `rollup` error ("sum did not finish
  in 6h").

### Cancellation

A scan interrupted by Ctrl+C closes the connection; the agent must notice. The
agent cancels a running sum when (a) a progress write fails, (b) a `cancel`
request for the sum's `id` arrives on another authenticated connection (the
client sets `id` on long requests and sends `cancel` from a fresh connection
when it abandons one), (c) the deadline passes. The agent checks a shared flag
every 1024 entries. A cancelled request ends with `code: "cancelled"` if the
connection is still open. Python sums check `cancel` (a `threading.Event`) the
same way.

## 8. What the agent must provide

This is the list the Rust agent is rewritten from. The wire forms are in
[agent-protocol.md](agent-protocol.md): `configure_policy`, `list_dir`,
`sum_subtree`, `cancel`, the new error codes.

**Policy (`configure_policy`)**

1. `policy.rules`: an ordered array of rule objects `{"id", "tag", "match",
   "type", "case", "keep", "private"}` (`id`: the rule's index; `tag`
   omitted when `keep`; `match`: patterns already normalised by the client).
   Not a tag-to-patterns map: the order across tags, `keep`, `type`, `case`
   and `private` are per rule.
2. `policy.bases`: `[{"base": "/volume1/project", "mpath": "nas-main/project"}]`:
   for a path at or beneath `base`, the match path of its children is
   `mpath` plus the path relative to `base`. The longest base wins. Under no
   base, no rule applies (exclude still does). The client sends one base per
   root it is about to scan.
3. `policy.exclude` as before. `rollup_groups` is gone.
4. Implement the matcher of section 2 exactly (name and path patterns, `?`,
   `*`, `**`, ASCII case folding, `type`, first match, `keep`), pass
   `tests/data/rollup_match_vectors.json`, and answer with `policy_id`
   (section 2), `rules` and `bases`. Limits: 1024 rules, 64 KiB of patterns in
   total, 4096 bytes per pattern; more is `bad_request`.

**`list_dir`**

5. Apply `exclude`, then the rules, to each child; partition into recorded
   entries and rollups.
6. A rollup entry per tag with these fields, all required:
   `name` (the tag), `kind: "rollup"`, `size`, `allocated_size`, `ino: 0`,
   `dev`, `nlink: 1`, `mtime_ns`/`ctime_ns` (newest), and `rollup` =
   `{tag, matched, total_files, total_dirs, total_size, total_allocated_size,
   newest_mtime_ns, oldest_mtime_ns (left out with no files), errors,
   error_codes, vanished, skipped_mounts, hardlink_names, complete}`.
   Optional later: `by_suffix`, `age` (never when the rule is `private`).
7. A real child whose name equals a rollup's tag (ASCII case-insensitive) in
   this folder is folded into it, counted in `matched`, not listed.
8. Names of folded children never leave the agent: not in `entries`, not in
   `error` objects, not in any rollup field.
9. Accept `progress_ms`, `deadline_ms`, `id` on `list_dir` (rollups can make it
   slow). Reply with `policy_id`.

**`sum_subtree`**

10. Request: `path`, optional `one_filesystem` (default true), `exclude`
    (patterns relative to `path`, same syntax, matched against the path
    below `path`), `private` (default false), `threads` (1 to 16; agent
    default 4), `progress_ms`, `deadline_ms`, `id`, `detail` (reserved).
11. Reply: the counters of a rollup entry (`total_files`, `total_dirs`,
    `total_size`, `total_allocated_size`, `newest_mtime_ns`,
    `oldest_mtime_ns`, `errors`, `error_codes`, `vanished`,
    `skipped_mounts`, `hardlink_names`, `complete`) and `path` only when not
    `private`.

**Both**

12. `lstat` only, never follow links; a link is a file of its own size. The
    basis for "same file system" is the `dev` of the folder being summed (a
    btrfs subvolume or snapshot nested inside is a different `dev` and is
    skipped and counted in `skipped_mounts`). The summed folder itself counts
    in `total_dirs`.
13. Hard links: `(dev, ino)` for `nlink > 1`, one set per rollup entry or per
    `sum_subtree` request, cap 2 million entries (then count without dedup and
    set `hardlinks_approx: true`).
14. Errors: counted by protocol code, `permission_denied` and `io`; an entry
    that disappears is `vanished`, not an error. Never a message or a path.
    Recursion is iterative; depth limit 4096 (deeper is an `io` count).
15. Under a `private` rule or request, no log line, no metric, no panic
    message may contain a path, a name or an OS error text.
16. `progress_ms` lines and cancellation as in section 7: check a shared flag
    every 1024 entries; `cancel` on another connection by `id`.
17. Concurrency: at most 4 sums run at once per agent by default (config); a
    fifth gets `code: "busy"` and the client retries after a pause.

## 9. Python work plan

The next step. Changes by file, then commands, then tests.

**New modules**

- `src/filecat/rollup.py`: `normalize_pattern`, `Rule`, `RuleSet.compile(
  user_rules, defaults)`, `RuleSet.match(mpath, name, is_dir, is_file)` ->
  `Rule | None`, `policy_id`, `to_wire()`, `mpath_of(root, rel_path)`,
  `partition(entries, parent_mpath)`; `Totals` (counters, `merge`, `to_probe`);
  `sum_tree(...)` (section 3.2); `classify(exc) -> code`; `RollupError`;
  `new_rollup_document(root, parent_rel, tag, totals, ...)`; `fingerprint(...)`.
- `src/filecat/rollups_cmd.py`: `filecat rollups {rules,list,migrate}`.
- `src/filecat/storefs.py`: `StoreFS` local and agent (section 4.3), as the
  second step.

**Changed**

- `record.py`: `KINDS += "rollup"`; `NON_FILE_KINDS`; `is_file_kind(kind)`.
- `config.py`: `[rollups]` and `[[rollups.rule]]` loading and validation
  (tags, patterns, `type`, `case`, `keep`, `private`; clear errors that never
  echo a private pattern); reject `[[agents]].rollup_groups`;
  `AgentConfig.policy()` loses `rollup_groups`; `config show`/`agents list`
  mask private patterns (`agents_cmd.py`).
- `options.py`: `rules: RuleSet`, `rollup_backups`, `rollup_databases`,
  `rollup_workers`, `rollup_timeout`, `store_resum`, `manifest_cap`;
  `cli.py`: `--rollup-backups/--no-rollup-backups`, `--rollup-databases/...`,
  `--no-default-rollups`, `--rollup-workers`; `--no-default-skips` removes the
  `[WINDOWS]` rules.
- `walker.py`: `_make_frame` partitions entries (rolled vs recorded, reserved
  tag names, store `rollup_children`), keeps `frame.rolled`; `_will_enter`
  applies the partition; the loop starts a sum per rolled group when the
  frame is made (a `rollup_pool`), or takes the agent's rollup entries, and
  writes the `[TAG]` records after the frame's files and before its dir record;
  `child_count` = recorded + rollups; `mark_dir_complete(child_dirs=)` only
  recorded names; `_delete_stale_children` uses the new `current` set,
  `delete_many`, and handles a rollup replacing a real entry; policy-change
  handling (`probe.rollup_policy` on the root record); `should_skip_*` and the
  constants are removed; `_backup_summary` passes `rollup_totals`; `_store_listing`
  unused in rollup mode; store fingerprint carry-forward.
- `fsource.py`: `AgentSource._entry` turns `kind: "rollup"` into an
  `AgentRollup` (not an `AgentEntry`) that the walker takes from the listing
  instead of skipping; `AgentSource` sends `configure_policy(rules, bases)`
  for each root and checks `policy_id`; `sum_subtree` wrapper with progress,
  deadline, `cancel`.
- `agent_client.py`: `configure_policy(rules, bases, exclude)`, streamed
  `progress` lines in `_call`, `sum_subtree(path, **options)`, `cancel(id)`,
  the new error codes, `DirEntry.rollup` fields.
- `backup/__init__.py`, `dbfiles/__init__.py`: `Store.rollup_children(names)`
  from `store_formats.json`; `summarize(..., rollup_totals=)`;
  `backup/hyperbackup.py`: totals-only check, `probe.backup.checked`.
- `backends/base.py` and every backend: `delete_many`, `purge_dropped_paths`,
  `rollups(root, prefix)`, `rollup_totals(root)`; `browse.py` and the SQL in
  `sqlite/postgres/mysql/mssql/mongodb` for `NON_FILE_KINDS`, `subtree`
  `rollup_bytes`, `sizes`.
- `aggregate.py`: skip rollups; `summary.py`: Rollups table and totals line;
  `roots_cmd.py`: rollup line; `rootinfo.py`: `_observe` and `last_scan`
  fields; `treemap.py`: `build(..., rollups=)`; `serve.py`: pass rollups into
  `treemap.build`, `/api/subtree` `rollup_bytes`; `web/index.html`: tile
  drawing for `folder.rollup`, the inspector card per tag, no zoom on a
  rollup tile; `dupes_cmd.py`: skip rollups, the "not examined" line;
  `enrich.py`: `NO_CONTENT_KINDS`; `rootcase.py`: sampling; `resume.py`:
  `forget_beneath`; `samples.py`/`member_sets.py`: no change beyond tests.
- `data/store_formats.json`: `rollup_children`; `tests/test_store_formats.py`.

**Order**: (1) record, matcher, vectors, config; (2) Python walk and sums,
`delete_many`, readers (aggregate, browse, summary, treemap, dupes, enrich);
(3) the agent client and fake agent; (4) stores and `rollups migrate`;
(5) serve and web; (6) `StoreFS`.

**Tests**

- `test_rollup_match.py`: the shared vectors; normalisation; case; `**`;
  `policy_id` vectors; reserved tag names.
- `test_rollup_walk.py`: a tree with `node_modules`, `.cache`, a folder named
  `[CACHE]`; record shape and counts; hard links (via fake agent), mount skip;
  rescan replaces; rule removed deletes the stale rollup; a rolled name was a
  stored dir: purged, not dropped; policy change relists without remeasuring;
  `--no-default-skips`; `exit code` stays 0 for denied.
- Parity: the same tree scanned locally and through the fake agent gives the
  same rollup documents (apart from `via`, `allocated_size`, `summed_at`).
- Readers: aggregates, `summary`, `roots`, browse filters, `subtree`,
  treemap tile and pin diff, `dupes` line, `enrich` leaves rollups alone, the
  SQL and in-memory backends in `test_backend_contract.py`.
- Stores: a fake Hyper Backup store gives `[BACKUP]` plus `probe.backup`
  (`checked: "totals"`), `--measure-backups` and `--verify-backups` keep rows,
  fingerprint carry-forward and `store_resum`, the DB engines.
- **Privacy test** (`test_rollup_privacy.py`): a tree with a redacted subtree
  whose folder, file and sub-folder names are distinctive tokens
  (`ZXQ-folder-7f3a`, ...) including one unreadable folder and a non-UTF-8
  name. Scan it three ways: locally, over the fake agent, and over the fake
  agent with a monkeypatched `os.scandir` that raises `PermissionError` with
  the file name in the message. Capture and search for every token (plain,
  U+F700-mapped, UTF-16, base64 of the name): stdout and stderr (progress,
  preflight, start line), `caplog` at DEBUG for all loggers, the exit
  exception text and a formatted traceback, every table of the backend
  (`files`, `dropped`, `members`, `samples`, `roots`, treemaps, via
  `backend.list()` and `list_dropped()` and a raw dump of the SQLite file),
  the resume file, the checkpoint, `filecat summary|roots|dupes|show`,
  `filecat serve` API responses, and the fake agent's **wire log** (every
  request and response line, which the fake records). Plus the purge test:
  scan with no rule (tokens present, with samples and members), add the
  rule, rescan (and separately run `rollups migrate`), and assert the
  tokens are in none of those places, `dropped` is empty for the path,
  pinned treemaps are rewritten, and `samples prune` leaves nothing.
  An in-process `sys.settrace`-free check: `rollup.sum_tree` is called
  with `os.scandir` patched to raise, and the raised exception's `str`,
  `repr`, `__cause__` and `__context__` are searched.
- Migration: kill points (after phase 1, after k batches of phase 2, before
  phase 3) and resume; run twice; `--dry-run`.
- Config: rule validation errors never print a private pattern; masked
  `config show`.

**Fake agent** (`tests/_fake_agent.py`) is extended to the contract of
section 8: `rules` and `bases` with the real matcher (imported from
`filecat.rollup` would test the matcher against itself, so a second small
independent implementation of the vectors, or the vectors only), `policy_id`,
`type`/`case`/`keep`/`private`, `oldest_mtime_ns`, `error_codes`, `vanished`,
`skipped_mounts`, `hardlink_names`, hard links by `(dev, ino)` across the
group, same-`dev` rule, `sum_subtree` options, `progress_ms` lines,
`deadline_ms` -> `complete: false`, `cancel`/`id`, `busy`, a wire log of every
line for the privacy test, and a way to make a child unreadable and to
inject names with bytes that are not UTF-8.

## 10. Open questions

1. **Defaults on?** `[CACHE]` and `[SYNOLOGY]` built-ins on, store rollups
   on, and the old default skips becoming `[WINDOWS]`, all change what an
   existing catalog holds after the next scan (no records for
   `node_modules`, `@eaDir`, backup pool files). Is on-by-default right, or
   should `defaults` be off until a catalog opts in? (Recommended: on.)
2. **Plaintext redacted patterns in `filecat.toml`** (masked in every
   output), or hashed name patterns as well in v0.2.0? (Recommended:
   plaintext now.)
3. **Totals-only backup checks** are the price of rolling up a Hyper Backup
   pool (the per-file Guard comparison needs the file list). Acceptable as the
   default, with `--verify-backups` for the full check?
4. **Case-insensitive pattern matching everywhere**, including on a Linux
   NAS where `Vault` and `vault` are different folders (the safe direction
   for `[REDACTED]`, a surprise for `[CACHE]`). Keep?
5. **`[[agents]].rollup_groups` removed** rather than translated; fine since
   nothing used it?
