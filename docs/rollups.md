# Rollup groups

Design for the rollup groups of research note
[01](research/01-rollup-groups-privacy-indexing.md) and the backup-store
rollups of note [05, section 3](research/05-catalog-tuning-agent-boundary.md):
`[BACKUP]`, `[REDACTED]`, `[CACHE]`, `[SYNOLOGY]` (plus `[WINDOWS]`,
`[DATABASE]` and tags the user defines). Everything is opt-in, with a mode per
type (section 2): an existing catalog changes only when its owner asks. A rollup stands for a set of files
and folders that the catalog counts but does not list: one record holds their
totals and none of their names.

This page settles the record, the rules, the privacy guarantees, the
reports, the cost and the agent contract, so that the Rust agent can be
written once and the Python side implemented from it (section 9). Where this
page and the research notes disagree, this page wins; the wire details live
in [agent-protocol.md](agent-protocol.md), which was updated to match.

Contents: [1 Record](#1-the-rollup-record) - [2 Rules](#2-rules) -
[3 REDACTED, markers and sticky redaction](#3-redacted-privacy-guarantees) - [4 BACKUP and DATABASE](#4-backup-and-database-stores) -
[5 Default tags](#5-default-tags) - [6 Reporting](#6-reporting-and-measures) -
[7 Cost](#7-cost-change-detection-progress-cancellation) - [8 Agent](#8-what-the-agent-must-provide) -
[9 Python work plan (stages A, B)](#9-python-work-plan) - [10 Open questions](#10-open-questions)

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
| `rollup.rule` | which rule made it: `user:<n>` (index in `[[rollups.rule]]`), `builtin:<tag>`, `marker:<tag>`, `sticky`, `store:<format id>`. Never the patterns |
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

### Everything is opt-in, with a mode per type

Nothing rolls up by itself. Each built-in type has a **mode**:

```toml
[rollups]
backup   = "automatic"
database = "manual"
cache    = "manual"
synology = "disabled"
windows  = "manual"
redacted = "manual"
```

| Mode | Meaning |
|---|---|
| `automatic` | the built-in rules of the type apply. For `backup` and `database`, store detection rolls up the stores' data pools (section 4). For `cache`, `synology` and `windows` the patterns of section 5 apply |
| `manual` | only what the user lists applies: `[[rollups.rule]]` paths and patterns with that tag, `[[rollups.backup_store]]` / `[[rollups.database_store]]` paths, and marker files (section 3.6) |
| `disabled` | the type never applies. Listed paths, patterns and markers of that type are ignored, and the scan says so once ("cache is disabled: 2 rules and .filecat-cache markers are ignored") |

**The default of every type is `manual`**, so a fresh install and an existing
catalog change nothing until the user opts in. Tags the user defines are
always manual (they have no built-in rules and no mode). `redacted` is always
on: `redacted = "disabled"` is refused with a warning and treated as
`manual`, so listed paths, markers and the sticky store of section 3.7
always apply.

`--rollup TYPE=MODE` (repeatable, e.g. `--rollup cache=automatic`) overrides
one mode for a scan. `--no-default-rollups` is not needed (the default is
`manual`) and is not added.

**The old default skips.** `should_skip_dir` / `should_skip_root_file`
(`$Recycle.Bin`, `System Volume Information`, `pagefile.sys`, `hiberfil.sys`,
`swapfile.sys` at a drive's root) keep their present behaviour: skipped, not
recorded, space missing from the totals, `--no-default-skips` to walk them.
They change only with `windows = "automatic"`, which turns the skip into the
built-in `[WINDOWS]` rule, so the space shows as a rollup and is still not
read (section 5). With `windows = "manual"` (default) and `"disabled"` the
skips stay as they are (`disabled` governs rollups, not the skip; the skip has
its own switch). `--no-default-skips` with `windows = "automatic"` removes the
`[WINDOWS]` rule too, and the folders are walked as before. A catalog made
before this page therefore gets no new rollup, no purge and no changed totals
unless its owner edits `[rollups]`.

### Suggestions

While a scan runs, a folder or file that a built-in rule would match, but
whose type is not `automatic`, is counted as a **suggestion**: it is listed,
walked and recorded normally, and the match is noted. A `disabled` type makes
no suggestions, and `redacted` never does (it has no built-in rules, and a
suggestion could leak what the user wants hidden). Only the tag, the parent
folder and the number of children matched are noted, never a name:

- stored on the root index, `suggestions` of that root: `[{"tag", "parent"
  (rel_path of the folder), "matched"}]`, at most 1000 per root (past that a
  `more` count), replaced whole by every complete scan of the root and left as
  it was by a partial one. It is a few kilobytes per root, rewritten with the
  root's other scan fields, which is why it is not a store;
- `filecat rollups suggest [--root R] [--json]` lists them, grouped by tag
  and parent folder, with the line that would adopt it (`[[rollups.rule]]`
  text). The web viewer later offers "add this rollup" (roadmap, v0.2.x).

On an agent scan the agent counts them: the policy rules carry `suggest:
true` for built-ins of a non-automatic type, and `list_dir` answers with
`suggest: [{"tag", "matched"}]` for the directory. A suggestion rule never
folds anything.

### Audit

`filecat rollups list [--root R] [--json]` reads the stored rollup records
(`Backend.rollup_totals`) and prints counts by tag and parent folder: rollups,
children folded in, files, bytes, newest modification, how many are `partial`
and how many came from a rule, a marker, a store or the sticky store
(`rollup.rule`). An administrator checks that the rollups are what was
expected: `[REDACTED]` appears as counts and parent folders, never names.
Roadmap: a web viewer screen with the same counts (v0.2.x).

### Where rules come from

A scan evaluates each entry in this order and the first match decides:

1. `exclude` (`--exclude`, `[[agents]].exclude`): hard exclusion, as today.
   An excluded path is neither walked nor counted nor rolled up.
2. **Redacted**, always: the sticky store (section 3.7), a `.filecat-redacted`
   marker (3.6), then the `[[rollups.rule]]` entries tagged `[REDACTED]` in
   file order. `keep` cannot take an entry out of `[REDACTED]`.
3. Other markers (`.filecat-cache`, `.filecat-backup`, `.filecat-<tag>`, ...)
   of the types that are not `disabled`.
4. User rules: the other `[[rollups.rule]]` tables, in file order (a rule with
   `keep` ends the search for its entries).
5. Store rollups (section 4): the data pool of a detected store, when
   `backup` / `database` is `automatic` or the store's folder is listed in
   `[[rollups.backup_store]]` / `[[rollups.database_store]]`.
6. Built-in rules (section 5) of the types whose mode is `automatic`.
7. Built-in rules of the types that are `manual`: suggestions only.

```toml
[rollups]
store_resum  = "30d"    # at most this long a store's rollup is carried forward when its fingerprint is unchanged
manifest_cap = "256MiB" # largest SQLite manifest copied through an agent (section 4.3)

[[rollups.rule]]
tag   = "[REDACTED]"
match = ['\\nas-main\project\private-project', '/volume1/homes/jdoe/vault']

[[rollups.rule]]
tag   = "[CACHE]"
host  = "nas-main"     # optional: only roots on this server or agent (see below)
match = ["node_modules", "**/AppData/Local/Temp", '\\nas-main\homes\build']
type  = "dir"          # any (default), dir or file
case  = "sensitive"    # default; or insensitive (ASCII folding of the whole pattern)

[[rollups.rule]]
keep  = true           # no tag: matching entries are walked normally, no later rule is tried
match = ["**/keep/node_modules"]

[[rollups.backup_store]]   # manual mode: this folder is a backup store; detect it and roll up its data pool
path = '\\nas-main\Backup\NAS-VM_1.hbk'
```

A user tag (`tag = "[LEGAL]"`) has no mode and may have an empty `match`
when only its marker is wanted. `private = true` on a rule applies the
`[REDACTED]` guarantees (section 3) to any tag; `tag = "[REDACTED]"` implies
it. `[[rollups.backup_store]]` / `[[rollups.database_store]]` take `path`
only in v0.2.0 (`verify` per store is v0.2.x, section 4.5).

**`[[agents]].rollup_groups` is removed.** It was never used by a scan (the
walker skipped rollup entries), its patterns were POSIX with a `*` that
crossed `/`, and one global list is what makes a rule mean the same through an
agent and over SMB. A configuration that still has it is an error naming
`[[rollups.rule]]`. `[[agents]].exclude` stays (an agent-specific hard
exclude in POSIX terms, sent as the policy's `exclude`).

### Pattern semantics

A pattern is one of three **forms**, told apart by its start:

| Form | Looks like | Matched against |
|---|---|---|
| agent form | `/volume1/homes/jdoe/vault` | the literal host path from `/` |
| share form | `\\nas3\homes\jdoe\vault` | the UNC path: `root` plus `rel_path`, with `\` |
| local form | `C:\Users\x\AppData`, or `/mnt/data/x` on a Python host | the local path of a local scan |

`/` and `\` are the same separator in a pattern; a leading `//` or `\\` is
a share form, a leading `/` an agent (or local POSIX) form, a drive letter a
local form. Patterns are normalised (repeated separators collapse; a trailing
separator means "directories only", as `type = "dir"`). A pattern that
starts with `**/` is a **suffix pattern** and is the same in every form
(`**/AppData/Local/Temp`). A pattern with **no separator** is a **name
pattern** (`node_modules`, `*.tmp`, `@eaDir`): it matches the entry's name at
any depth, in any form.

**Converting between forms** uses the share root mapping that already exists:
`ShareMap` (`agent_client.py`: the `[agents.shares]` table, the Synology
`/volumeN/<share>` fallback, and the entries `topology.share_entries` derives
from the storage topology, the config winning), never a second table.

- **Agent scan**: a share-form pattern whose server the agent's map covers is
  converted to agent form (`ShareMap.to_posix_path`, with `canonical` repairing
  the share's spelling from the agent's listing of `/volumeN`) and sent. The
  agent matches **literal host paths**. A share-form pattern for another server
  is not sent; a local-form pattern is not sent.
- **SMB scan** of `\\nas3\homes`: an agent-form pattern is converted to share
  form (`ShareMap.to_catalog_path`) with the map of the configured agent that
  covers the root's server. When no agent map covers that server the pattern
  is **unresolved for that root**: the scan prints a warning naming the rule
  (never a private pattern; the rule index and tag) and counts it in the
  root's `rollup_unresolved`, so it is never silently ignored. `host =` on a
  rule (an agent name or a server) restricts it to that host, which an
  agent-form pattern should always say when more than one agent is configured,
  since `/volume1/homes/x` means different folders on different hosts.
- **Local scan**: local-form patterns match as they are; share-form patterns
  match only when the local root is itself a UNC root.
- A pattern in the form that fits the scan needs no conversion; name and
  suffix patterns never need one.

The conversion happens once per scan and root, in Python, and the result is
what the policy id (below) and the agent see.

Wildcards, and only these: `?` one character that is not a separator; `*` any
run of characters that is not a separator; `**` as a whole component, zero or
more components (`a/**/b` matches `a/b` and `a/x/y/b`). `x/**` matches what
is inside `x` but not `x` itself, so `\\nas\s\x\**` rolls up each child of `x`
into `x\[TAG]`, where `\\nas\s\x` rolls up `x` into the parent's `[TAG]`.
There are no character classes and no escapes: `[` is an ordinary character
in a pattern, so a folder `[x]` is matched by writing `[x]`; a name that
contains a literal `*` or `?` cannot be matched exactly.

- **Case**: path patterns are **case-sensitive below the share**. The server
  and share parts of a share form (and the drive letter of a local form) are
  case-insensitive, consistent with the roots case rules (`rootcase.py`,
  [scanning.md](scanning.md#one-share-two-spellings)): the catalog holds the
  NAS's own spelling and the names below it are exact. Over SMB, Windows
  reports the NAS's real case for every name, so exact matching works there
  as well as on the agent. `case = "insensitive"` on a rule folds ASCII letters
  in the whole pattern (the one per-rule override: one more flag in the
  matcher). Other characters are always compared exactly (no Unicode folding,
  no NFC/NFD normalisation), so Python and Rust agree byte for byte. Name
  patterns follow the rule's `case` (sensitive by default), so `Node_Modules`
  does not match `node_modules` unless the rule says so. The built-in rules
  of section 5 are `case = "insensitive"` where the names are Windows names.
- **Type**: `type = "dir"` (or a trailing separator) matches directories
  only, `file` non-directories (links and specials count as files), `any`
  both. A link is matched by its own name and is never followed.
- **Order**: rules are tried in order for each entry, first match wins. The
  matched entry is then not entered, so a rule can never apply inside what an
  earlier rule took, and an outer match always wins over an inner one (a
  `[REDACTED]` folder inside a `node_modules` is part of `[CACHE]`, which
  holds no names either).
- **Exclude first**: an entry that matches `exclude` is skipped before any
  rule is tried.

The match path of an entry is the form of the scan: on an agent scan the
agent builds it from the child's literal path (nothing is computed from the
catalog root); on an SMB scan Python builds it
from the recorded root and `rel_path` (`\\nas-main\project` + `a/b` is
`\\nas-main\project\a\b`; the recorded root is used, so an alias such as
`\\nas-main` standing for `\\192.0.2.13` matches as `nas-main`).

A conformance file, `tests/data/rollup_match_vectors.json`, is read by the
Python tests and copied into the agent's test suite. It has three tables:
`match` (`{rules, path, is_dir} -> tag | null`, covering the three forms,
suffix and name patterns, `**`, `x/**`, `?`, `case`, `type`, `keep`, ASCII
versus non-ASCII case, a trailing separator), `policy` (`{rules} ->
wire policy id`) and `redaction` (`{key_hex, root, rel_path} -> hex`, section
3.7, including a name with a U+F700-mapped byte, a name with a space and `.`,
and a non-ASCII name). The matcher and the HMAC are the two places where the
implementations can drift. Conversion between forms is Python-only (the agent
only sees the result) and has its own Python tests.

### The rule-set ids

There are two ids and they answer different questions.

- **Catalog policy** (`probe.rollup_policy` on the root's directory record,
  `rollup.policy` on every rollup): the first 12 hex digits of the SHA-256 of
  the canonical JSON of the effective configuration: the modes, then the
  user rules after normalisation (`{"tag", "match", "type", "case", "keep",
  "private", "host"}` in that key order), the store paths, the configured
  marker tags; compact separators, UTF-8. It is computed from the written
  form, **not** the converted one, so scanning the same share through an
  agent one day and over SMB the next does not look like a rule change. The
  sticky store, markers found on disk and suggestions are not in it (they are
  state, not configuration). Store rollups come from detection.
- **Wire policy id** (`configure_policy` and `list_dir` replies): the same
  hash over the rules as sent after conversion (`{"tag","match","type","case",
  "keep","private","suggest"}`) plus the marker names. The client computes it
  and compares it with the reply; a mismatch means the two matchers read the
  rules differently and the scan fails for that root before it lists anything.

48 bits are enough to detect a change, and too few to be a useful oracle for
guessing a hidden pattern list.

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

The viewer's file-name search (`/api/search`, docs/roadmap.md v0.2.5) matches the `name` of the
stored records and nothing else, so it can show only what the catalog holds: a rollup is found by
its own name (`[REDACTED]`, `[CACHE]`), and nothing of what it folds in exists to be found.
`tests/test_rollup_privacy.py` runs it over a catalog with redacted subtrees.

### 3.2 SMB and local scans

Python computes the rollup itself, and names exist only transiently in memory:

1. **Never listed ahead, never recorded.** Before a child directory is
   listed, read ahead or recorded, `_make_frame` checks the sticky store and
   the child's marker files (3.6, 3.7). In `_make_frame` the folder's
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
   **The agent's deny list does not change a sum.** It stops *content* reads
   (`read_file`, `read_range`, `measure`); a `.env`, a private key or a
   Windows hive inside a rolled-up folder (a `.filecat-redacted` folder, a
   `[CACHE]`) is still counted in `total_files`, `total_size` and
   `total_allocated_size`, because a sum uses `lstat` only, in Python and in
   `sum_subtree` alike. Outside a rollup the same file gets a metadata-only
   record (name, size, times, `probe.secret`; docs/scanning.md section 4).
   Likewise a cloud placeholder is counted and never recalled.
7. **Hard links** on Windows are not detected (`DirEntry.stat()` has no
   `st_nlink`/`st_ino`); `hardlink_names` is left out and the record says
   `via: "python"`. `allocated_size` is also left out.

### 3.3 Agent scans

- The agent matches the rules itself (it receives the `rules` in agent form,
  the marker names and the redaction sets, section 8) against literal host
  paths, looks for markers and sticky folders before returning a child, and
  sums locally. `list_dir` returns the
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
- The sticky store (3.7) is the one place redaction is remembered beyond the
  config, and it holds keyed hashes, never names. Hashed name patterns
  (`sha256:<hex>` matching the hash of a name) would keep names out of the
  config as well, but cannot express path patterns or wildcards and cost a
  hash per directory entry in the agent; not in v0.2.0 (open question 4).

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
  rollup from the stored records beneath each match, registers each folder in
  the sticky store (3.7), then deletes them. It also cleans the other places
  (below). A scan that follows finds nothing to
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

### 3.6 Marker files

A folder can mark itself. `.filecat-redacted`, `.filecat-cache`,
`.filecat-backup`, `.filecat-database`, `.filecat-synology`,
`.filecat-windows`, and `.filecat-<tag>` for each user tag (`[LEGAL]` is
`.filecat-legal`; the lower-cased tag without brackets) are names that
filecat looks for. A marker file inside folder X rolls **X** up, under X's
parent, as `<parent>\[TAG]` (`[BACKUP]` and `[DATABASE]` markers fold the whole
folder like any other: the store treatment of section 4 comes from detection
or `[[rollups.backup_store]]`, not from a marker). The file's content is
ignored (an empty file is enough). Marker files are counted inside the rollup
like every other file.

**Detection happens when the parent is listed, before X is entered.** If X's
listing were read first, X's names would already have been read, and on an
agent scan sent over the wire. So:

- **Agent**: for each child **directory** it is about to return, it `lstat`s
  the marker names in that child (`fstatat` on an open directory descriptor):
  the fixed set of built-in names plus the user-tag names the client sent in
  `configure_policy` (`markers`), one `lstat` per marker name per
  subdirectory, and returns a marked child only as part of a rollup. The
  agent does not have the list built in: it checks what the policy lists, so
  a `disabled` type's marker name is simply not sent.
- **Python on SMB or local** (decided after the first draft, which `lstat`ed
  each marker name in each child: a network round trip apiece over SMB): the
  marker is looked for in the child's **own listing**, which the walk reads
  anyway, read-ahead included. `walker._list_dir(path, markers)` is the only
  way such a listing reaches the walk: it reads the names, checks them against
  the marker names (ASCII case ignored) **before** sorting, stat-ing or
  returning anything, and when one is there it returns `rollup.Marked`
  instead of the entries. The read-ahead then queues nothing from it, and the
  walk rolls the child up (`rollup.rule` = `marker:<tag>`), summing it with
  `sum_tree`. The names of a marked folder exist only in that function's
  local variables. Rules and the sticky store decide from the name alone,
  before the child is listed, so a ruled or sticky folder is never listed.
- **Cost**: Python: one pass over a listing's names that is already in memory
  (a lookup per dotted name), no extra I/O. Agent: one `lstat` per marker name
  per subdirectory, free on a local file system.
  A type that is `disabled` is not looked for.
- A marker found in a child's listing is found only when the walk reaches the
  child, so a folder whose child has one is unchanged only if, once all its
  children are known, it holds as many entries and the same tags as its stored
  record (`probe.child_count`, `probe.rollup_tags`); a newly marked child
  forces the stale pass for its parent. Rank: a marker is found after the
  rules (it needs the listing), so a folder that a rule or the sticky store
  rolls up never shows its marker. That differs from the list of section 2 only
  when a `[CACHE]`-like rule and a `.filecat-redacted` marker meet on one
  folder, and both hold no names.
- A `disabled` type's markers are ignored, and the scan says so once, except
  `redacted`, which cannot be disabled.
- A marker in the folder being scanned as a root: that root is not listed;
  its contents are recorded as one rollup `<root>\[TAG]` (rel_path `[TAG]`), as
  if every child had matched. A marker found only after the fact (a file
  created while the folder is being read) is picked up at the next scan.
- **Anyone with write access to a share can roll a folder up** by dropping a
  marker in it. The rollup still shows its size, files and newest date, so
  nothing vanishes silently; a marker cannot hide that something exists. It
  can hide what is inside, and it can make `[REDACTED]` permanent, because of
  3.7. Removing the folder's redaction is a deliberate act (3.7).
- **Why filecat does not search for `.filecat-*` before a scan**: there is no
  index of names (the catalog is built by the scan), so finding markers
  first costs a full walk of every share, which is the scan itself, and any
  marker created after that walk would be missed. Looking at each child when
  its parent is listed costs a few `lstat`s and is correct at the moment the
  folder is read.

### 3.7 Sticky redaction: forget the name, remember the folder

Once a folder has been redacted, by marker or by config, filecat remembers it
without storing its name, so that a removed marker, an edited config, a
restore that overwrote the folder or a rename on the NAS does not reveal it
at the next scan.

**What is stored** (the `redactions` store, new):

| Field | Meaning |
|---|---|
| `id` | a random 8 hex digits, shown by the commands, not derived from the path |
| `root` | the root's id |
| `parent` | the `rel_path` of the folder the `[REDACTED]` rollup sits in (not secret: it is in the catalog) |
| `path_hash` | the keyed hash of the folder's path, below |
| `dev`, `ino` | the folder's `(dev, ino)`, from an agent scan only (otherwise absent) |
| `status` | `active`, or `pending` (release requested, section below) |
| `source` | what first redacted it: `marker`, `config`, `sticky` (re-registered) |
| `created`, `last_seen`, `released` | timestamps |
| `key_id` | the first 8 hex digits of the SHA-256 of the key that made `path_hash` |

**The hash.** `path_hash = HMAC-SHA256(key, "filecat-redact-v1\0" + root +
"\0" + rel_path)`, hex of the first 16 bytes (32 digits), where `root` is the
root's id (UTF-8) and `rel_path` is the folder's catalog `rel_path`: `/`
separated, no leading or trailing `/`, exactly as stored (a byte that is not
valid UTF-8 is the character U+F700 + byte, encoded in UTF-8, as
`fsource.to_storage`), **no case folding and no Unicode normalisation**.
Hashing the path relative to the root, with the root's id, gives one value
for a folder whether it was scanned over an agent or SMB; the agent only needs
the root's base path to compute it. Only folders are hashed (one HMAC per
child directory, nothing for files). The vectors are in
`tests/data/rollup_match_vectors.json`.

**The key** is 32 random bytes in `redact.key` in the user config directory
next to `filecat.toml` (`%APPDATA%\filecat\` or `~/.config/filecat/`), created
on first use with owner-only permissions, read in memory, never in the
catalog and never in any output (`FILECAT_REDACT_KEY_FILE` points elsewhere).
It must be backed up apart from the catalog (a catalog backup that carries its
key defeats the purpose). `key_id` is the only thing about it in the store.

**Who computes the hash.** Python cannot hash names it never sees on an agent
scan, so the agent does: `configure_policy` carries `redaction: {"key": hex,
"roots": [{"root", "base", "hashes": [...], "inodes": [[dev, ino], ...]}]}`
per root to be scanned. The agent holds the key in memory only, computes the
hash of each child **directory** (path relative to `base`), and treats a child as
redacted when its hash is in `hashes` or its `(dev, ino)` is in `inodes` (so a
rename on the NAS is still caught). For the matches it folds into a
`[REDACTED]` rollup it returns `folded: [{"h": hash, "dev": n, "ino": n}]`
(directories only; capped at 1000 an entry), so Python registers or updates
sticky entries (a renamed folder gets its new hash) without ever having the
name. On SMB and local scans Python computes the same hash itself.

**What it does at each scan.** A child directory whose hash or `(dev, ino)`
matches an `active` or `pending` entry is folded into `[REDACTED]` even if no
marker, no rule matches it. Anything that is redacted by marker or rule and is
not yet in the store is added. A folder that is gone (no match for a whole
complete scan) stays in the store; entries are only removed by approval.

**Releasing a redaction takes two steps**, so that nobody un-redacts a folder
by accident or in one command:

1. `filecat rollups redacted release <path>` (any of the pattern forms of
   section 2: the user supplies the path, so filecat can hash it; nothing
   stored reveals it) marks the entry `pending` and prints its `id`. It
   changes nothing visible: the folder is still redacted.
2. `filecat rollups redacted approve <path-or-id>` clears it. It is a **separate
   invocation**, refuses an entry that is not `pending`, prints what will
   become visible ("the next scan of \\nas3\homes will list and record the
   contents of one folder under jdoe, about 41 GiB in 3,210 files; a
   .filecat-redacted marker or a [[rollups.rule]] still matches it" when it
   does) and asks for confirmation (`--yes` for scripts; refused without a
   terminal otherwise). A marker or rule that still matches re-registers the
   folder at the next scan, so approving is useful only after both are gone.
   A web approval screen is v0.2.x.

`filecat rollups redacted list [--root R] [--json]` shows ids, status, parent
folder, root, source, `last_seen` and counts, **never names or hashes**.

**If the key is lost.** Everything redacted by marker or config stays
redacted (they do not need the key). Sticky entries cannot be matched by path:
`path_hash` values no longer verify (the stored `key_id` differs from the new
key's). Entries with a `(dev, ino)` still match on agent scans. filecat does not
quietly make a new key when entries exist: the scan of a root that has sticky
entries stops with "redaction key not found (key_id 1a2b3c4d)" unless run with
`--new-redaction-key`, which writes a key and leaves the old entries to be
matched by inode only. A fresh install with no entries creates its key
silently.

**Backend contract.** New store `redactions` (SQL table with unique
`(root, path_hash)`; Mongo collection): `put_redaction(entry)`,
`redactions(root=None, status=None)`, `touch_redaction(id, last_seen)`,
`set_redaction_status(id, status)`, `update_redaction_identity(id, path_hash,
dev, ino, parent)` (a rename), `delete_redaction(id)`. Not part of
`dropped`, not included in treemap snapshots or exports of names, and read
by `filecat rollups redacted` and the walker only.

## 4. Backup and database stores

**Prominent: the store record keeps everything the manifests say.** The
store's own `dir` record keeps `probe.backup` / `probe.database` (computer,
job or task, versions, latest, sizes, `problems`) exactly as today. Only the
**bulk folders** under it roll up; the information that makes a backup store
useful in a report is never folded away.

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
The rule that makes a store rollup: store detected, not `--measure-backups`
(or `--measure-databases` for an engine) for that store (they need the files),
and either `backup` / `database` is `automatic`, or the store's folder is listed
in `[[rollups.backup_store]]` / `[[rollups.database_store]]` (manual mode).
Verify levels 0 and 1 (4.5) work with a rollup. All
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
`enrich`'s check remain for those. With `backup = "automatic"` and
`database = "automatic"` the rows of a 1 TB pool cost 500,000 documents
for no information the sum does not hold. Nothing rolls up until a type is
`automatic` or a store is listed (section 2). `--measure-backups` and
`--measure-databases` imply per-file mode for the stores they apply to;
`--verify-backups` levels 2 and 3 will (4.5).

What is lost in rollup mode: the per-file checks of `uses_listing` formats
(Hyper Backup's "every file Guard lists is in the listing with Guard's size").
`summarize()` is passed `rollup` (the rolled folders' names and the bytes and
file count of the rollup; stage B, see the notes in section 9) and Hyper Backup
no longer lists the pool. At verify level 0 (default) nothing is
compared (`probe.backup.checked = "none"`); at level 1 Hyper Backup checks
totals and file count (Guard's against the rollup's) and sets `checked =
"totals"`; the `problems` text says so. The per-file check
is level 2 (4.5, v0.2.x); until then `--measure-backups` scans that store per
file. Veeam, ABB and the others do not use the pool listing in the roll-up
set.

### 4.3 Manifests through the agent

Implemented (`backup/storefs.py`). The format modules in `backup/` and the
engines in `dbfiles/` no longer call `os.*` / `open` / `sqlite3.connect` on a
path: `summarize(path, names, ..., fs=)` takes a `StoreFS`, the file system the
manifests are read through (the walker passes it only for an agent scan; the
default is the local one, so local and SMB scans run the same code as before).

    join(base, *parts)  basename(path)  listdir(path) -> {name: entry}
    stat(path)  exists  isfile  isdir  file_size  open(path, mode)  read_json
    readlink(path, entry)  sizes(path) -> {inner path: size}  lpath(path)
    sqlite_rows(path, sql, params)  sqlite_many(path, [(sql, params), ...])

`LocalFS` is `os` (an OS path or an SMB UNC path). `AgentFS(source, root, cap)`
works on the catalog's UNC paths and uses `list_dir` (an entry quacks like
`os.DirEntry`), `measure(hash="none", head_bytes=0)` as `stat`, and
`fsource.RemotePath.open` (`open_remote`, `read_range`) for `open`. Every
thread gets its own agent connection as usual (`AgentSource.client()`).

A SQLite manifest (`target.db`, `file_map.db`, Hyper Backup's `*.db`, ABG's
`*.sqlite`) is copied through `read_range` (4 MiB per request) into a folder
in the system temp directory (prefix `filecat-backup-`), together with its
`-wal` / `-journal` when they exist and are not empty, then queried and the
folder deleted whatever happens (an error mid-copy, a bad file, a failed
query). A copy with no sidecar is opened read-only (`mode=ro`); with one it is
opened normally, because SQLite has to replay the log, which writes to the
copy and never to the NAS. The size and mtime of the file and its sidecars are
checked after the copy and the copy is retried once if they moved; a manifest
still moving fails with a `problems` entry (`changed while being copied`). The
queries of one file (ABB's `target.db` has three) share one copy.

`rollups.manifest_cap` is the most one manifest (with its sidecars) may be:
default 256 MiB. A manifest over it is not copied: `AgentFS.oversize` records
which one (its path inside the store, never the full path), and the walker
records `probe.store_note` ("<format>: manifest not read through
filecat-agent, over the manifest_cap limit: <inner path> (<n> bytes, limit
<cap>)") in place of `probe.backup` / `probe.database`, no error. `rollups
migrate` reads `probe.store_note` as before, so such a store still migrates.

Differences from a local scan, all small: error texts inside `problems` name
the agent's errors, not the OS's; a database engine's tree totals (`files`,
`bytes`) come from one `list_dir` per folder instead of one `scandir`, so a
huge cluster costs a round trip per folder; and where the agent folded
children into a rollup entry, the totals it summed stand in for them.

Nothing here logs a path. A store inside a redacted folder is never listed, so
it is never reached, and the messages above name only paths inside a store.

**What the agent must provide: nothing new.** `list_dir`, `measure` and
`read_range` do it.

### 4.4 Migrating existing catalogs

`filecat rollups migrate [--tags TAG ...] [--root R] [--dry-run] [--batch N]
[--checkpoint FILE]` converts stored records to rollups without a rescan:
listed-only `backup_data` / `db_data` rows under a store, and anything the
current rules match (so it also performs the `[REDACTED]` purge of
section 3.5). Crash-safe and resumable like `samples migrate`, per rollup
target `T` (a store child, or a rule match):

1. **Plan.** Read-only. Find the targets: dir records with
   `probe.backup` / `probe.database` and their `rollup_children`; stored
   records whose path a rule matches (first match, same matcher as scans).
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

### 4.5 Verify levels

`--verify-backups` is no longer a boolean. It takes a level:

| Level | Checks | When |
|---|---|---|
| 0 | nothing: the manifest summary is recorded (`probe.backup.checked = "none"`) and the pool is only summed | default |
| 1 | the pool's total bytes and file count against the manifest's (`checked = "totals"`; today's totals-only check) | v0.2.0 |
| 2 | every file the manifest names exists with its size | v0.2.x |
| 3 | the files' hashes, as the backup application would check them | v0.2.x |

A bare `--verify-backups` means level 1 (the cheapest check that needs no new
agent command). It used to turn on the per-file Hyper Backup comparison; that
comparison is level 2, and until it ships `--verify-backups=2` and `=3` are
refused with a message naming `--measure-backups`, which still gives per-file
rows for a store. Levels apply to stores that are rolled up and are recorded
in `probe.backup.checked` and `problems`. A per-store level goes in
`filecat.toml` in v0.2.x: `[[rollups.backup_store]] path = '...' verify = 2`
(the CLI level is the default for stores that do not say).

**Sketch of level 2 through the agent, without per-file rows.** Python reads
the manifest (through `StoreFS`, 4.3) into a list of expected `(relative path,
size)` pairs and sends them in batches of a few thousand to a new agent
command, `check_files`: `{base, items: [{"i": manifest index, "p": path,
"s": size}]}`. The agent `lstat`s each item and answers with counts and only
the items that fail: `{checked, ok, missing: [i, ...], size_mismatch: [i,
...]}` (indexes into the batch, capped). Python keeps the totals and at most 20
examples (manifest ids, not file names beyond what the manifest itself holds)
in `probe.backup.verified = {level, checked, missing, size_mismatch,
examples}`. A pool of 500,000 files is about 100 requests; nothing is stored
per file. Level 3 adds a `hash` kind to the batch item and needs a per-format
recipe, which is why it is later.

## 5. Default tags

Built-in rules apply only to a type whose mode is `automatic` (section 2); for
a `manual` type they produce suggestions, for a `disabled` one nothing.
`filecat rollups rules` lists them with each type's mode.

| Tag | Built-in patterns (all `case = "insensitive"`) | Notes |
|---|---|---|
| `[CACHE]` | `type=dir`: `__pycache__`, `node_modules`, `.cache`, `**/AppData/Local/Temp`, `**/AppData/Local/Microsoft/Windows/INetCache`, `**/AppData/Local/CrashDumps`, `**/.gradle/caches`, `**/.npm/_cacache`, `**/Library/Caches` | the unambiguous ones. Not `Temp` or `tmp` by bare name |
| `[SYNOLOGY]` | `type=dir`, by name: `@eaDir`, `#recycle`, `#snapshot`, `@Recycle`, `@tmp`, `@SynoEAStream`, `@appstore`, `@appdata`, `@apphome`, `@database` | name patterns apply at any depth; these names are harmless off a Synology. `@docker`, `@iSCSI`, `@Repository` are not here: they are `exclude` or the storage topology's business |
| `[WINDOWS]` | `System Volume Information`, `$Recycle.Bin` (dir, any depth); files `?:\pagefile.sys`, `?:\hiberfil.sys`, `?:\swapfile.sys` (local form) and `\\*\*$\pagefile.sys`, ... (the administrative share form) | the former default skips (below) |
| `[BACKUP]`, `[DATABASE]` | not patterns: section 4 (`automatic` rolls up detected stores) | |
| `[REDACTED]` | none: only user rules, markers and the sticky store | always on |

**The default skips are a rollup only under `windows = "automatic"`.**
`DEFAULT_SKIP_DIRS` (`$Recycle.Bin`, `System Volume Information`) and
`DEFAULT_SKIP_ROOT_FILES` (`pagefile.sys`, `hiberfil.sys`, `swapfile.sys` at a
drive's root) are today skipped entirely, so the space they take is missing
from every total; that stays the behaviour in `manual` and `disabled`, so no
existing catalog changes. With `windows = "automatic"` the same names become
the built-in `[WINDOWS]` rule: the skip is replaced, the space shows as a
rollup and is still not read. `--no-default-skips` keeps its meaning (walk and
measure them) and also turns that rule off. `should_skip_dir`,
`should_skip_root_file` and the two constants stay as the non-automatic
path; their patterns are also in the vectors so both paths agree on names.
`System Volume Information` is unreadable to a normal account: its rollup is
`size 0` with `partial: true` and `error_codes.permission_denied: 1`, and
(section 1) no `errors` entry, so the exit code stays 0.

`--exclude` and `[[agents]].exclude` are untouched and still win.

Windows equivalents for local scans: `C:\Users\*\AppData\Local\Temp` and
`INetCache` (`[CACHE]`), `$Recycle.Bin`, `System Volume Information`,
`pagefile.sys`, `hiberfil.sys`, `swapfile.sys` (`[WINDOWS]`). `Windows\WinSxS`
and `Windows\Installer` are not built in: they are real data a person may want
listed; a user rule can roll them up (`**/Windows/WinSxS`).

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
| `filecat rollups list` / `suggest` | counts by tag and parent folder; suggestions per root (section 2). Web screens for both are v0.2.x |
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
  bytes (the dedup ratio), the `checked` badge (none, totals; later
  files, hashes), and the command to verify with `--verify-backups=N`.
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

- **Rules and markers (`[REDACTED]`, `[CACHE]`, `[SYNOLOGY]`, `[WINDOWS]`, user tags):
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
   "type", "case", "keep", "private", "suggest"}` (`id`: the rule's index;
   `tag` omitted when `keep`; `match`: patterns already normalised **and
   converted to agent form by the client**; `suggest`: count matches, fold
   nothing). Not a tag-to-patterns map: the order across tags, `keep`, `type`,
   `case`, `private` and `suggest` are per rule.
2. The agent matches **literal host paths** (the child's absolute path from
   `/`), name patterns against the child's name, suffix patterns (`**/...`)
   against the tail. There is no match path built by the client
   (`redaction` carries one `base` per root, for the hash only). Default `case` is sensitive.
3. `policy.markers`: `[{"name": ".filecat-cache", "tag": "[CACHE]", "private":
   false}]`, the marker names to look for. The agent hardcodes none.
4. `policy.redaction`: `{"key": hex, "roots": [{"root", "base", "hashes":
   [...], "inodes": [[dev, ino], ...]}]}`: the HMAC key (memory only, never
   logged) and, per root being scanned, the base path of the root, the path
   hashes and the `(dev, ino)` pairs of folders to treat as `[REDACTED]`
   (section 3.7). Limits: 10,000 hashes and inodes per root.
5. `policy.exclude` as before. `rollup_groups` and `bases` are gone.
6. Implement the matcher of section 2 exactly (name, path and suffix
   patterns, `?`, `*`, `**`, ASCII case folding when `case` says so, `type`,
   first match, `keep`) and the HMAC of section 3.7 byte for byte, pass
   `tests/data/rollup_match_vectors.json`, and answer with the wire
   `policy_id` (section 2), `rules`, `markers`. Limits: 1024 rules, 64 KiB of
   patterns in total, 4096 bytes per pattern; more is `bad_request`.

**`list_dir`**

7. Apply `exclude`, then for each child in the order of section 2: sticky
   redaction (hash or `(dev, ino)` in the policy's sets), the `[REDACTED]`
   rules, markers, the other rules; partition into recorded entries and
   rollups. Rules with `suggest` never partition: the matches are only
   counted.
8. **Markers**: for each child directory it is about to return or fold, `lstat`
   (`fstatat`) every marker name of `policy.markers` inside it **before the
   child's contents are read for any other purpose**, and fold a marked child
   into a rollup. The cost is one `lstat` per marker name per subdirectory.
9. **Redaction identity**: for each child directory, when `policy.redaction`
   has a root whose `base` contains it, compute the HMAC of its path relative
   to `base` (section 3.7, input and normalisation exactly as specified) and
   compare with `hashes`; compare `(dev, ino)` with `inodes`. A match is
   redacted. For every directory folded into a `[REDACTED]` rollup, return
   `folded: [{"h", "dev", "ino"}]`.
10. A rollup entry per tag with these fields, all required: `name` (the tag),
    `kind: "rollup"`, `size`, `allocated_size`, `ino: 0`, `dev`, `nlink: 1`,
    `mtime_ns`/`ctime_ns` (newest), and `rollup` = `{tag, matched,
    total_files, total_dirs, total_size, total_allocated_size,
    newest_mtime_ns, oldest_mtime_ns (left out with no files), errors,
    error_codes, vanished, skipped_mounts, hardlink_names, complete}`, plus
    `folded` for `[REDACTED]`. Optional later: `by_suffix`, `age` (never when
    the rule is `private`).
11. Reply `suggest: [{"tag", "matched"}]` for the directory when `suggest`
    rules matched, and `policy_id`.
12. A real child whose name equals a rollup's tag (ASCII case-insensitive) in
    this folder is folded into it, counted in `matched`, not listed.
13. Names of folded children never leave the agent: not in `entries`, not in
    `error` objects, not in `folded`, not in any rollup field.
14. Accept `progress_ms`, `deadline_ms`, `id` on `list_dir` (rollups can make it
    slow).

**`sum_subtree`**

15. Request: `path`, optional `one_filesystem` (default true), `exclude`
    (patterns relative to `path`, same syntax, matched against the path
    below `path`), `private` (default false), `threads` (1 to 16; agent
    default 4), `progress_ms`, `deadline_ms`, `id`, `detail` (reserved).
16. Reply: the counters of a rollup entry (`total_files`, `total_dirs`,
    `total_size`, `total_allocated_size`, `newest_mtime_ns`,
    `oldest_mtime_ns`, `errors`, `error_codes`, `vanished`,
    `skipped_mounts`, `hardlink_names`, `complete`) and `path` only when not
    `private`.

**Both**

17. `lstat` only, never follow links; a link is a file of its own size. The
    basis for "same file system" is the `dev` of the folder being summed (a
    btrfs subvolume or snapshot nested inside is a different `dev` and is
    skipped and counted in `skipped_mounts`). The summed folder itself counts
    in `total_dirs`.
18. Hard links: `(dev, ino)` for `nlink > 1`, one set per rollup entry or per
    `sum_subtree` request, cap 2 million entries (then count without dedup and
    set `hardlinks_approx: true`).
19. Errors: counted by protocol code, `permission_denied` and `io`; an entry
    that disappears is `vanished`, not an error. Never a message or a path.
    Recursion is iterative; depth limit 4096 (deeper is an `io` count).
20. Under a `private` rule, a `[REDACTED]` match or request, no log line, no
    metric, no panic message may contain a path, a name or an OS error text;
    the key is never logged.
21. `progress_ms` lines and cancellation as in section 7: check a shared flag
    every 1024 entries; `cancel` on another connection by `id`.
22. Concurrency: at most 4 sums run at once per agent by default (config); a
    fifth gets `code: "busy"` and the client retries after a pause.

**Later (v0.2.x, not in the first agent)**: `check_files` for verify level 2
(section 4.5).

## 9. Python work plan

Stage A is implemented (see the notes at the end of this section for where it
differs from the text). The sticky hash input is `"filecat-redact-v1\0" +
root + "\0" + rel_path` (NUL bytes; the first draft of the protocol page used
spaces), and the wire policy id is defined in agent-protocol.md.

The next step, in two stages. Changes by file, then commands, then tests.
Stage A is complete for the opt-in model and everything `[REDACTED]`: rules,
modes, markers, redaction, the sticky store, records, the walker for local,
SMB and agent scans, the privacy test, and the commands that audit it. Stage B
adds store rollups, verify levels 0 and 1, `rollups migrate` and the reports.
After A nothing changes unless the user opts in, so A can ship alone.

### Stage A: rules, modes, markers, redaction, records, walker

**New modules**

- `src/filecat/rollup.py`: `normalize_pattern`, `pattern_form`, `Rule`,
  `RuleSet.compile(config, modes)`, `RuleSet.match(path, name, is_dir)` ->
  `Rule | None` (name, path, suffix patterns; `case`; `type`; `keep`), the
  converters `to_agent_form(rule, sharemap)` / `to_share_form(rule, sharemap)`
  (using `ShareMap`, reporting unresolved patterns), `catalog_policy_id`,
  `wire_policy_id`, `to_wire()`, `partition(entries, parent)`; `Totals`
  (counters, `merge`, `to_probe`); `sum_tree(...)` (section 3.2);
  `classify(exc) -> code`; `RollupError`; `new_rollup_document(...)`; marker
  helpers (`marker_names(config)`, `find_marker(child_path)`).
- `src/filecat/redaction.py`: key handling (`load_key`, `new_key`, `key_id`,
  `FILECAT_REDACT_KEY_FILE`), `path_hash(key, root, rel_path)`, the sticky
  matching (`StickySet.match(root, rel_path, dev, ino)`), registering and
  renaming entries from rollups (`folded`), `release`, `approve`.
- `src/filecat/rollups_cmd.py`: `filecat rollups {rules,list,suggest}` and
  `filecat rollups redacted {list,release,approve}`.

**Changed**

- `record.py`: `KINDS += "rollup"`; `NON_FILE_KINDS`; `is_file_kind(kind)`.
- `config.py`: `[rollups]` modes (`automatic`/`manual`/`disabled`, default
  `manual`, `redacted = "disabled"` refused with a warning), `[[rollups.rule]]`
  (tags, patterns, `type`, `case`, `keep`, `private`, `host`),
  `[[rollups.backup_store]]` / `[[rollups.database_store]]` (`path`, stage B),
  user tags; errors that never echo a private pattern; reject
  `[[agents]].rollup_groups`; `AgentConfig.policy()` loses it; `config
  show`/`agents list` mask private patterns (`agents_cmd.py`).
- `options.py`: `modes`, `rules`, `rollup_workers`, `rollup_timeout`;
  `cli.py`: `--rollup TYPE=MODE`, `--rollup-workers`, `--new-redaction-key`;
  `--no-default-skips` also removes the `[WINDOWS]` rule.
- `walker.py`: `_make_frame` checks the redaction store and the markers of each
  child directory before it is listed, read ahead or recorded, partitions
  entries (rolled vs recorded, reserved tag names), keeps `frame.rolled`;
  `_will_enter` applies the same partition; a rolled group is summed in a
  `rollup_pool` (or taken from the agent's rollup entries) and written after
  the frame's files and before its dir record; `child_count` = recorded +
  rollups; `mark_dir_complete(child_dirs=)` only recorded names;
  `_delete_stale_children` uses the new `current` set, `delete_many`, handles a
  rollup replacing a real entry, and forces the stale pass when a rollup
  appears where none was stored (a marker added to a folder whose parent did
  not change); suggestions counted and stored on the root index; the
  catalog-policy handling (`probe.rollup_policy`); `windows = "automatic"` swaps
  the skip for the `[WINDOWS]` rule (otherwise `should_skip_*` unchanged).
- `fsource.py`: `AgentSource._entry` turns `kind: "rollup"` into an
  `AgentRollup` that the walker takes from the listing instead of skipping;
  `AgentSource` sends `configure_policy(rules in agent form, markers,
  redaction, exclude)` for each root, checks the wire `policy_id`, registers
  `folded`; `sum_subtree` wrapper with progress, deadline, `cancel`.
- `agent_client.py`: `configure_policy(rules, markers, redaction, exclude)`,
  streamed `progress` lines in `_call`, `sum_subtree(path, **options)`,
  `cancel(id)`, the new error codes, `DirEntry.rollup` and `suggest` fields.
  `ShareMap` itself is unchanged (conversion uses `to_posix_path`,
  `to_catalog_path`, `canonical`).
- `backends/base.py` and every backend: `delete_many`, `purge_dropped_paths`,
  `rollups(root, prefix)`, `rollup_totals(root)` (also by parent folder), the
  `redactions` store (section 3.7), root-index `suggestions`; `browse.py` and
  the SQL in `sqlite/postgres/mysql/mssql/mongodb` for `NON_FILE_KINDS`,
  `subtree` `rollup_bytes`, `sizes`.
- `aggregate.py`: skip rollups; `rootinfo.py`: `_observe`, `last_scan` and
  `suggestions` fields; `enrich.py`: `NO_CONTENT_KINDS`; `rootcase.py`:
  sampling; `resume.py`: `forget_beneath`; `dupes_cmd.py`: skip rollups;
  `samples.py`/`member_sets.py`: no change beyond tests.

**Tests**

- `test_rollup_match.py`: the shared vectors (three forms, suffix and name
  patterns, `**`, case, type, keep, the HMAC vectors, wire policy ids);
  `ShareMap` conversion both ways, unresolved patterns warn; modes
  (`manual` rolls nothing built-in, `disabled` ignores and warns,
  `redacted = "disabled"` refused); catalog policy id equal for agent and SMB.
- `test_rollup_walk.py`: a tree with `node_modules`, `.cache`, a folder named
  `[CACHE]`, markers of every type; record shape and counts; hard links (via
  fake agent), mount skip; rescan replaces; a marker added later is applied;
  a rolled name was a stored dir: purged, not dropped; policy change relists
  without remeasuring; `windows = "automatic"` versus the unchanged skip;
  exit code stays 0 for denied; suggestions counted for `manual` types and
  never for `redacted`; `rollups list` and `suggest` output.
- Parity: the same tree scanned locally and through the fake agent gives the
  same rollup documents (apart from `via`, `allocated_size`, `summed_at`).
- Redaction: sticky entry created by a marker; marker deleted: still
  redacted; folder replaced (restore) over SMB by path hash; folder renamed on
  the fake agent by `(dev, ino)` and re-registered; `release` then `approve`
  (separate invocations, `--yes`, pending still redacts); a lost key stops the
  scan unless `--new-redaction-key`; `redacted list` shows no name or hash.
- **Privacy test** (`test_rollup_privacy.py`): a tree with a redacted subtree
  whose folder, file and sub-folder names are distinctive tokens
  (`ZXQ-folder-7f3a`, ...) including one unreadable folder and a non-UTF-8
  name; redacted by a rule, by a marker (its content is never read), and by
  the sticky store. Scan it three ways: locally, over the fake agent, and over
  the fake agent with a monkeypatched `os.scandir` that raises
  `PermissionError` with the file name in the message. Capture and search for
  every token (plain, U+F700-mapped, UTF-16, base64 of the name): stdout and
  stderr (progress, preflight, start line), `caplog` at DEBUG for all loggers,
  the exit exception text and a formatted traceback, every table of the
  backend (`files`, `dropped`, `members`, `samples`, `roots`, `redactions`,
  treemaps, via `backend.list()` and `list_dropped()` and a raw dump of the
  SQLite file), the resume file, the checkpoint, `filecat summary|roots|dupes|
  show|rollups`, `filecat serve` API responses, and the fake agent's **wire
  log** (every request and response line, which the fake records; a marked
  folder's contents must never be listed on the wire). Plus the purge test:
  scan with no rule (tokens present, with samples and members), add the rule,
  rescan, and assert the tokens are in none of those places, `dropped` is empty
  for the path, pinned treemaps are rewritten, and `samples prune` leaves
  nothing. A direct check: `rollup.sum_tree` is called with `os.scandir`
  patched to raise, and the raised exception's `str`, `repr`, `__cause__` and
  `__context__` are searched.
- Config: rule validation errors never print a private pattern; masked
  `config show`.

**Fake agent** (`tests/_fake_agent.py`) is extended to the contract of
section 8: rules in agent form with a second small independent implementation
of the matcher (or the vectors only; importing `filecat.rollup` would test the
matcher against itself), the HMAC, `markers` (lstat inside each child), the
`redaction` sets and `folded`, `suggest`, wire `policy_id`,
`type`/`case`/`keep`/`private`, `oldest_mtime_ns`, `error_codes`, `vanished`,
`skipped_mounts`, `hardlink_names`, hard links by `(dev, ino)` across the
group, same-`dev` rule, `sum_subtree` options, `progress_ms` lines,
`deadline_ms` -> `complete: false`, `cancel`/`id`, `busy`, a wire log of every
line for the privacy test, and a way to make a child unreadable, to rename a
folder keeping its inode, and to inject names with bytes that are not UTF-8.

**Differences in the implementation of A**

- Markers on local and SMB scans come from the child's listing, not `lstat`s
  (section 3.6).
- A rollup entry from an agent may carry an optional `rule` field (the id of the
  first rule that folded something in, `"marker"` or `"sticky"`); without it
  `rollup.rule` is `agent`.
- `hardlink_names` is stored only when the agent reports more than 0.
- Python sums are `sum_tree`, one thread-pool task per folded child
  (`--rollup-workers`); a `rollup_timeout` option exists but has no flag.
- One `configure_policy` serves every root of an agent in a scan: the rules and
  markers are the same, and each root has its own `redaction.roots` entry
  (found by its `base`). It is sent before the preflight listing, so not even
  that listing carries the name of a folder that is rolled up.
- A purge (names now rolled up that the catalog held) deletes them, their
  members and dropped entries, prunes samples and member sets, deletes the
  unpinned treemap snapshots of the root and merges the folders of a pinned
  one into `[REDACTED]`, clears `last_error` and `newest_file` when they
  pointed there, and on SQLite runs `VACUUM` (with `secure_delete`) after the
  aggregates were rebuilt, so the names are not left in a free page or the
  write-ahead log. A pinned snapshot cut above the purged folder still carries
  the enclosing folder's extension bytes.
- A real child named like a tag is folded into the rollup when the rollup comes
  from a rule or the sticky store; for one made by a marker found later, only
  if the child is not yet reached.
- `Backend.scrub()` (a no-op except SQLite), `Backend.delete_many`,
  `purge_dropped_paths`, `rollups`, `rollup_totals` and the `redactions`
  methods are on every backend; the server backends are written but only
  exercised when their DSN variables are set.

**Order inside A**: (1) record, matcher, vectors, modes and config;
(2) redaction key, hash, `redactions` store; (3) Python walk, markers, sums,
`delete_many`, readers needed to keep the catalog consistent (aggregate,
browse, enrich, dupes skip); (4) the agent client and fake agent; (5) the
privacy test; (6) `rollups list|suggest|redacted`.

### Stage B: stores, verify levels 0-1, migrate, reports

- `data/store_formats.json`: `rollup_children`; `tests/test_store_formats.py`.
- `backup/__init__.py`, `dbfiles/__init__.py`: `Store.rollup_children(names)`;
  `summarize(..., rollup_totals=)`; `backup/hyperbackup.py`: totals check at
  level 1, `probe.backup.checked`.
- `walker.py`: store rollups (`automatic` or a listed store path),
  `_backup_summary` passes `rollup_totals`, `--verify-backups[=0|1]`,
  store fingerprint carry-forward (`store_resum`).
- `rollups_cmd.py`: `filecat rollups migrate` (section 4.4), including
  registering sticky entries for migrated `[REDACTED]` targets.
- `summary.py`: Rollups table and totals line; `roots_cmd.py`: rollup line;
  `treemap.py`: `build(..., rollups=)`; `serve.py`: pass rollups into
  `treemap.build`, `/api/subtree` `rollup_bytes`; `web/index.html`: tile
  drawing for `folder.rollup`, the inspector card per tag, no zoom on a
  rollup tile; `dupes_cmd.py`: the "not examined" line.
- Tests: a fake Hyper Backup store gives `[BACKUP]` plus `probe.backup`
  (`checked: "none"` at level 0, `"totals"` at level 1), `--measure-backups`
  keeps rows, `--verify-backups=2` refused, fingerprint carry-forward and
  `store_resum`, the DB engines; migration kill points (after phase 1, after k
  batches of phase 2, before phase 3), resume, twice, `--dry-run`; readers
  (summary, roots, browse filters, `subtree`, treemap tile and pin diff,
  `dupes` line, the SQL and in-memory backends in `test_backend_contract.py`).
- `StoreFS` (manifests through the agent, section 4.3) followed as its own step; see there.

**Stage B is implemented.** Where it differs from the list above:

- *Where the code is.* The store decision is made in the walker's
  `_make_frame` after the listing is partitioned, from the folder's entries
  (`backup.Store.rollup_children(entries)` and `Store.tag` instead of a
  method on names); `rollup_children` is read from `store_formats.json` and
  `tests/test_store_formats.py` checks it against the code. A store rollup
  is a `rollup.Group` with `.store` set, summed with `rollup.sum_tree` on an
  SMB or local scan and with `AgentSource.sum_subtree` (progress, deadline,
  cancel) through an agent. A real child named `[BACKUP]` and a `[BACKUP]`
  from a rule or marker in the same folder are folded into the store's group.
  A store's folder is matched against `[[rollups.backup_store]]` paths as
  recorded, as read, and (agent) in the agent's POSIX form, ignoring case.
  Names rolled up by a store are not "purged" (no redaction cleanup, no
  treemap deletion): they are not secret; the rows are deleted, not dropped.
  The read-ahead lister does not list a store's bulk folders.
- *`summarize(..., rollup=, level=)`.* Instead of `rollup_totals=`; a format
  opts in with `uses_rollup`. `rollup` is `{"children", "files", "bytes",
  "partial"}`; `listing` is still passed (the files outside the rolled
  folders are compared with it at level 1). `probe.backup.checked` is set on a
  rolled backup store only (`"none"` or `"totals"`); a store that is listed per
  file has no `checked`, and a database folder never has one.
- *Hyper Backup, level 1.* Guard's bytes under `Pool/` must equal the
  pool's; the file count may be higher (files Guard does not list, such as
  `.lock`) and is noted in `guard.rollup.unlisted_files`, not reported as a
  problem; fewer is a problem. Files outside `Pool/` are compared with the
  listing as before (`guard.missing`, `guard.size_mismatch`). A partial sum
  (read errors) is not compared and says so.
- *`--verify-backups`.* `=0|1|2|3` or bare (rewritten to `=1` before argparse
  sees it, so it cannot swallow the root). The refusal names `--measure-backups`.
  Veeam's and Google Workspace's own metadata reads stay on the flag from
  level 1 (they are not the per-file comparison the design moves to level 2);
  Hyper Backup's whole-target CRC32 read is `verify_level = 2`, which no CLI
  level reaches in v0.2.0.
- *Fingerprint.* A format lists the manifest files `summarize()` reads
  (`manifests`: Hyper Backup, ABB); the fingerprint is the SHA-256 of the store
  folder's mtime, the name, size and mtime of every entry in it (the rolled
  folders included), and those files' size and mtime (an agent: `measure` with
  `hash: "none"`). Folder mtimes are `lstat`ed, not taken from the listing
  (NTFS shows them late). A format without `manifests`, and every database,
  is summed every scan. The stored rollup is carried only when it is complete,
  made under the same rule-set id, and `matched` is unchanged.
- *Reporting.* `rollup_bytes` / `rollup_files` are added to `/api/subtree`
  rows by `browse.with_rollups` in `serve`, not inside each backend's
  `subtree`; a folder holding only rollups appears. `/api/record` of a store
  rollup carries `store_record` (the store's `probe.backup` / `database` /
  `store_note`). Clicking a rollup tile opens its record (the inspector card)
  instead of zooming. `summary` prints "-- Rollups --" before the totals and a
  "recorded files ...; rollups ...; together ..." line; `roots` adds a
  "rollups" line; `show` prints a one-line summary to stderr; `dupes` prints
  "not examined" to stderr and, with `--json`, a final `{"rollups_not_examined":
  ...}` object.
- *`rollups migrate`* is in `rollup_migrate.py`. It takes `--tags`, `--root`,
  `--dry-run`, `--batch`, `--checkpoint`, `--progress-interval`, `--rollup
  TYPE=MODE`. The plan finds rule targets (one pass over the root's records
  through the same matcher a scan uses, so user rules, the sticky store and
  automatic built-ins all count) and store targets from the stored
  `probe.backup` / `probe.database` / `probe.store_note`. The rollup is written
  with `migrated: true`, `via: "python"`, no `fp` and no `allocated_size`
  unless every row had one; a store whose rows include one that was read (a
  hash) is skipped, as is a target that already has a rollup a scan made; a
  rerun that finds more children than the rollup holds also skips it. Phase 2
  deletes from the front of the sorted rows (deleting shifts the next page to
  the start) and removes each child's own record last, so a rerun still finds
  it. The checkpoint reports where a run stopped; the catalog is what a rerun
  trusts. Phase 3 runs `redaction.cleanup` for `[REDACTED]` targets (and
  registers their sticky entries first), prunes samples and member sets for
  the others, drops resume markers beneath the folded paths, rebuilds the
  root's aggregates and, for `[REDACTED]`, scrubs. It also fixes the parent
  folder's `child_count` and `rollup_tags`. Nothing is migrated through an
  agent; it works on the catalog.

## 10. Open questions

1. **Marker cost over SMB.** Settled: Python takes markers from the child's
   own listing (section 3.6), at no extra I/O. The agent `lstat`s them.
2. **A marker in a scanned root itself** is recorded as one `<root>\[TAG]`
   rollup (3.6). Right, or refuse such a scan?
3. **A bare `--verify-backups` means level 1** and no longer the per-file
   Hyper Backup comparison (now level 2, v0.2.x). Acceptable?
4. **Plaintext redacted patterns in `filecat.toml`** (masked in every output),
   or hashed name patterns as well in v0.2.0? (Recommended: plaintext now.)
5. **`[[agents]].rollup_groups` removed** rather than translated; fine since
   nothing used it?
