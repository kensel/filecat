# filecat-agent wire protocol, version 1

The contract between `filecat` (the Python client, `src/filecat/agent_client.py`)
and `filecat-agent`, the Rust daemon that runs on a NAS (research note
[02](research/02-rust-agent-architecture.md), draft sources in
[research/rust-agent](research/rust-agent/)). The draft `main.rs` came first
and has gaps; this page settles them, and the agent is to be brought into
line with it ([the differences](#differences-from-the-draft-mainrs) are
listed at the end). Where this page and the draft disagree, this page wins.

The agent is a fast, dumb syscall and byte-range engine (note
[05, section 3](research/05-catalog-tuning-agent-boundary.md)): it lists,
stats, hashes, sums and reads, reports file system totals (`statfs`), reads
files that have no size (`read_file`), and runs the read-only commands of a
hardcoded allowlist (`run`; on Windows `wmi`) without interpreting what they
print. Store detection, probing, every manifest parser and the whole storage
topology stay in Python: new rules, formats and platforms never need an agent
rebuild.

## Transport

- TCP, default port 9876, then TLS 1.2 or newer. The agent's certificate is
  self-signed and generated on first start; the client does not validate a
  chain or a host name. It compares the SHA-256 of the DER-encoded leaf
  certificate with the `cert_sha256` in `filecat.toml` and drops the
  connection on a mismatch before sending anything, the token included.
- One JSON object per line, UTF-8, terminated by `\n`. JSON escapes
  newlines, so a line never contains a raw one. A line is at most 8 MiB in
  a request; the agent answers a longer one with `bad_request` and closes the
  connection. Responses have no limit (a `list_dir` of a large directory is
  big).
- Strictly one request, then one response, in lockstep, on a connection.
  The client sends the next request only after it has read the previous
  response. No pipelining, no unsolicited messages (a `progress` line is
  never sent unless the request set `progress_ms`). The agent serves each
  connection on its own thread, so a client wanting parallelism opens
  several connections; each has its own authentication and its own policy.
  One exception, only when the request asks for it: a long `list_dir` (with
  rollups) or `sum_subtree` may send `progress` lines before its response
  ([progress and cancellation](#progress-deadline-and-cancellation)).
- The agent may close an idle connection at any time. A client that finds
  its connection closed reconnects, authenticates again and sends its policy
  again; every command is safe to repeat.
- Unknown request fields are ignored. An unknown `cmd` or a line that is not
  a JSON object is a `bad_request`; the connection stays open.

## Requests and responses

A request is `{"cmd": "...", ...}`. A response is either

```json
{"ok": true, ...}
{"ok": false, "error": "human-readable text", "code": "not_found"}
```

| `code` | Meaning |
|---|---|
| `unauthorized` | the command needs `auth` first, or the token was wrong |
| `bad_request` | malformed request, missing or invalid field, a `len` over the maximum, a path that is not absolute, or the wrong kind of file (`list_dir` on a file, `measure` on a directory or a link) |
| `not_found` | the path, or a directory above it, does not exist |
| `permission_denied` | `EACCES` or `EPERM` |
| `io` | any other failure reading the file system, including a file that changed while it was read |
| `cancelled` | the request was stopped by `cancel` (**new**; only when the connection is still open) |
| `busy` | the agent is already running its maximum number of long sums, or of `run` commands; retry later (**new**) |
| `refused` | a `run` argument failed the validation of its argument kind, so nothing was run; or a path is outside the agent's allowed roots, or a content read of a path on its deny list, of a private key, of a credential-blanked file other than by `read_file`, or of a cloud placeholder ([below](#allowed-roots-and-the-deny-list)) (**new**) |

`error` is for people; clients branch on `code`. A client that meets an
unknown code treats it as `io`.

Before `auth` succeeds the agent answers only `hello` and `auth`; every
other command gets `unauthorized`.

### Paths and names

- A `path` in a request is an absolute POSIX path on the agent host:
  starts with `/`, no empty, `.` or `..` components, no trailing `/` (except
  `/` itself). Anything else is `bad_request`. Every command acts on the
  final component without following it if it is a symbolic link; links in
  the directories above are followed by the OS as usual.
- Names and paths are byte strings on Linux, not always UTF-8. **The
  byte-string rule:** a string that came from the OS carries its text as
  `X` (invalid sequences replaced with U+FFFD) and, only when the bytes are
  not valid UTF-8, also `X_b64` with the exact bytes in standard Base64.
  This applies to an entry's `name` and `link_target`. A request addresses a
  path whose bytes are not UTF-8 with `path_b64` in place of `path` (the
  Base64 of the whole path); the client builds it from the parent's bytes,
  `/`, and the entry's `name_b64`. A path that is valid UTF-8 is always sent
  as `path`. Clients that need a lossless round trip decode `X_b64` with
  UTF-8 and `surrogateescape` (what the Python client does).
- What the catalog stores for such a name is the client's business
  (`fsource.py`): each byte `b` of 0x80 to 0xFF that is not part of valid
  UTF-8 becomes the private-use character U+F700 + `b`, so the record is
  valid JSON and database text, and the same mapping is undone when the
  path goes back to the agent. The agent needs to do nothing for it.
- A path the client sends is never rewritten. Mapping between these paths
  and catalog (UNC) paths is the client's job; see
  [Path mapping](#path-mapping-client-side).

### Timestamps

Every `mtime_ns`, `ctime_ns`, `newest_mtime_ns` and `oldest_mtime_ns` is nanoseconds since the
Unix epoch, a JSON integer, **floored to a multiple of 100** (`div_euclid`,
not truncation toward zero, so a time before 1970 also rounds down). A
Windows SMB client sees times as 100 ns FILETIME ticks, so a record built
from an agent must carry the same value as a record built over SMB, or
`mtime_ns` comparisons, rescan skips and `sha256_partial` would all differ
between the two kinds of scan. `ctime_ns` is the birth time (`statx`
`btime`) where the file system has one, else the inode change time; the
SMB scan records the creation time in the same field.

## Commands

### `hello`

Answered before and after `auth`; it reveals nothing secret.

```json
{"cmd": "hello", "label": "scan \\\\nas3\\Apps by kense@DESKTOP"}
{"ok": true, "protocol": 1, "agent_version": "0.2.3", "hostname": "nas-main",
 "os": "linux", "arch": "x86_64"}
```

`label` is optional (0.2.1): a short text saying what the connection is for
(`scan \\nas3\Apps by kense@DESKTOP`, `job nightly-apps: scan`,
`agents status`). The agent keeps at most 200 characters, control characters
removed, and shows it in [`activity`](#activity) and in its status log. It is
not secret and not checked, so it only describes the client's own word.
`filecat` sends it with `hello`; `auth` accepts the same field and the last
one sent wins. A label that is not a string is `bad_request`.

`protocol` is this page's version, an integer. Additive changes (a new
optional field, a new command) keep it; anything else raises it. A client
refuses an agent whose `protocol` it does not implement. `os` and `arch` are
Rust's `std::env::consts::OS` and `ARCH` (`linux`, `x86_64` or `arm`).

### `auth`

```json
{"cmd": "auth", "token": "..."}
{"ok": true}
{"ok": false, "error": "invalid token", "code": "unauthorized"}
```

The token is compared in constant time. After a wrong token the agent waits
about a second, answers, and closes the connection. The token is configured
in the agent's environment (`FILECAT_AGENT_TOKEN`); the agent refuses to
start without one.

### `configure_policy`

**Changed** (rules replace `rollup_groups`; design in [rollups.md](rollups.md)).

```json
{"cmd": "configure_policy", "policy": {
    "exclude": ["/volume1/@docker", "@eaDir"],
    "rules": [
      {"id": 0, "tag": "[REDACTED]", "match": ["/volume1/project/private-project"],
       "type": "any", "case": "sensitive", "private": true},
      {"id": 1, "match": ["**/keep/node_modules"], "keep": true, "type": "any", "case": "sensitive"},
      {"id": 2, "tag": "[CACHE]", "match": ["node_modules", "**/AppData/Local/Temp"],
       "type": "dir", "case": "insensitive"},
      {"id": 3, "tag": "[SYNOLOGY]", "match": ["@eaDir"], "type": "dir",
       "case": "sensitive", "suggest": true}],
    "markers": [{"name": ".filecat-redacted", "tag": "[REDACTED]", "private": true},
                {"name": ".filecat-cache", "tag": "[CACHE]"}],
    "redaction": {"key": "9f2c...64 hex digits...", "roots": [
      {"root": "r_01hf", "base": "/volume1/homes",
       "hashes": ["a3c1e0d94b7f5a2e60c8d1b9f4e37a02"], "inodes": [[2049, 913442]]}]}}}
{"ok": true, "policy_id": "a1b2c3d4e5f6", "rules": 4, "markers": 2}
```

Replaces the connection's policy as a whole (all fields optional, default
empty); a new connection starts with an empty policy. It applies to
`list_dir` (all fields) and to `sum_subtree` (`exclude` only); `measure` and
`read_range` act on the path they are given. The client sends rules already
converted to this host's paths (it knows the share mapping, `ShareMap`);
the agent matches the **literal host path** of each child and knows nothing
of shares. Design: [rollups.md](rollups.md).

- `exclude`: absolute paths or bare names, compared for equality with each
  child's path and name. Excluded entries are neither listed nor counted.
  They are not globs. Applied before the rules.
- `rules`: an ordered array, tried in order for each child, first match wins.
  A rule has `match` (patterns, already normalised and in agent form),
  `type` (`any`, `dir`, `file`; a link or special counts as `file`), `case`
  (`sensitive`, the default; `insensitive` folds ASCII letters in the whole
  pattern), `tag` (a name of the form `[A-Z][A-Z0-9_-]{0,31}` in brackets;
  absent when `keep`), `keep` (a matching child is listed normally and no
  later rule is tried), `private` (the tag's contents must stay secret, see
  below), `suggest` (count the matches, fold nothing: the `list_dir` reply
  reports them) and `id` (the rule's index, for the client's logs).
- Patterns: no separator means a **name pattern**, matched against the
  child's name at any depth; a pattern starting with `**/` is a **suffix
  pattern**, matched against the tail of the child's path; otherwise a **path
  pattern**, matched against the child's whole absolute path
  (`/volume1/homes/jdoe/vault`), anchored at both ends. `?` is one character
  other than `/`, `*` any run of characters other than `/`, `**` as a whole
  component zero or more components (`a/**/b` matches `a/b`). `x/**` matches
  what is inside `x`, not `x`. No character classes, no escapes. Case-
  sensitive unless the rule says `insensitive`; non-ASCII characters are always
  compared exactly. The conformance vectors are
  `tests/data/rollup_match_vectors.json`.
- `markers`: file names to look for **inside each child directory** the agent
  is about to return. For every child directory and every marker name the
  agent `lstat`s `<child>/<name>` before it reads anything else of the child;
  a child that has one is not returned and not entered, it is folded into the
  marker's tag exactly as a rule match would be (a marker is a file of the
  folded folder, counted inside). Cost: one `lstat` per marker name per
  subdirectory. The agent has no built-in marker names.
- `redaction`: sticky `[REDACTED]` folders. `key` is a 32-byte HMAC key in hex
  (kept in memory, never logged, only sent over the authenticated TLS
  channel). Per `roots` entry: `root` (the catalog's root id), `base` (the
  root's absolute path on this host), `hashes` and `inodes`. For each child
  **directory** at or beneath `base`, the agent computes
  `HMAC-SHA256(key, "filecat-redact-v1 " + root + " " + rel)` (NUL bytes) where `rel`
  is the child's path relative to `base`, `/`-separated, no leading or trailing
  `/`, in the catalog's name form (a byte that is not valid UTF-8 is the
  character U+F700 + byte, UTF-8 encoded), no case folding and no Unicode
  normalisation; hex of the first 16 bytes. A child whose hash is in `hashes`,
  or whose `(dev, ino)` is in `inodes`, is redacted: folded into `[REDACTED]`
  like a rule match, whatever the rules and markers say. Limits: 10,000
  hashes and inodes per root. Vectors: the `redaction` table of the same
  file.
- `private`: the agent adds nothing to the rollup beyond counters, writes no
  log line, and puts no path or OS error text in any reply, for matches of that
  rule, of its markers and of the redaction sets.
- The reply carries `policy_id` (the first 12 hex digits of the SHA-256 of
  the compact JSON (`separators=(",", ":")`, UTF-8, no ASCII escaping) of
  `[rules, marker names]`, each rule as `{"tag","match","type","case","keep",
  "private","suggest"}` in that key order with `tag` null for a `keep` rule and
  the booleans false when absent; the client computes the same and treats a
  difference as a failure to scan that root; the reply carries it only when
  the policy has rules or markers). Limits: 1024 rules, 64 KiB of
  patterns in all, 4096 bytes in a pattern; more is `bad_request`.

### `list_dir`

```json
{"cmd": "list_dir", "path": "/volume1/Backup"}
{"ok": true, "path": "/volume1/Backup", "dev": 2049, "mtime_ns": 1761001200000000000,
 "ctime_ns": 1700000000000000000, "entries": [ ... ]}
```

Lists the immediate children, each `lstat`ed, and never recurses (except
into a rollup). `dev`, `mtime_ns` and `ctime_ns` are the directory's own, so
the client needs no second call for a root's record. Entries are sorted by
name bytes; rollup entries are interleaved by their tag. The reply carries
`policy_id` when the connection has rules. A `list_dir` that has to sum
rollups can take minutes: it accepts `progress_ms`, `deadline_ms` and `id`
([below](#progress-deadline-and-cancellation)). When `suggest` rules matched,
the reply also carries `suggest: [{"tag": "[CACHE]", "matched": 3}]` for the
directory (counts, never names).

An entry:

| Field | Meaning |
|---|---|
| `name` | the file name (the byte-string rule applies; `name_b64` when needed) |
| `kind` | `file`, `dir`, `link`, `rollup`, or `other` (socket, FIFO, device: record it, never open it) |
| `size` | `st_size`; for a link the link's own size; for a rollup the tag's `total_size` |
| `allocated_size` | `st_blocks * 512`, the space actually used (a sparse file's is smaller than `size`) |
| `ino`, `dev`, `nlink` | from `lstat`; 0, the directory's `dev` and 1 for a rollup. Hard links share `(dev, ino)`; the client deduplicates |
| `mtime_ns`, `ctime_ns` | see Timestamps; for a rollup both are the newest mtime of a non-directory inside (0 when none) |
| `link_target` | links only: `readlink` text (byte-string rule: `link_target_b64`) |
| `rollup` | rollups only: the summary below (optionally `rule`: the id of the first rule that folded something in, or `"marker"` or `"sticky"`; the client records it as `rollup.rule`) |
| `error` | `{"code": "...", "message": "..."}` when the entry could not be `lstat`ed |
| `attributes` | **Windows agents only** (left out elsewhere): the file's attribute bits from `GetFileAttributesW` / `FindFirstFileW`, as a number, for files and directories. Python reads the recall bits as `cloudfiles.py` does ([below](#cloud-placeholders-windows)) |

An entry whose `lstat` fails is still listed: `name`, `kind` (from the
directory entry's type when the OS gave one, else `other`) and `error`, with
the numeric fields left out. Silently dropping it would hide a file the SMB
scan would have recorded with an error. Only a failure to open or read the
directory itself fails the call (`not_found`, `permission_denied`, `io`).

A rollup entry stands for every child of this directory matched by one
rule's tag (a file or a directory; a directory is summed as `sum_subtree`
does, and counts in `total_dirs`). **Changed**: new fields, marked below.

```json
{"name": "[CACHE]", "kind": "rollup", "size": 48291049216, "allocated_size": 48295198720,
 "ino": 0, "dev": 2049, "nlink": 1, "mtime_ns": 1761001200000000000,
 "ctime_ns": 1761001200000000000,
 "rollup": {"tag": "[CACHE]", "matched": 3, "total_files": 14820, "total_dirs": 312,
            "total_size": 48291049216, "total_allocated_size": 48295198720,
            "newest_mtime_ns": 1761001200000000000, "oldest_mtime_ns": 1500000000000000000,
            "errors": 2, "error_codes": {"permission_denied": 2}, "vanished": 0,
            "skipped_mounts": 0, "hardlink_names": 12, "complete": true}}
```

| `rollup` field | Meaning |
|---|---|
| `tag`, `matched` | the tag; children of this directory folded in (a real child named like the tag, ignoring ASCII case, is folded in too and is not listed) |
| `total_files` | names that are not directories (files, links, specials) |
| `total_dirs` | directories inside, the matched ones included |
| `total_size`, `total_allocated_size` | logical and `st_blocks * 512`; a file with `nlink` over 1 counts once per `(dev, ino)` across the whole entry |
| `newest_mtime_ns`, `oldest_mtime_ns` | over non-directory entries; both left out when `total_files` is 0 (**new**: `oldest`) |
| `errors`, `error_codes` | entries or directories that could not be read, and the count per protocol `code` (`permission_denied`, `io`). Codes only: no name, path or message (**new**: `error_codes`) |
| `vanished` | entries that disappeared during the sum; not errors (**new**) |
| `folded` | `[REDACTED]` entries only: `[{"h": hash, "dev": n, "ino": n}]` for each directory folded in (at most 1000; `folded_truncated: true` past that), so the client can register sticky entries and follow a rename without ever receiving a name (**new**) |
| `skipped_mounts` | directories on another `dev` than the summed child's, not entered or counted (**new**) |
| `hardlink_names` | names beyond the first of a hard-linked file, whose size was not added again (**new**; may be left out) |
| `hardlinks_approx` | present and true when the hard-link set hit its limit (2,000,000 entries) and later links were counted twice (**new**) |
| `complete` | false when `deadline_ms` ended the sum early; the totals are then a lower bound (**new**) |

The names of what is inside never leave the agent, whatever the rule; for a
`private` rule the entry also has no optional breakdown and the agent logs
nothing about it. `matched` was `matched_Folders` in the draft.

### `measure`

```json
{"cmd": "measure", "path": "/volume1/Backup/a.zip", "hash": "auto", "head_bytes": 8192}
{"ok": true, "size": 123456, "mtime_ns": 1761001200000000000,
 "head_b64": "UEsDBA...", "sha256": "e3b0..."}
```

`hash` is `auto` (default), `full` or `none`; `head_bytes` defaults to 8192
and at most 1 MiB (`bad_request` above). The path must be a regular file.

The agent opens the file (refusing a symbolic link), takes `size` and
`mtime_ns` from `fstat` on that open handle (so they describe the bytes it
reads), floors `mtime_ns` to 100 ns, and returns both: the client records
exactly these values, not those of an earlier `list_dir`. `head_b64` is the
first `min(size, head_bytes)` bytes, whatever the hash policy.

The digest reproduces `src/filecat/hashing.py` exactly, with its constants
fixed in protocol 1: cutoff 64 MiB (67108864), edge 1 MiB (1048576).

| size | `auto` | `full` | `none` |
|---|---|---|---|
| 0 | no digest | `sha256` of the empty string (`e3b0c442...b855`) | no digest |
| 1 B to 64 MiB | `sha256` of the whole file | same | none |
| over 64 MiB | `sha256_partial` | `sha256` of the whole file | none |

**Files the agent does not read.** Two kinds of file are answered with
`size` and `mtime_ns` only, plus `unread` and no `head_b64`, `sha256` or
`sha256_partial`, whatever `hash` and `head_bytes` say (the head and the digest
of the bytes never leave the agent):

| `unread` | When | Also |
|---|---|---|
| `private_key` | the head of the file is a private key ([Private keys](#private-keys-by-content)) | |
| `cloud_placeholder` | Windows: the attributes include `RECALL_ON_DATA_ACCESS` (0x400000), `RECALL_ON_OPEN` (0x40000) or `OFFLINE` (0x1000) ([below](#cloud-placeholders-windows)) | `attributes`: the bits. The file is not opened: the sizes come from `lstat` |

The client records such a file from its directory entry with
`probe.secret: "private_key"` or `probe.cloud`, exactly as a scan of the same
file from disk or over SMB does. A file on the deny list is not answered this
way but with `refused` (it is not read at all, not even for a size); the
client records that as `probe.secret: "denied"`, not as an error.

The response carries at most one of `sha256` and `sha256_partial`, lowercase
hex, and the field is left out (not `null`) when there is none. A partial
digest never goes in `sha256`. `sha256_partial` is one SHA-256 fed, in this
order:

1. the first 1 MiB of the file;
2. the last 1 MiB (`size - 1 MiB` to the end; the windows cannot overlap
   because `size` is over 64 MiB);
3. `size` as 8 bytes, big-endian, unsigned;
4. `mtime_ns` as 8 bytes, big-endian, **signed**.

**The `mtime_ns` in step 4 is the value floored to 100 ns.** Over SMB,
Windows reports a file's modification time in 100 ns ticks, so the digest
of an SMB scan is computed from a time that is a multiple of 100 ns. The
agent sees the true nanoseconds; it must floor them before step 4 and
before returning `mtime_ns`, or the digest of the same file would differ
between an agent scan and an SMB scan, and its records would not
deduplicate against the older ones. (This replaces the draft's
`smb_tick_quantize` flag: there is no unquantized mode.)

If the file turns out shorter than `size` while it is read (it was
truncated), the call fails with `io`.

### `read_range`

```json
{"cmd": "read_range", "path": "/volume1/Backup/a.zip", "offset": 1048576, "len": 65536}
{"ok": true, "data_b64": "...", "eof": false}
```

`len` is 0 to 4 MiB (4194304) inclusive; more is `bad_request`, and the
agent checks before it allocates. The agent reads until it has `len` bytes
or reaches the end of the file, so a short `data_b64` means the end was
reached; `eof` is true when the data ends at or past the file's end. An
`offset` at or beyond the end returns empty data and `eof: true`. The path
must be a regular file. A client reading more than 4 MiB sends several
requests. Disk images, ZIP central directories and PE headers go through
this. Like `measure`, it is `refused` ("denied by agent policy") on a private
key (the agent reads the first 256 bytes of the file to see, whatever the
offset), on a [credential-blanked file](#files-served-with-credentials-blanked)
and, on Windows, on a cloud placeholder.

### `sum_subtree`

**Changed** (options and fields added).

```json
{"cmd": "sum_subtree", "path": "/volume1/Backup/NAS.hbk/Pool", "one_filesystem": true,
 "exclude": ["**/@tmp"], "private": false, "threads": 4,
 "progress_ms": 5000, "deadline_ms": 21600000, "id": "7d3f0c2e"}
{"ok": true, "path": "/volume1/Backup/NAS.hbk/Pool", "total_files": 512004,
 "total_dirs": 4210, "total_size": 48291049216, "total_allocated_size": 48295198720,
 "newest_mtime_ns": 1761001200000000000, "oldest_mtime_ns": 1500000000000000000,
 "errors": 0, "error_codes": {}, "vanished": 0, "skipped_mounts": 0,
 "hardlink_names": 0, "complete": true}
```

The same totals as a rollup entry, for one directory the client names: the
rollup of a backup pool without a row per bucket. `lstat` only, never
follows symbolic links (a link counts as a file of its own size), and stays
on the file system of `path` (a different `dev` is skipped, counted in
`skipped_mounts`, not entered; `one_filesystem: false` enters it). The
directory itself is counted in `total_dirs` (**changed**: the first version of
this page did not count it; the client's rollup record and a `sum_subtree` of
the same folder now agree). `total_files` counts names (every non-directory
entry); `total_size` and `total_allocated_size` count a file with `nlink`
over 1 once per `(dev, ino)` within the request. The policy's `exclude`
applies; the policy's `rules` do not. `errors` counts entries and directories
that could not be read, so a total with `errors` over 0 is a lower bound.
Options:

| Option | Meaning |
|---|---|
| `one_filesystem` | default true |
| `exclude` | patterns, syntax of `configure_policy`, matched against the path below `path` (`**/@tmp`, `Pool/lost`) |
| `private` | default false. When true: the reply has no `path`, the agent logs nothing about the walk, no reply field carries a name or message |
| `threads` | 1 to 16; the agent's default (4) when omitted. A walk is `lstat` bound, so a few threads help on RAID |
| `progress_ms`, `deadline_ms`, `id` | [below](#progress-deadline-and-cancellation) |
| `detail` | reserved: `["by_suffix", "age"]`, not in the first agent |

It can take minutes on a big tree (5 million files: 1 to 15 minutes), so a
client sets `progress_ms` and does not depend on a long timeout.

### Progress, deadline and cancellation

**New.** `list_dir` (when rollups are summed) and `sum_subtree` accept:

- `progress_ms` (at least 500): while the request runs the agent writes, at
  that interval, `{"progress": {"entries": 1204113, "bytes": 8123456789}}` lines
  (no `ok` key), then the ordinary response. The client reads lines until one
  has `ok` and restarts its read timeout at every line. Counters only, never a
  name, even without `private`. An agent that does not implement the field
  sends no progress; a client that did not ask never receives any.
- `deadline_ms` (default 21,600,000, six hours; at most 86,400,000): when it
  passes the agent stops and answers `ok: true` with the totals so far and
  `complete: false`. The client does not store such a total as a result.
- `id` (a client-chosen string up to 64 characters): names the request so it
  can be cancelled.
- Cancelling: a running request stops, and answers `code: "cancelled"` if the
  connection is still open, when (a) a `cancel` for its `id` arrives on another
  authenticated connection, or (b) a `progress` write fails (the client closed
  the connection). The deadline is not a cancellation: it ends with
  `complete: false`. The agent tests its flag at least every 1024 entries.

```json
{"cmd": "cancel", "id": "7d3f0c2e"}
{"ok": true, "found": true}
```

`cancel` is answered at once on its own connection; `found` is false when no
request has that `id` (it already ended).

The agent runs at most 4 long sums (`list_dir` with rollups, `sum_subtree`) at
once, in total; the next gets `busy` and the client retries after a pause.

### `read_file`

**New.** Reads one file from its start to its end, up to `max` bytes, when the
size is not known beforehand. It exists for `/proc` and `/sys`, whose files
report `st_size` 0 (or 4096) and so cannot be read with `read_range`'s
offset-and-length contract, and for small configuration files
(`/etc/VERSION`, `iscsi_lun.conf`) where one round trip is better than a
`measure` followed by a `read_range`.

```json
{"cmd": "read_file", "path": "/proc/mdstat", "max": 65536}
{"ok": true, "data_b64": "UGVyc29uYWxpdGllcyA6...", "truncated": false}
```

- `max` is optional: default 262144 (256 KiB), at most 4 MiB (4194304); a
  larger value is `bad_request`, checked before anything is allocated. This
  is the cap: the agent reads at most `max + 1` bytes (to know whether the
  file goes on), returns at most `max`, and sets `truncated: true` when it
  did. A client that needs more reads the file with `read_range`.
- The path rules are those of every command (absolute, canonical, no `..`).
  The final component is opened with `O_NOFOLLOW`, as in `measure`. The
  file must be a regular file: procfs and sysfs files are, a directory, a
  link, a device, a FIFO or a socket is `bad_request` (a FIFO would hang the
  read). The read has a deadline of 10 seconds (a sysfs attribute of a dying
  disk can block); on expiry the answer is `io`.
- The reply is the bytes read, as `data_b64`. There is no `eof` field: a
  `read_file` reply that is not `truncated` is the whole file.
- It reaches no further than `read_range` and `measure` do, and all three
  are confined the same way: to the agent's **allowed roots**, minus its
  **deny list** ([Allowed roots and the deny list](#allowed-roots-and-the-deny-list));
  outside them the answer is `refused`. It is not a new privilege, only a
  new way to read files that have no size. A private key is `refused` here
  too, a cloud placeholder as well (Windows), and a
  [credential-blanked file](#files-served-with-credentials-blanked) is served
  with the credentials replaced, so the bytes returned are not the file's.

### `statfs`

**New.** File system totals for the file system that holds `path`, from
`statvfs(3)` and `statfs(2)`. It replaces the `statvfs` calls and the `df -T
-B1` of the old `synology_storage.rs`.

```json
{"cmd": "statfs", "path": "/volume1"}
{"ok": true, "total_bytes": 47000000000000, "free_bytes": 6006600000000,
 "avail_bytes": 6006600000000, "block_size": 4096, "fs_type_id": 2435016766,
 "flags": 4096, "files": 0, "files_free": 0}
```

| Field | Meaning |
|---|---|
| `total_bytes` | `f_blocks * f_frsize` |
| `free_bytes` | `f_bfree * f_frsize`: free including the root-only reserve |
| `avail_bytes` | `f_bavail * f_frsize`: what an ordinary user can still take |
| `block_size` | `f_frsize` (the fundamental block size, not `f_bsize`) |
| `fs_type_id` | `f_type` from `statfs(2)`, the file system's magic number as an integer (`0x9123683E` = 2435016766 is btrfs, `0xEF53` ext4, `0x58465342` xfs, `0x2FC12FC1` zfs); Python maps the number to a name |
| `flags` | `f_flag` of `statvfs(3)` as the kernel's `ST_*` bit mask (`ST_RDONLY` 1, `ST_NOSUID` 2, `ST_NODEV` 4, `ST_NOEXEC` 8, `ST_NOATIME` 1024, ...); the agent passes the number through and Python names the bits |
| `files`, `files_free` | `f_files`, `f_ffree`; 0 when the file system has no inode count (btrfs) |

`path` may be any existing path (a file, a directory; it is followed, since
`statfs` describes the mount that holds it). Used bytes are `total_bytes -
free_bytes`; that is the client's arithmetic. A Windows agent answers from
`GetDiskFreeSpaceExW` and leaves `fs_type_id` and `flags` out.

### `run`

**New.** Runs one command from a **hardcoded allowlist compiled into the
agent**, and returns what it printed. It is the only way the agent starts a
process, and the table of commands is the reviewable surface of that:
[agent-allowlist.md](agent-allowlist.md).

```json
{"cmd": "run", "id": "lsblk_json"}
{"ok": true, "id": "lsblk_json", "binary": "/bin/lsblk", "exit_code": 0, "timed_out": false,
 "stdout": "{\"blockdevices\": [...]}", "stderr": "", "stdout_truncated": false,
 "stderr_truncated": false, "duration_ms": 41}

{"cmd": "run", "id": "btrfs_usage", "arg": "/volume1"}
{"cmd": "run", "id": "smartctl_info_json", "arg": "/dev/sata1"}
```

- `id` is the entry's name in the allowlist (`lsblk_json`, `zpool_list`,
  `btrfs_usage`, ...). An id the agent does not have is `bad_request`. The
  field is called `id` for the same reason `list_dir`'s is: it names a thing
  the client chose from a fixed vocabulary; a `run` is not cancellable and
  takes no `progress_ms`.
- **Nothing else comes from the network.** The agent builds the command line
  from the entry: an absolute path to the binary and a fixed argument
  vector. There is no shell, no `sh -c`, no globbing, no environment
  expansion, no free-form argument. An entry may declare one **argument
  kind**, and then, and only then, the request carries `arg`, which the agent
  validates itself against live host state before using it as the last
  argument:

  | Kind | `arg` must be | Checked against |
  |---|---|---|
  | `btrfs_mount` | an absolute path | `/proc/self/mountinfo` or `/proc/mounts` at that moment lists it as a mount point whose type is `btrfs` |
  | `block_device` | `/dev/<name>` | `<name>` is a whole disk listed in `/sys/block` (not a partition, not `loop*` or `ram*`) |
  | `md_device` | `/dev/mdN` | `mdN` is listed in `/proc/mdstat` |
  | `zfs_pool` | a pool name | the name is a pool in `zpool list -H -o name` (the agent asks the same way it runs entries) |

  An `arg` that fails its check is refused (`code: "refused"`), and nothing
  is run. An `arg` sent for an entry without a kind, or missing for one with a
  kind, is `bad_request`. A kind's rule never allows a leading `-`, a
  newline, a NUL, or a path that is not canonical. New kinds are code in the
  agent, so adding one is a rebuild; that is on purpose.
- **Environment.** The child gets an empty environment except `LC_ALL=C`,
  `LANG=C` and a fixed `PATH=/usr/sbin:/usr/bin:/sbin:/bin`. Standard input is
  `/dev/null`, the working directory `/`. Output is therefore the C
  locale's: stable, untranslated, parsed by Python.
- **Binary.** Each entry lists absolute candidate paths (`/bin`, `/sbin`,
  `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, and on
  Synology `/usr/syno/bin`, `/usr/syno/sbin`: DSM, TrueNAS and Proxmox put the
  same tool in different places). The first that exists and is executable is
  used; none is `not_found`. The reply says which one ran (`binary`).
- **Limits.** `stdout` is capped at 4 MiB and `stderr` at 64 KiB
  (`stdout_truncated`, `stderr_truncated`; the rest is read and thrown away
  so the child does not block). Each entry has a timeout, 20 seconds unless
  it says otherwise; at the deadline the agent kills the child's process group
  and answers `ok: true` with `timed_out: true`, `exit_code: null` and what
  was printed so far. At most 2 commands run at once on the agent; a third
  gets `busy`.
- **Exit status.** A command that ran is `ok: true` whatever it returned:
  `exit_code` is the child's, `null` with `signal` when a signal ended it.
  `smartctl` returns a bit mask that is non-zero for a failing disk, and
  `zpool status` and `lsblk` fail on a missing device while still printing,
  so the client decides. `ok: false` is for requests the agent did not run.
- **Text.** `stdout` and `stderr` follow the byte-string rule: the text with
  invalid sequences replaced and, only when the bytes are not UTF-8, also
  `stdout_b64` / `stderr_b64` with the exact bytes.
- Read-only by construction: the table holds no command that writes, mounts,
  repairs, scrubs, snapshots or changes a setting. Anything that could go in
  the table is reviewed against that, in [agent-allowlist.md](agent-allowlist.md).

### `capabilities`

**New.** Which allowlist entries are usable on this host, so the client does
not try each one and read errors.

```json
{"cmd": "capabilities"}
{"ok": true, "allowlist_version": 1, "allowlist_sha256": "5c0e...64 hex digits...",
 "deny_sha256": "91ab...64 hex digits...",
 "allow_roots": ["/volume*", "/proc", "/sys", "/etc/samba"], "allow_roots_source": "default",
 "platform": "linux",
 "entries": [
   {"id": "lsblk_json", "available": true, "binary": "/bin/lsblk", "version": "2.38.1",
    "arg_kind": null},
   {"id": "btrfs_usage", "available": true, "binary": "/sbin/btrfs", "version": "4.0",
    "arg_kind": "btrfs_mount"},
   {"id": "zpool_list", "available": false, "binary": null, "version": null, "arg_kind": null}]}
```

- `entries` has one element per allowlist entry the agent was built with
  (and on Windows, per `wmi` entry, with `class` instead of `binary`),
  `available: false` when no candidate path exists or is executable.
- `version` is filled where it is cheap: an entry that declares a version
  probe (a fixed `--version` vector, 3-second timeout) is run once, the first
  number it prints returned as text, and the answer cached for the life of
  the agent process; `null` otherwise, and when the probe fails. It is
  informative: whether a feature exists is for the client to know from the
  version (`lsblk -J` needs util-linux 2.27) or from trying the command.
- `allowlist_version` is a number the agent bumps when entries are added or
  changed; `allowlist_sha256` is the SHA-256 of the allowlist as compiled
  (each entry's id, candidate paths, argument vector, argument kind, timeout,
  joined in id order with NUL separators). A client can record it per agent
  version, so a binary that was patched to run something else shows up as a
  different hash. Neither is a secret and neither is secured against an agent
  that lies: it is an audit aid, with the review of the table the real control.

- `allow_roots` is the **effective** list of allowed roots exactly as the agent
  uses it (canonical paths, globs as written) and `allow_roots_source` is
  `env`, `env_file` or `default`, so the server can explain a `refused`
  ("the agent serves /volume* and /proc; /home is not one of them") instead of
  guessing. `deny_sha256` is the SHA-256 of the compiled-in deny list (the
  path rules and the private key signatures of the next section, one per line
  in source order); an audit compares
  it per agent version as it does `allowlist_sha256`. The deny list itself is
  not sent: it is in this document and in the binary.

### `activity`

**New in 0.2.1.** Who is using the agent now, so a client can tell whether it
is busy (`filecat server` asks before it starts a job; `filecat agents status`
lists the sessions). Authenticated connections only.

```json
{"cmd": "activity"}
{"ok": true, "self_id": 7, "sessions": [
  {"id": 5, "peer": "192.0.2.20:51234", "connected_at": 1793000000, "connected_secs": 722,
   "authenticated": true, "label": "scan \\\\nas3\\Apps by kense@DESKTOP",
   "command": "sum_subtree", "command_secs": 180, "last_request_secs": 4,
   "requests": 1204, "dirs_listed": 310, "entries_listed": 88120, "files_measured": 0,
   "bytes_read": 0, "files_summed": 41234, "bytes_summed": 912345678901, "errors": 3},
  {"id": 7, "peer": "192.0.2.10:40022", "connected_at": 1793000700, "connected_secs": 2,
   "authenticated": true, "label": "agents status", "command": "activity", "command_secs": 0,
   "last_request_secs": 0, "requests": 3, "dirs_listed": 0, "entries_listed": 0, "files_measured": 0,
   "bytes_read": 0, "files_summed": 0, "bytes_summed": 0, "errors": 0}]}
```

- One element per open connection, the asker's own included (`self_id`, so
  the client can leave it out). A connection is removed when it closes.
- `command` is the command being run now, `null` when the connection is idle;
  `command_secs` how long it has run. `last_request_secs` is the time since the
  last request, `null` for a connection that has made none (a bare `hello`,
  which is what a health check without `auth` looks like).
- The counters count what the replies held, per connection: `dirs_listed` and
  `entries_listed` (`list_dir`, and the folders and entries a `sum_subtree` or
  a rollup visits), `files_measured` (`measure`), `bytes_read` (content read by
  `measure`, `read_range` and `read_file`; for `measure` the file's size when
  it was hashed in full, 2 MiB for a partial digest, else the head),
  `files_summed` and `bytes_summed` (`sum_subtree` and rollups, updated as the
  walk goes, not at its end), and `errors` (requests answered `ok: false`).
- **No path and no request argument is ever in the reply**: a path could lie
  inside a `[REDACTED]` rollup. Command names, the label and numbers only.
- `activity` is a command, not a `run` allowlist entry: the allowlist and its
  hash are unchanged. An agent older than 0.2.1 answers `bad_request`
  (`unknown cmd "activity"`); the client treats that as "activity not
  supported", never as a failure.

The agent also writes one line per session that made requests (or is running
one) every `FILECAT_AGENT_STATUS_INTERVAL` seconds (default 600; see
[agent-deploy.md](agent-deploy.md)): label, peer, how long connected, the
current command, and the changes since the last line and the totals of files,
GB read and entries listed, with the rate. Nothing is logged for an idle agent.

### Allowed roots and the deny list

**New.** Where the agent will read is decided **on the agent host**, never by
a request, and a hardcoded deny list wins over it.

**Allowed roots.** `FILECAT_AGENT_ALLOW_ROOTS` is a list of absolute paths
separated by `:` on POSIX and `;` on Windows.

- *Where it is set.* In the agent's environment, or as `FILECAT_AGENT_ALLOW_ROOTS=...`
  in a `.env` file in the **same directory as the agent binary** (read once at
  start; `KEY=value`, `#` comments, optional single or double quotes, no
  expansion). The environment variable wins over the `.env` key. Nothing in
  the protocol sets or changes it; `configure_policy` cannot.
- *Unset* (neither source): a built-in default for the OS, so a fresh
  agent is already confined. DSM (detected by `/etc/VERSION` with a
  `productversion`):
  `/volume*`, `/proc`, `/sys`, `/dev/disk`, `/etc/samba`, `/etc/space`,
  `/etc/VERSION`, `/etc/exports`, `/etc/lvm/backup`,
  `/usr/syno/etc/iscsi_*.conf`: the paths the Synology collector and StoreFS
  read. Other Linux: `/proc`, `/sys`, `/dev/disk`, `/etc/hostname`,
  `/etc/os-release`, `/etc/exports`, `/mnt`, `/srv`, `/media`. Windows: every
  local fixed volume (`GetLogicalDrives` and `GetDriveType` = `DRIVE_FIXED`,
  evaluated at each request) **except the system drive**, plus the path of each
  disk share (`Win32_Share` type 0, not special) not already under one of
  those volumes. On a **Windows client** the system drive is included too. The
  agent tells them apart by `Win32_OperatingSystem.ProductType` (WMI,
  [agent-allowlist.md](agent-allowlist.md) section 13): 1 = workstation
  (Windows 10 or 11, a client), 2 = domain controller, 3 = server; only 1
  includes `C:\`. When the type cannot be read the agent assumes a server (the
  narrower list), and `capabilities` reports `product_type` (the number, or
  `null`) next to `allow_roots`. The fake agent's `default_windows_roots` is
  the executable specification. *Set but empty*: no
  roots at all; every path is refused.
- *Entries.* Absolute, with no `.` or `..`. `*` matches any run of
  characters **inside one path component** (never `/`), anywhere in a
  component: `/volume*`, `/usr/syno/etc/iscsi_*.conf`. No other glob, no
  `**`, no regular expressions. A root allows itself and everything below it,
  compared component by component (`/etc/space` allows `/etc/space/a.xml`,
  not `/etc/spacey`). Windows entries are compared case-insensitively.
  A malformed entry stops the agent from starting (it does not widen the
  scope silently).
- *Canonicalisation.* The check is on the **real path**: every symlink in the
  path (and on Windows every junction, reparse point, `\\?\` prefix and 8.3
  short name, via `GetFinalPathNameByHandle`) is resolved first, and the
  result must be inside a root. A link inside an allowed root that points
  outside it is therefore `refused`. When the path does not exist the check
  uses the longest existing ancestor, resolved, plus the remaining components,
  so a path outside the roots is `refused` whether or not it exists (no
  `not_found` oracle). Non-glob roots are canonicalised at start; one that
  does not exist yet is kept as written and logged. The operation then runs on
  the **resolved** path with `O_NOFOLLOW` on the last component, which
  leaves only a swap of a directory inside an allowed root as a race.
- *Scope.* Every command that takes a path: `read_file`, `read_range`,
  `measure` (content), `list_dir`, `sum_subtree` (names, sizes, times) and
  `statfs` (totals). `list_dir`, `sum_subtree` and `statfs` are included
  because one check at the front of the dispatcher is simpler to review and
  to get right than a per-command rule, and the names of a user's home
  directory are not for the central server either. Not affected: `run`
  (its own allowlist), `wmi`, `hello`, `auth`, `capabilities`.
- *Error.* `refused`, with `"<path>: outside the agent's allowed roots
  (FILECAT_AGENT_ALLOW_ROOTS on the agent host)"` (`<path>` is the request's
  path, not the resolved one, so a link target is not disclosed). The client
  raises `AgentError` with that code and text; collectors record it as a
  `collector.notes` line and go on without that source.

**Deny list.** Compiled into the binary, not configurable, not overridable by
the environment, the `.env` file or any request; it is checked on the same
canonical path **after** the roots and applies to the commands that return
file **content**: `read_file`, `read_range` and `measure` (which returns a
head and a digest of the bytes). `list_dir`, `sum_subtree` and `statfs` still
see a denied file's name and size: a catalog needs to know a `.env` exists,
and its size, even though no one may read it. A rollup or `sum_subtree` counts
a denied file in its totals as any other (they use `lstat` only,
[rollups.md](rollups.md) section 3.2); outside a rollup a scan records it with
name, size and times and `probe.secret: "denied"`. Match on the canonical path:

| Platform | Denied |
|---|---|
| POSIX | `/etc/shadow`, `/etc/shadow-`, `/etc/gshadow`, `/etc/gshadow-` (password hashes); `/etc/sudoers` and `/etc/sudoers.d/**`; `/etc/ssh/ssh_host_*_key` (host private keys) and `/etc/ssl/private/**`; `/var/log/**` and `/var/logs/**` (logs hold tokens, paths and other users' activity) |
| POSIX and Windows | any file named exactly `.env` or matching `.env.*`, anywhere, including inside shares and the agent's own `.env`, **except** `.env.example`, `.env.sample` and `.env.template` (conventionally secret-free; case-insensitive on Windows) |
| Any file, by content | a **private key**: see [Private keys](#private-keys-by-content). Not a path rule: the file is opened and its first bytes decide |
| Windows (case-insensitive, on the final path) | `%SystemRoot%\System32\config\**` (the SAM, SECURITY, SYSTEM, SOFTWARE and DEFAULT hives, their `.LOG*` and `RegBack`); `NTUSER.DAT*` and `UsrClass.dat*` anywhere (user hives and their logs); `%SystemRoot%\NTDS\**` (`ntds.dit`, `edb*.log`) and any `*.dit` anywhere |

Decisions: `SYSVOL` is **not** denied (every domain user may read it, and it
is what a domain controller's file catalog is for); the list is short on
purpose, each entry being a place where the content is a credential or
identity store and never a file a catalog needs; a denied path is `refused`
with `"<path>: denied by agent policy"` and nothing else (no rule is echoed).
A new entry is code and a rebuild. `capabilities` reports `deny_sha256`.
The collectors read none of these paths, and StoreFS reads only backup and
database manifests under the roots; `tests/test_synology_space.py` asserts it
for the Synology collection.

#### Private keys by content

A file whose head is a private key is not read by `measure`, `read_range` or
`read_file`, whatever it is called and wherever it is (inside the allowed
roots). The agent reads the first 256 bytes, drops an optional UTF-8 byte
order mark and then leading ASCII whitespace (space, tab, CR, LF), and tests
the start of what is left:

| Signature | Covers |
|---|---|
| `-----BEGIN ` ... `PRIVATE KEY-----` on the first line | PKCS#8 `PRIVATE KEY`, `RSA`, `EC`, `DSA`, `ENCRYPTED` and `OPENSSH PRIVATE KEY` |
| `-----BEGIN PGP PRIVATE KEY BLOCK-----` | PGP/GPG secret keys |
| `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----` | ssh.com keys |
| `PuTTY-User-Key-File-` | PuTTY `.ppk` (any version) |

A public key (`ssh-ed25519 AAAA...`, `-----BEGIN PUBLIC KEY-----`), a
certificate, a certificate request and a PGP public block are not matched. A key
after something else in the file (a certificate first, a text before the
header) and a key in UTF-16 are not found: the rule looks at the start only.
`measure` answers `unread: "private_key"` (above) and the other two commands
`refused` with `"<path>: denied by agent policy"`. The signature table is part
of `deny_sha256`. The Python scan applies the same rule to the head it reads
itself (`src/filecat/secretfiles.py`), so a local, SMB and agent scan agree.
filecat also treats `.pfx`, `.p12` and `.kdbx` as secrets **by name**
(encrypted binary containers with no header to test); that is the scan's rule
and the agent does not know it.

#### Files served with credentials blanked

A small table compiled into the agent lists files that are readable but hold
credentials; `read_file` serves them with the value of every credential line
replaced by the literal `<filecat-redacted>`, so the server can see that the
agent blanked them. First entry:

| File | Lines blanked (key before the first `=`, compared after trimming) |
|---|---|
| `/usr/syno/etc/iscsi_target.conf` | `password`, `mutual_password`, `username`, `mutual_username` |

`password=hunter2` is served as `password=<filecat-redacted>`; every other
line, the line endings and the order are the file's own. The reply is
therefore **not the bytes on disk**: its length differs from the `size`
`list_dir` reports for the file, and nobody should compare them. Because
offsets into the blanked text would not match the file, `read_range` and
`measure` on such a file are `refused` ("denied by agent policy"); only
`read_file` serves it, up to 4 MiB (a larger file is `io`). The table is not
configurable and not part of the path rules; adding a file is code and a
rebuild. `iscsi_host.conf`, which the Synology documentation also lists, is
not in the table: nothing in this repository shows that it holds a credential,
and the collector does not read it. If a DSM file turns out to hold CHAP
secrets, it is added here. The collector ignores those keys; the topology
never contains them or the marker.

#### Cloud placeholders (Windows)

A file whose attributes include `RECALL_ON_DATA_ACCESS` (0x400000),
`RECALL_ON_OPEN` (0x40000) or `OFFLINE` (0x1000) is a OneDrive Files On-Demand,
iCloud, Dropbox or tiered file: opening it makes the provider download it. The
agent follows `filecat.cloudfiles`: it **never opens** such a file on a
Windows host, wherever it is. It reads the attributes without opening
(`GetFileAttributesW`, or the `FindFirstFile` data it already has). Listing
is fine (`list_dir` reports `attributes`); `measure` answers `unread: "cloud_placeholder"` with
`size`, `mtime_ns` and `attributes`; `read_file` and `read_range` are
`refused` with `"<path>: not on this device (cloud placeholder), not read"`;
`sum_subtree` and rollups count the file from the directory entry and never
open it. `PINNED` (0x80000) and `UNPINNED` (0x100000) alone do not make a file
unreadable. The client records `probe.cloud = {"provider": null, "state":
"online-only" | "offline"}` as `cloudfiles.describe` does (the provider name
comes from the Windows sync root registry, which the agent host knows and the
server does not read), so the record of a file seen through an agent is the
record of the same file seen over SMB. There is no way to ask the agent to
hydrate a file.

### `wmi`

**New, Windows agents only.** Runs one allowlisted WMI query and returns the
raw property maps; everything else (classification, joining a disk to its
pool) is Python's, as everywhere. On any other platform the answer is
`bad_request`.

```json
{"cmd": "wmi", "id": "storage_physical_disk"}
{"ok": true, "id": "storage_physical_disk", "namespace": "root\\Microsoft\\Windows\\Storage",
 "class": "MSFT_PhysicalDisk", "duration_ms": 120,
 "rows": [{"UniqueId": "{...}", "FriendlyName": "Samsung SSD 990", "SerialNumber": "S6Z...",
           "Size": "1000204886016", "MediaType": 4, "HealthStatus": 0, "BusType": 17}]}
```

- The table (id, namespace, class, the property list, a fixed `WHERE`-less
  query) is compiled in, like `run`'s; the request carries no query text, no
  property names and no argument. The agent issues `SELECT <fixed properties>
  FROM <class>` through WMI's COM API (the Rust `wmi` crate), read-only.
- Values are WMI's, unconverted: strings stay strings, booleans and 32-bit
  numbers are JSON numbers and booleans, 64-bit integers are **decimal
  strings** (WMI itself marshals `uint64` that way), dates keep the CIM
  datetime text (`20261022090000.000000+000`), arrays are arrays, an embedded
  object is left out. Python converts.
- `capabilities` lists the `wmi` ids with `available` (the class exists in the
  namespace on this Windows version) in place of `binary`. Timeout 30 seconds,
  then `io`.

### Storage topology is built in Python

There is no `storage_topology` command (the first drafts had one that
returned Synology volumes, and the version of this page before this change had
one that returned the generic hierarchy). The agent does not parse
`iscsi_lun.conf`, `/proc/mdstat`, `zpool status` or anything else for the
topology: Python asks for the raw sources with `read_file`, `list_dir`,
`statfs`, `sum_subtree` and `run`, and builds the generic hierarchy
(`filecat.topology_collect`, [storage-topology.md](storage-topology.md)), so
a new rule, file format or platform never needs an agent rebuild. A client
that sends `storage_topology` to this agent gets `bad_request`.

## Path mapping (client side)

Records from an agent scan must line up with records from an SMB scan of the
same share: same `root`, same `rel_path`. The catalog root is the UNC path
the SMB scan uses (`\\nas-main\Backup`); `rel_path` is `/`-separated. The
client maps in both directions with `ShareMap` (`agent_client.py`):

- an explicit `[agents.shares]` table, POSIX prefix to UNC root
  (`"/volume1/Backup" = '\\nas-main\Backup'`), longest prefix first;
- otherwise Synology's layout: `/volumeN/<share>/rest` is
  `<alias>\<share>\rest` for the configured volume (default 1);
- any other path is `<alias>\$root\<path without the leading slash>`, so
  every path has one UNC form and converts back.

POSIX is case-sensitive and UNC share names are not. Towards UNC, the
share is spelled as it is on the agent host (which is how Synology reports
its shares). Towards POSIX, the alias and the explicit UNC roots are
matched case-insensitively, as in `aliases.py`, and everything after them
is passed through exactly: catalog paths come from listings, so they carry
the file system's own case. A name containing a backslash cannot be written
as a UNC path and is an error.

## Differences from the draft main.rs

What the Rust side changes to match this page:

1. **`hello`** is new, answered before `auth`, and returns `protocol`,
   `agent_version` (from `CARGO_PKG_VERSION`), `hostname`, `os`, `arch`.
2. **Errors** always carry `code` from the table above. The draft has
   free text only; a wrong token is `unauthorized`, and it closes the
   connection. The default token `change-me-token` goes: no
   `FILECAT_AGENT_TOKEN`, no start. Compare tokens in constant time.
3. **`measure`** loses `full_hash_max` and `smb_tick_quantize`. It takes
   `hash` (`auto`, `full`, `none`) and applies `hashing.py`'s table, fixed
   at 64 MiB and 1 MiB. `full` hashes a 0-byte file as `sha256(b"")`
   (the draft answers `null`). `mtime_ns` is always floored to 100 ns with
   `div_euclid` (the draft's `/ 100 * 100` rounds toward zero and only
   when the flag is set) before it feeds the partial hash. `size` and
   `mtime_ns` come from `fstat` on the open file and are returned. Digest
   fields are omitted instead of `null`. The head is returned for every
   `hash` value. Open with `O_NOFOLLOW`, reject non-regular files. A short
   read is an `io` error, not ignored (`let _ = file.read_exact`).
4. **`list_dir`**: a failed `lstat` becomes an entry with `error`, not a
   `continue`. No per-entry `path` (it duplicated the parent's path and
   could not carry non-UTF-8 names). `kind` gains `other` (the draft shows
   a socket or FIFO as a `file`, which a client would then open and hang
   on). Links get `link_target`. Names that are not UTF-8 get `name_b64`
   (`to_string_lossy` alone loses them). The response adds the
   directory's own `dev`, `mtime_ns`, `ctime_ns`. Entries are sorted, and
   rollups come out in tag order instead of `HashMap` order. Timestamps are
   floored to 100 ns; `ctime_ns` is the birth time where `statx` gives one.
5. **Rollups**: `rollup_meta` is `rollup`; `matched_Folders` is `matched`;
   `errors` is added. Hard links are counted by `(dev, ino)`, not by `ino`
   alone, and the set is shared across the whole group, not rebuilt for each
   matched folder. Unreadable directories add to `errors` instead of being
   skipped silently. **Changed by the rollup design** ([rollups.md](rollups.md)):
   - `rollup_groups` (tag to patterns) is replaced by an ordered `rules`
     array with `type`, `case`, `keep`, `private`, `suggest`. Patterns are
     matched against the **literal host path** (name, suffix and path
     patterns), converted by the client from the share form the user may have
     written; `*` does not cross `/` (the draft's did), `**` does; matching is
     case-sensitive unless a rule says otherwise. The earlier `bases` idea
     (a client-built match path) is not used. `configure_policy` answers with
     `policy_id`.
   - New: `markers` (look inside each child directory for the named files
     before returning it), `redaction` (HMAC key and per-root `base`,
     `hashes`, `inodes`: sticky `[REDACTED]` folders; `folded` in the reply),
     and `suggest` rules with the `suggest` reply field.
   - A rollup reports `oldest_mtime_ns`, `error_codes`, `vanished`,
     `skipped_mounts`, `hardlink_names`, `complete`; a `private` rule gets
     counters only and no logging. A real child named like the tag is folded
     in.
   - A different `dev` is not entered and is counted in `skipped_mounts`;
     the basis is the `dev` of the summed folder (a nested btrfs subvolume is
     skipped).
   - The hard-link set is capped at 2,000,000 entries (`hardlinks_approx`).
6. **`sum_subtree`** is new (the iterative `sum_rollup_subtree` exposed as a
   command, with `exclude` applied). **Changed**: options `one_filesystem`,
   `exclude` (patterns), `private`, `threads`, `progress_ms`, `deadline_ms`,
   `id`; the summed folder counts in `total_dirs`; the totals of a rollup
   entry. New: `progress` lines, `deadline_ms`/`complete`, the `cancel`
   command, the codes `cancelled` and `busy`.
7. **`read_range`**: `len` over 4 MiB is `bad_request` and is checked
   before `vec![0u8; len]` (the draft allocates whatever it is asked to);
   the response adds `eof`; regular files only, `O_NOFOLLOW`.
8. **Requests**: paths are validated (absolute, no `.` or `..`);
   `path_b64` is accepted everywhere `path` is; a malformed line is
   `bad_request` and the connection survives; the line reader is capped at
   8 MiB (`read_line` in the draft grows without limit); every response is
   flushed after the write (`StreamOwned` buffers); errors map from
   `io::ErrorKind`/`raw_os_error` to a `code` through one function.
9. **`storage_topology` is gone** (the draft's reply, and the generic
   hierarchy this page described for a while). The agent no longer parses
   anything for the topology; see [Storage topology is built in
   Python](#storage-topology-is-built-in-python). `synology_storage.rs` is
   deleted ([below](#what-synology_storagers-becomes)). The TLS code
   (`tls.rs`) is unchanged. Output of `cert_sha256` stays as the lowercase
   hex printed at start; the client also accepts `AA:BB:...`.
10. **New generic primitives**, none of which interprets a file system or a
    tool's output:
    - `read_file {path, max}`: to EOF up to `max` bytes (default 256 KiB,
      at most 4 MiB), for `/proc` and `/sys` files that report size 0.
      `O_NOFOLLOW`, regular files only.
    - `statfs {path}`: `statvfs(3)` and `statfs(2)` totals, block size, file
      system magic number, mount flags (replaces the draft's inline `statvfs`).
    - `run {id[, arg]}`: a command from the **compiled-in allowlist**
      ([agent-allowlist.md](agent-allowlist.md)): fixed absolute candidate
      paths, fixed argument vector, no shell, `LC_ALL=C`, fixed `PATH`,
      stdout and stderr capped, a timeout, exit code and binary path in the
      reply. Its only variable input is an `arg` of a declared kind that the
      agent validates itself (`btrfs_mount`: a path `/proc` currently lists as
      btrfs). New error code `refused`.
    - `capabilities`: which allowlist entries exist here, with the resolved
      binary path, a cached version where cheap, and `allowlist_version` /
      `allowlist_sha256` for audit.
    - `wmi {id}` (Windows agents only): an allowlisted WMI query, raw
      property maps back, through the Rust `wmi` crate.
    All five are additive: `protocol` stays 1.
11. **Read scope** ([above](#allowed-roots-and-the-deny-list)). New: at the
    front of the dispatcher, for every command that takes a path, resolve the
    path to its real form (symlinks; on Windows `GetFinalPathNameByHandle`),
    check it against the allowed roots (`FILECAT_AGENT_ALLOW_ROOTS` from the
    environment, else the `.env` file next to the binary, else the OS default;
    `*` inside one component only) and answer `refused` outside them; for
    `read_file`, `read_range` and `measure` also check the **deny list
    compiled into the binary** (it wins over the roots and nothing configures
    it). `capabilities` reports `allow_roots`, `allow_roots_source` and
    `deny_sha256`. Open the file by the resolved path with `O_NOFOLLOW`.
    The Python fake agent (`tests/_fake_agent.py`) is the executable
    specification of the matching rules, including `resolve_allow_roots` for
    the environment/`.env` precedence.
12. **`run` and the argument rule.** The agent never builds a command from
    request text. If the table gains a command that needs an argument, the
    change is a new argument kind in the agent's source and a new row, both
    reviewed, not a configuration.
13. **Private keys by content** ([above](#private-keys-by-content)). `measure`,
    `read_range` and `read_file` read the first 256 bytes of the file they are
    about to serve, apply the signature table (BOM, leading whitespace, the four
    signatures) and answer `unread: "private_key"` (`measure`: `size` and
    `mtime_ns` from `fstat`, no `head_b64`, no digest) or `refused` /
    `"<path>: denied by agent policy"` (the others). Add the signatures to the
    input of `deny_sha256`. `tests/_fake_agent.py` (`private_key_head`) is the
    specification; the Python client already handles `unread`.
14. **Credential blanking** ([above](#files-served-with-credentials-blanked)).
    A small table `path -> keys` (first entry `/usr/syno/etc/iscsi_target.conf`:
    `password`, `mutual_password`, `username`, `mutual_username`); `read_file`
    of a listed file replaces each such line's value with `<filecat-redacted>`
    (the key, the `=`, line endings and every other line unchanged), while
    `read_range` and `measure` of it are `refused`. A file over 4 MiB is `io`.
    Spec: `redact_credentials` and `REDACT_FILES` in the fake agent.
15. **Windows: product type, roots and placeholders.**
    - Default roots: local fixed volumes, the system drive only when
      `Win32_OperatingSystem.ProductType` is 1; plus the disk-share paths not
      under a volume; assume a server when the type is unknown; report
      `product_type` in `capabilities` (`default_windows_roots` in the fake
      agent).
    - Add the `ProductType` property to the `os_info` WMI entry
      ([agent-allowlist.md](agent-allowlist.md)).
    - `list_dir` reports `attributes` for every entry; files with a recall or
      offline bit are never opened (not by `measure`, `read_file`, `read_range`,
      hashing, nor `sum_subtree`); `measure` answers `unread:
      "cloud_placeholder"` with `attributes` ([above](#cloud-placeholders-windows)).
      Use `GetFileAttributesW` / `FindFirstFileW` data, never `CreateFileW`,
      to decide. SYSVOL on a domain controller stays readable (NTDS is on the
      deny list).
16. **Connection label, `activity` and the status log (0.2.1).** `hello` and
    `auth` take an optional `label` ([above](#hello)); `activity` lists the
    open connections with their counters ([above](#activity)); a thread logs
    each busy connection every `FILECAT_AGENT_STATUS_INTERVAL` seconds. The
    counters are atomics added to as the walk goes (one relaxed add per file),
    the rest of a session is behind a mutex taken once per request. Nothing in
    the `run` allowlist, the deny list or the other commands changed, so
    `allowlist_sha256` and `deny_sha256` are the same as in 0.2.0.

### What `synology_storage.rs` becomes

Deleted, with the `mod synology_storage;` and the `StorageTopology` branch of
`main.rs`. Its logic moves to Python, where it is a collector over raw
sources (`src/filecat/topology_collect/synology.py`):

| In `synology_storage.rs` | Now |
|---|---|
| `/proc/mounts` parsing, `statvfs` per `/volume*` | `read_file /proc/mounts` (or `/proc/self/mountinfo`), `statfs <mount>`; the volume node is built in Python |
| shares = every top-level folder not starting with `@` or `#` | read the share definitions (Samba and NFS configuration, with the folder scan only as a flagged fallback) |
| `iscsi_lun.conf` stanza parser, `devtype` to kind, `bytes=` | `read_file` of the same files; the parser is Python |
| allocated bytes = `read_dir` + `st_blocks * 512` per LUN directory, `ROD` aside | `sum_subtree` of the LUN directory, `total_allocated_size` (never `total_size`: the 512 GiB `ROD`) |
| `@Repository/<vm>/vguest.conf` and `vdisk.conf` (`serde_json`) | `read_file` and `json.loads` |
| (none) disks, md arrays, LVM, NAA id, ACL, targets | `/sys/block`, `/proc/mdstat`, `/etc/lvm/backup`, `topology.naa_from_unit_serial`, `iscsi_lun_acl.conf`, all read through `read_file`, `list_dir` and the `mdadm_detail_scan`, `smartctl_info_json` entries of `run` |

The order, ids and fields of the nodes the collector produces are the
contract of [storage-topology.md](storage-topology.md) and are tested against
recorded raw sources (`tests/data/raw`). Reads stay read-only; a source that
cannot be read (a root-only file, a missing tool) leaves its nodes or fields
out and puts a note in the snapshot's `collector.notes`, never a failed
collection.

## Settled by the Linux agent (0.2.0)

Details the page above left open, as the Rust agent (`agent/`, phase 1: Linux and DSM)
implements them. The fake agent (`tests/_fake_agent.py`) and the Rust agent agree on all of
them; the conformance run of the Python agent tests against the binary
([agent/README.md](../agent/README.md)) is what keeps them in step.

- **`allowlist_sha256`** is the SHA-256 of the table as compiled: for each entry in id order six
  fields joined with NUL (the id; the candidate paths joined with `\x1f`; the argument vector
  joined with `\x1f`; the argument kind name, empty for none; the timeout in seconds in decimal;
  the version-probe vector joined with `\x1f`, empty for none), the records joined with NUL as
  well, no trailing separator. A cargo test pins the value; changing an entry means bumping
  `allowlist_version` and the pin. The Linux table has 39 entries: the 60 of
  [agent-allowlist.md](agent-allowlist.md) less the 19 `wmi` ones (phase 2) and the two
  Synology tools whose arguments are not committed. The Python fake's `allowlist_sha256` is its
  own placeholder; nothing compares the two.
- **`deny_sha256`** is the SHA-256 of `DENY_POSIX`, the three `.env` exceptions, the two Windows
  path rules and the four key signatures (`secretfiles.SIGNATURES`, spelled with `*` for the
  free part of the first), one per line joined with `\n`, no trailing newline. One value for a
  given agent version on every platform; the fake computes the same bytes.
- **Links.** The scope check resolves every symbolic link, the last component included (so
  `/proc/mounts`, a link to `self/mounts`, is readable), and the operation then runs on the
  resolved path with `O_NOFOLLOW`. `list_dir`, `sum_subtree` and `statfs` of a link to a
  directory describe the directory. A link that resolves outside the roots is `refused`; a
  dangling one is `bad_request`.
- **Paths** are validated before anything else: a path with an empty, `.` or `..` component, a
  trailing `/` (other than `/`) or a NUL is `bad_request`, as the Paths section says. `list_dir`
  answers with the request's `path` (and `path_b64` when the request used it and the bytes are
  not UTF-8).
- **Rules.** `configure_policy` rejects (`bad_request`) a rule that has no tag and is not a
  `keep` rule, a tag that is not `[A-Z][A-Z0-9_-]{0,31}` in brackets, a `type` or `case` outside
  the documented values, and a marker whose name is empty, `.`, `..` or has a `/`. Patterns are
  matched against names and paths in the catalog's spelling (an invalid UTF-8 byte is U+F700 +
  byte), so `?` is one character even there.
- **`list_dir`.** Entries, rollups and errors are sorted together by name bytes. `ctime_ns` is
  the birth time where the kernel and file system give one (`statx`; DSM's 4.4 kernel has none,
  so it is the inode change time there). Rollups carry `newest_mtime_ns` always (0 when no file)
  and `oldest_mtime_ns` only with files; the sum of one rollup shares one deadline and one
  cancel flag. The agent writes no log line about any path.
- **Sums.** `progress_ms` below 500 is raised to 500; `threads` is validated (1 to 16) and
  accepted, the walk itself is single-threaded (a `lstat`-bound walk of 95,000 files takes about
  a quarter of a second on ext4). `deadline_ms` above 86,400,000 and an `id` over 64 characters
  are `bad_request`. At most 4 long sums run at once across connections. The walk is iterative
  with a depth limit of 4096; a deeper directory is counted as an `io` error.
- **`read_file`** reads on its own thread with the 10 second deadline; a blanked file
  (`iscsi_target.conf`) is read whole (at most 4 MiB, else `io`) before the credentials are
  replaced, then cut at `max`. The line splitting of the blanking follows `bytes.splitlines`
  (`\n`, `\r\n`, a lone `\r`).
- **`run`.** A binary is the first candidate that is a regular file with the execute bit. The
  `block_device` kind accepts `/dev/<name>` with `<name>` made of letters, digits, `.`, `_`
  and `-`, not starting with `.`, `loop` or `ram`, and a directory in `/sys/block`;
  `md_device` accepts `/dev/md<digits>` listed in `/proc/mdstat`; `btrfs_mount` reads
  `/proc/self/mountinfo` (then `/proc/mounts`), unescaping `\040`-style octal. The version
  probe (`--version`, 3 s) covers `lsblk`, `blkid`, `findmnt`, `btrfs`, `mdadm`, `smartctl`
  and the LVM tools; the first number printed is cached for the life of the process.
  `wmi` is `bad_request` ("wmi is only available on Windows agents").
- **Connections.** A client has 20 seconds to finish the TLS handshake and send its first line,
  and 15 minutes of silence before the agent closes; at most 64 connections at once (the rest
  are dropped at accept). A request line over 8 MiB is answered `bad_request` and the
  connection closed. A wrong token is answered after one second and the connection closed.
- **TLS and the certificate.** TLS 1.2 and 1.3 through rustls with the `ring` provider; the
  first start generates an ECDSA P-256 self-signed certificate (`CN=filecat-agent`) and its key
  (mode 0600) next to the binary (or where `--cert` / `--key` say) and prints
  `cert_sha256 <hex>`. If only one of the two files exists the agent refuses to start rather
  than replace half a pair and change the fingerprint the clients pinned.
- **Configuration** is the command line, then the environment, then the `.env` next to the
  binary: `FILECAT_AGENT_TOKEN` (or `FILECAT_AGENT_TOKEN_FILE`, first line), `FILECAT_AGENT_LISTEN`
  (default `0.0.0.0:9876`), `FILECAT_AGENT_CERT`, `FILECAT_AGENT_KEY`,
  `FILECAT_AGENT_ALLOW_ROOTS`. The token is never an argument. Deployment:
  [agent-deploy.md](agent-deploy.md).
