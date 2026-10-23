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
stats, hashes, sums and reads. Store detection, probing and every manifest
parser stay in Python.

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
  response. No pipelining, no unsolicited messages. The agent serves each
  connection on its own thread, so a client wanting parallelism opens
  several connections; each has its own authentication and its own policy.
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

Every `mtime_ns`, `ctime_ns` and `newest_mtime_ns` is nanoseconds since the
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
{"cmd": "hello"}
{"ok": true, "protocol": 1, "agent_version": "0.2.0", "hostname": "nas-main",
 "os": "linux", "arch": "x86_64"}
```

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

```json
{"cmd": "configure_policy", "policy": {
    "exclude": ["/volume1/@docker", "@eaDir"],
    "rollup_groups": {"[CACHE]": ["*/.cache", "*/node_modules"],
                      "[REDACTED]": ["/volume1/project/private-project"]}}}
{"ok": true}
```

Replaces the connection's policy as a whole (both fields optional, default
empty); a new connection starts with an empty policy. It applies to
`list_dir` (both fields) and to `sum_subtree` (`exclude` only); `measure`
and `read_range` act on the path they are given.

- `exclude`: absolute paths or bare names, compared for equality with each
  child's path and name. Excluded entries are neither listed nor counted.
  They are not globs.
- `rollup_groups`: tag to list of patterns. A pattern equal to a child's
  path or name, or a glob matching either (`*` any run of characters
  including `/`, `?` one character, `[...]` a class), puts that child in the
  tag's rollup. Tags are tried in the order given (JSON object order is
  kept), the first match wins. `exclude` is applied first.
- A tag is a non-empty string without `/` or a NUL; by convention
  `[UPPER_CASE]` in brackets (note [01](research/01-rollup-groups-privacy-indexing.md)).

### `list_dir`

```json
{"cmd": "list_dir", "path": "/volume1/Backup"}
{"ok": true, "path": "/volume1/Backup", "dev": 2049, "mtime_ns": 1761001200000000000,
 "ctime_ns": 1700000000000000000, "entries": [ ... ]}
```

Lists the immediate children, each `lstat`ed, and never recurses (except
into a rollup). `dev`, `mtime_ns` and `ctime_ns` are the directory's own, so
the client needs no second call for a root's record. Entries are sorted by
name bytes; rollup entries are interleaved by their tag.

An entry:

| Field | Meaning |
|---|---|
| `name` | the file name (the byte-string rule applies; `name_b64` when needed) |
| `kind` | `file`, `dir`, `link`, `rollup`, or `other` (socket, FIFO, device: record it, never open it) |
| `size` | `st_size`; for a link the link's own size; for a rollup the group's `total_size` |
| `allocated_size` | `st_blocks * 512`, the space actually used (a sparse file's is smaller than `size`) |
| `ino`, `dev`, `nlink` | from `lstat`; 0, the directory's `dev` and 1 for a rollup. Hard links share `(dev, ino)`; the client deduplicates |
| `mtime_ns`, `ctime_ns` | see Timestamps; for a rollup both are the group's newest mtime |
| `link_target` | links only: `readlink` text (byte-string rule: `link_target_b64`) |
| `rollup` | rollups only: the summary below |
| `error` | `{"code": "...", "message": "..."}` when the entry could not be `lstat`ed |

An entry whose `lstat` fails is still listed: `name`, `kind` (from the
directory entry's type when the OS gave one, else `other`) and `error`, with
the numeric fields left out. Silently dropping it would hide a file the SMB
scan would have recorded with an error. Only a failure to open or read the
directory itself fails the call (`not_found`, `permission_denied`, `io`).

A rollup entry stands for every child of this directory matched by one tag
(a file or a directory; a directory is summed as `sum_subtree` does, and
counts in `total_dirs`):

```json
{"name": "[CACHE]", "kind": "rollup", "size": 48291049216, "allocated_size": 48295198720,
 "ino": 0, "dev": 2049, "nlink": 1, "mtime_ns": 1761001200000000000,
 "ctime_ns": 1761001200000000000,
 "rollup": {"tag": "[CACHE]", "matched": 3, "total_files": 14820, "total_dirs": 312,
            "total_size": 48291049216, "total_allocated_size": 48295198720,
            "newest_mtime_ns": 1761001200000000000, "errors": 0}}
```

`matched` is the number of children folded in (the draft called it
`matched_Folders`). The names of what is inside never leave the agent.
Hard links are counted once per `(dev, ino)` across the whole group, and the
sum does not cross onto another file system.

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
this.

### `sum_subtree`

```json
{"cmd": "sum_subtree", "path": "/volume1/Backup/NAS.hbk/Pool"}
{"ok": true, "path": "/volume1/Backup/NAS.hbk/Pool", "total_files": 512004,
 "total_dirs": 4210, "total_size": 48291049216, "total_allocated_size": 48295198720,
 "newest_mtime_ns": 1761001200000000000, "errors": 0}
```

The same totals as a rollup summary, for one directory the client names:
the rollup of a backup pool without a row per bucket. `lstat` only, never
follows symbolic links (a link counts as a file of its own size), and stays
on the file system of `path` (a different `dev` is skipped, not counted).
The directory itself is not counted. `total_files` counts names (every
non-directory entry); `total_size` and `total_allocated_size` count a file
with `nlink` over 1 once per `(dev, ino)` within the request. The policy's
`exclude` applies; rollup groups do not. `errors` counts entries and
directories that could not be read, so a total with `errors` over 0 is a
lower bound. It can take minutes on a big tree, so a client gives it a long
timeout.

### `storage_topology`

```json
{"cmd": "storage_topology"}
{"ok": true, "topology": {
  "version": 1, "platform": "synology",
  "host": {"name": "nas-main", "unc_server": "\\\\nas-main", "os": "DSM 7.2.2"},
  "collected_at": "2026-10-21T18:00:00Z",
  "nodes": [
    {"id": "disk:ZR5A1B2C", "type": "disk", "parent": null, "serial": "ZR5A1B2C",
     "slot": "1", "size_bytes": 16000900661248, "health": "ok"},
    {"id": "pool:3f7c1d2a-...", "type": "pool", "parent": null, "name": "Storage Pool 1",
     "level": "shr", "size_bytes": 64003602644992, "health": "ok"},
    {"id": "group:8c1f6a40-...", "type": "group", "parent": "pool:3f7c1d2a-...", "name": "md2",
     "role": "data", "level": "raid5", "members": [{"disk": "disk:ZR5A1B2C", "role": "data"}]},
    {"id": "vol:5b0e9c77-...", "type": "volume", "parent": "pool:3f7c1d2a-...", "mount": "/volume1",
     "fs_type": "btrfs", "size_bytes": 0, "used_bytes": 0, "free_bytes": 0},
    {"id": "share:backup", "type": "share", "parent": "vol:5b0e9c77-...", "name": "Backup",
     "path": "/volume1/Backup", "unc": "\\\\nas-main\\Backup", "protocols": ["smb"]},
    {"id": "lun:f48f1514-...", "type": "lun", "parent": "vol:5b0e9c77-...", "kind": "iscsi",
     "thin": true, "size_bytes": 11811160064000, "allocated_bytes": 12094627905536,
     "target": "PVEC",
     "initiators": [{"iqn": "iqn.1993-08.org.debian:01:pve2", "authority": 3},
                    {"iqn": "iqn.2000-01.com.synology:default.acl", "authority": 0, "default": true}],
     "match": ["uuid:f48f1514-6072-4193-989e-9e7bfbe6d0e1", "naa:6001405f48f1514d6072d4193d989ed9"],
     "platform": {"synology": {"devtype": 5, "vpd_unit_serial": "f48f1514-6072-4193-989e-9e7bfbe6d0e1"}}}
  ]}}
```

The host's storage as one generic hierarchy (disk, group, pool, volume,
share, lun, vdisk, plus `vm` on a hypervisor) rather than Synology-shaped volume records. The node
types, fields, id scheme, `platform` extras and the per-platform mappings
are specified in [storage-topology.md](storage-topology.md); the Python
validator is `filecat.topology`. In short:

- `nodes` is flat; `parent` is an id or `null` and forms a containment tree
  (group in pool, volume in pool or volume, share in volume, lun or vdisk in
  a volume or pool). Disks have no parent: groups, pools and volumes list
  `members` (`{"disk": id, "role": ...}`).
- `id` is `<type>:<platform-native key>` (pool GUID, disk serial, file
  system UUID, LUN UUID), never an array index or a name like `md2`, so it
  survives rescans.
- Sizes are bytes. `size_bytes` is logical for a `lun`/`vdisk` and
  `allocated_bytes` the physical `st_blocks * 512`, never the 512 GiB `st_size`
  of a Synology `ROD` file. A value the agent cannot tell is left out, not 0.
- Native detail goes in `platform`, keyed by platform name
  (`{"synology": {...}}`).
- Hosts are linked through their disks, not through a server field. The agent
  reports what it can see and the central side joins the snapshots of many
  hosts (`topology.resolve_links`, storage-topology.md section 5):
  - `match`, identifiers as `kind:value`: a LUN's `uuid:`; the NAA/WWN of a
    disk an initiator sees (`naa:`, from the SCSI id; Windows `UniqueId`,
    Linux `/dev/disk/by-id/scsi-3...`); a guest disk's `serial:`; a
    hypervisor vdisk's `vmserial:` (the `serial=` of its VM config) and
    `volid:` (`PVEC:0.0.1.scsi-...`); a VMM vdisk's `vmmdisk:`.
  - `virtual: true` on a disk the host knows is provided by something else
    (model `QEMU HARDDISK`, `Virtual disk`, an iSCSI disk).
  - `backing: {host, id}` only when the agent really knows the other node.
  - A `lun` reports its `target` and `initiators` (the LUN's ACL as `{iqn, authority}`); a
    `vdisk` its `vm`, the id of a `vm` node. A hypervisor reports `vm` nodes
    (Proxmox `vm:<vmid>`, Synology VMM `vm:<guest uuid>`).
  - A Proxmox node adds `host.cluster` and may return the cluster's own
    snapshot (shared storage; `host.kind: "cluster"`) as `cluster_topology`
    next to `topology`.
- A host the agent has no reader for answers `nodes: []` with its
  `platform` (`linux`). Fields may be added without a protocol bump, so
  clients keep unknown ones. This replaces the draft's `volumes` reply, which
  no client has depended on yet.

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
   `errors` is added; `rollup_groups` becomes an ordered map (the draft's
   `HashMap` makes "first tag wins" random). Hard links are counted by
   `(dev, ino)`, not by `ino` alone, and the set is shared across the whole
   group, not rebuilt for each matched folder. Unreadable directories add to
   `errors` instead of being skipped silently.
6. **`sum_subtree`** is new (the iterative `sum_rollup_subtree` exposed as a
   command, with `exclude` applied).
7. **`read_range`**: `len` over 4 MiB is `bad_request` and is checked
   before `vec![0u8; len]` (the draft allocates whatever it is asked to);
   the response adds `eof`; regular files only, `O_NOFOLLOW`.
8. **Requests**: paths are validated (absolute, no `.` or `..`);
   `path_b64` is accepted everywhere `path` is; a malformed line is
   `bad_request` and the connection survives; the line reader is capped at
   8 MiB (`read_line` in the draft grows without limit); every response is
   flushed after the write (`StreamOwned` buffers); errors map from
   `io::ErrorKind`/`raw_os_error` to a `code` through one function.
9. **`storage_topology`** is rewritten to the generic reply above; the list of
   changes to `synology_storage.rs` follows. The TLS code (`tls.rs`) is
   unchanged. Output of `cert_sha256` stays as the lowercase hex printed at
   start; the client also accepts `AA:BB:...`.

### Changes to `synology_storage.rs`

1. Replace `VolumeTopology` and `SynologyBlockDevice` with one `Node` struct
   (the fields of storage-topology.md, `Option`s skipped when `None`,
   `platform` a `serde_json::Value`) and return `Topology { version, platform,
   host, collected_at, nodes }`.
2. Ids: pool, volume and LUN ids from UUIDs (`blkid`, LVM VG, `mdadm`, the LUN
   uuid), disk ids from serials; none from index or name. A node whose key
   cannot be read is omitted and logged, not given an index.
3. Add the layers the draft lacks: disks (`/sys/block`, serial, model, slot,
   health), md arrays as `group`s from `/proc/mdstat` (`level`, `[UU_]` ->
   `degraded`, `members`), the LVM VG as the `pool`, then `volume` with a
   `parent` pool. The pool/volume link comes from the device mapper chain
   under `/sys/block/dm-*/slaves`.
4. `shares`: read the share definitions (name and `path`), not every
   top-level folder, and emit `share` nodes with `path`, `unc`
   (`\\<hostname>\<name>`) and `protocols`. The draft's `shares` held absolute
   paths of any folder that did not start with `@` or `#`.
5. `SynologyBlockDevice.kind` maps to `lun` (`san_blun`, `san_blun_thick`:
   `thin` from devtype, `kind: "iscsi"`) or `vdisk` (`vmm_vdisk`:
   `attached: true`, `vm`; `vmm_image`: `attached: false`). `provisioned_bytes`
   becomes `size_bytes`; `allocated_bytes` keeps `st_blocks * 512`. `uuid`,
   `lid`, devtype, `extent_files`, `is_meta_disk`, the `vguest.conf` fields move
   into `platform.synology`. `root_volume` becomes `parent`; `backing_dir`
   becomes `path`.
6. `used_bytes` is `f_blocks - f_bfree` (what is in use), `free_bytes` is
   `f_bavail` (what a user can take), `size_bytes` is `f_blocks`; the draft
   derives `used` from `bavail`, which counts the reserve as used.
7. Deterministic order (disks by slot, then pools, groups, volumes, shares,
   luns, vdisks, each by id) so a rescan diffs cleanly; sizes as JSON integers.
8. Links: for each LUN, `target` (the iSCSI target name) and
   `match: ["uuid:<uuid>", "naa:<derived>"]`. Read `vpd_unit_serial` from the
   LUN's stanza in `/volume1/@iSCSI/LUN/iscsi_lun.conf`, keep it in
   `platform.synology.vpd_unit_serial` and derive the NAA id from it: `6001405`
   plus the first 25 characters of the serial, every character that is not a
   hex digit replaced by the hex digit of `ord(c) & 0xF` (`-` becomes `d`),
   lowercase. `f48f1514-6072-4193-989e-9e7bfbe6d0e1` gives
   `6001405f48f1514d6072d4193d989ed9`, which Proxmox shows as
   `scsi-36001405f48f1514d6072d4193d989ed9` (confirmed on nas3;
   `topology.naa_from_unit_serial` is the reference). Parse
   `/volume1/@iSCSI/LUN/iscsi_lun_acl.conf` into each LUN's `initiators`: one
   stanza per (LUN, initiator), keyed by `lun_uuid`, each giving
   `{"iqn": <initiator>, "authority": <integer, as written>}`; the stanza whose
   initiator is `iqn.2000-01.com.synology:default.acl` is the default for
   initiators not listed, recorded as an entry with `"default": true`. Do not
   interpret `authority` (0 and 3 are seen; 0 = no access and 3 = read/write is
   a guess to verify). For each VMM vdisk,
   `match: ["uuid:<uuid>", "vmmdisk:<uuid>"]` and `vm` pointing at a new `vm`
   node per `@Repository/<vm_uuid>` (`vm:<uuid>`, name, `is_general_vm`, vCPU,
   RAM). When the agent runs inside a Virtual DSM, mark its disks
   `virtual: true` and report the VMM vdisk uuid as `vmmdisk:` if it can
   see one. Leave `backing` empty. A host that is not a Synology answers
   with `nodes: []` and `platform: "linux"` until a reader for it exists.
9. Later agents: Proxmox needs disk serial and WWN (`lsblk -o SERIAL,WWN`),
   `qm config` (`vm` nodes, `serial=` and volume ids on each vdisk), and the
   cluster's shared storages; Windows needs `Get-Disk`'s `UniqueId` (NAA id)
   and `SerialNumber` for each disk and `Get-InitiatorPort` for the host's
   IQN; TrueNAS needs the disk serial (`lsblk`, `zpool status -P`).
10. Reads stay read-only and root-only paths that cannot be read produce a
   `health: "unknown"` node with a `detail`, not a failed command.
