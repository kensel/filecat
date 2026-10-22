# File catalog requirements

Requirements for a Python program that walks directories on this PC and on
NAS shares, records each file, and extracts details the bytes support.
The first model backend is a local Ollama server. This note is the
requirements. It is not the program.

The catalog is a general inventory of storage. A game install, a documents
folder, and a media share are all valid roots. Probes for executables,
models, textures, and the X3 data formats run when the bytes match. They
do not define what gets scanned.

Suggested home for the program and this note: `C:\code\filecat\`. Catalog
databases stay on local disk unless the user points `--out` or `--dsn`
somewhere else. The scan does not copy file bodies into the catalog.

## Goal

Given one or more roots, the program writes one record per file and one
record per directory. A record holds identity (root, relative path, size,
times, hash policy result), a probed kind, and the measurements that kind
supports. The same record can be stored as JSONL, SQLite, PostgreSQL,
MySQL, SQL Server, or MongoDB.

The program finishes a scan when Ollama is absent. Ollama, when asked,
adds a summary beside the measurements for a bounded set of files.

`filecat summary` is the WinDirStat-style overview: bytes, file count, and
percent, grouped by extension, by directory, and by identified type.
`filecat programs` is a separate inventory of installed software. Neither
one draws a treemap. The aggregates are what a later treemap would read.

## Non-goals

* Deleting, moving, or rewriting anything under a root.
* Uploading file bytes to a hosted model. Ollama is local.
* A backup, a deduplicator, or a full-text search engine.
* Unpacking a Steam stub, or disassembling an executable. A packed image
  is recorded as packed and left there.
* Copying archive members, meshes, photos, or executables into the
  catalog. The catalog stores measurements and short text samples.
* Treating an Ollama reply as a fact that overrides a measurement.
* Downloading a signature database during a scan. Database files are
  local. Updating them is a separate step.

## Run

```
filecat scan ROOT [ROOT ...] --backend sqlite --out C:\code\filecat\catalog.sqlite
filecat scan C:\ D:\ \\nas\share --backend jsonl --out C:\code\filecat\catalog.jsonl
filecat scan \\nas\share --backend postgres --dsn "$FILECAT_DSN"
filecat scan ROOT --backend mysql --dsn "$FILECAT_DSN"
filecat scan ROOT --backend mssql --dsn "$FILECAT_DSN"
filecat scan ROOT --backend mongodb --dsn "$FILECAT_DSN"
filecat scan ROOT --ollama --model NAME
filecat summary --backend sqlite --out C:\code\filecat\catalog.sqlite
filecat summary --by extension --by mime --by dir --depth 2
filecat show REL_PATH --root ROOT --backend sqlite --out C:\code\filecat\catalog.sqlite
filecat scan ROOT --identify always
filecat scan ROOT --pronom
filecat programs --backend sqlite --out C:\code\filecat\catalog.sqlite
```

A root may be a drive (`C:\`), a folder, or a UNC share (`\\server\share`).
Mapped drive letters are accepted and stored as given. A second column
`probe.unc` is filled when Windows can resolve the map to a UNC path, so
a later scan of the same share under a different letter can be matched.

One unreadable file is recorded with `errors` filled and the scan
continues. The process exits 0 when every visited entry was recorded, and
exits 1 when one or more records contain an extractor error. A missing
Ollama server, with `--ollama` set, is an error on the `llm` object only.

## How a large or remote tree is walked

* Stay on the volume that the root is on. A scan of `C:\` does not follow
  a junction onto `D:\` or onto a share. A scan of `\\nas\share` stays on
  that share. Extra volumes are extra roots.
* Symlinks and junctions are recorded as `link` and are not followed.
* Access denied, a sharing lock, a timeout, and a path that is too long
  are recorded on that entry. The walk continues with the next sibling.
* Per-entry timeout defaults to 30 seconds on a local volume and 120
  seconds on a UNC path. `--timeout` overrides both.
* Progress is a line every few seconds: root, files seen, bytes seen,
  last path. A resume file next to the catalog lists the last completed
  directory. A rerun skips directories whose recorded mtime and child
  count are unchanged, and rewrites a directory whose mtime changed.
* `--force` remeasures every entry.

Default hash policy, because a NAS holds files larger than RAM:

| file size | what is hashed |
|---|---|
| 0 | no hash; `sha256` omitted |
| 1 byte through 64 MiB | SHA-256 of the whole file |
| larger than 64 MiB | SHA-256 of the first 1 MiB, the last 1 MiB, the size, and the mtime, recorded as `sha256_partial` |

`--hash full` hashes every readable byte and stores `sha256`. `--hash none`
stores no digest. A partial digest is never written into the `sha256`
field.

Default name skips, overridable with `--no-default-skips`:

* `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` at a drive root
* the directory `$Recycle.Bin`
* the directory `System Volume Information`

Everything else is visited, including hidden files and folders whose
names start with `.`.

## Record

Every backend stores this document. SQL backends store one row in `files`
with indexed columns for the fields marked below and a JSON column
`document`. MongoDB uses collection `files`. JSONL is one UTF-8 document
per line.

| field | indexed | meaning |
|---|---|---|
| `root_id` | yes | hash of the root path string the user passed |
| `root` | | that path string |
| `rel_path` | yes | path relative to the root, `/`-separated; unique with `root_id` |
| `name` | | final path component |
| `size` | | bytes, 0 for a directory |
| `mtime_ns` | | modification time when the filesystem provides it |
| `ctime_ns` | | creation time when the filesystem provides it |
| `sha256` | yes | full-file digest, or omitted |
| `sha256_partial` | | set only under the partial policy |
| `kind` | yes | one label from the list below. Set by the built-in probe, not by a type database |
| `container` | | `plain`, `gzip`, `gzip_xored`, `zip`, `pe`, `bzip2`, `xz`, `7z`, or `unknown` |
| `suffix` | yes | extension in lower case, without the dot. Empty when the name has none |
| `mime` | yes | winning type from Type identification, or omitted |
| `encoding` | | see Encoding |
| `newlines` | | see Encoding |
| `probe` | | kind-specific measurements. Omitted keys were not measured |
| `sample` | | at most 4 KiB of decoded text, or omitted |
| `llm` | | present only after an Ollama call |
| `errors` | | list of `{stage, message}` |

`kind` is one of: `dir`, `link`, `empty`, `exe`, `archive`, `image`,
`texture`, `mesh`, `audio`, `video`, `document`, `text`, `data`,
`save`, `unknown`.

`data` is a structured text or binary table the probe recognized
(spreadsheet export, CSV, a decoded catalogue index, a semicolon table).
`document` is PDF or an Office document. `image` is a picture. `texture`
is a GPU texture container (DDS, TGA). `mesh` is a 3D model container
the probe knows.

## Backends

One storage interface: `put(document)`, `get(root, rel_path)`,
`list(kind)`, `summary()`. All six backends implement it.

| backend | requirement |
|---|---|
| `jsonl` | UTF-8, one document per line. Rescan rewrites so each `(root, rel_path)` appears once. |
| `sqlite` | stdlib `sqlite3`. Unique `(root_id, rel_path)`. Default backend. |
| `postgres` | `psycopg` v3. `document` is `jsonb`. |
| `mysql` | `pymysql`. `document` is `JSON`. |
| `mssql` | `pyodbc`. `document` is `NVARCHAR(MAX)` of UTF-8 JSON. |
| `mongodb` | `pymongo`. Unique index on `(root_id, rel_path)`. |

JSONL and SQLite are the base install. The others are extras:
`filecat[postgres]`, `filecat[mysql]`, `filecat[mssql]`, `filecat[mongo]`.
The program creates its table or collection. It does not create the
database or the login. Connection strings come from `--dsn` or
`FILECAT_DSN`.

A contract test writes three synthetic documents through each backend the
environment has enabled and reads them back. Values match. JSON key order
may differ. CI runs SQLite and JSONL. The other four run when
`FILECAT_TEST_POSTGRES`, `FILECAT_TEST_MYSQL`, `FILECAT_TEST_MSSQL`, or
`FILECAT_TEST_MONGODB` is set.

## Probe order

Magic wins over the file name. The extension is used when the bytes have
no recognized header, and it is recorded as `probe.ext_only = true` in
that case.

1. Directory → `dir`. Record child count when the listing succeeds.
2. Reparse point or symlink → `link`, with the target string when the
   OS returns it.
3. Size 0 → `empty`.
4. `MZ` and a PE header → `exe`.
5. ZIP local header → `archive`. A ZIP whose first entry names
   `[Content_Types].xml` is `document` and `container` stays `zip`.
6. `1F 8B`, or the XOR-gzip wrapper below → unwrap up to 4 MiB for
   probing, then classify the inflated bytes. `container` stays `gzip`
   or `gzip_xored`.
7. `DDS ` → `texture`. A TGA header that passes the checks below →
   `texture`. JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), or GIF (`GIF8`) →
   `image`.
8. `BOB1` → `mesh`.
9. `RIFF`/`WAVE`, `ID3`, or a frame sync that identifies MP3 → `audio`.
   `ftyp` in an ISO BMFF box, or an EBML header → `video`. Duration is
   omitted unless it is in the header the probe already parsed.
10. `%PDF` → `document`. Record the version token on the first line.
11. Text (no NUL in the first 8 KiB, and a decoded encoding) → `text`,
    then refined: CSV when the first line splits into at least two
    columns on `,` or `;` or a tab; a semicolon `version;count;` or
    `fields;count;` header → `data`.
12. Anything else → `unknown`. The extension, when it has one, is stored
    on `probe.suffix`.

The X3 pack below is a refinement of steps 6, 8, and 11. It does not run
on files that already classified as a picture, a PE, or a PDF.

The built-in list sets `kind`. The databases in Type identification set
`mime` and the description fields. A database result does not change
`kind`.

## Type identification

Two layers, because a full-disk magic read is a lot of seeks and a name
is free.

1. **Names, every file.** Take the suffix. Look it up in a vendored copy
   of the freedesktop shared-mime-info glob list
   ([spec](https://specifications.freedesktop.org/shared-mime-info/latest-single/)).
   Store `probe.mime_glob` and `probe.mime_glob_desc`. This layer is what
   makes the extension table say "Word document" for `.docx` before any
   byte has been read.
2. **Bytes, when asked.** `--identify` reads at most 8 KiB (2 KiB is the
   minimum that libmagic's own guidance treats as enough) and runs magic.
   Default is `local`: on for a drive-letter or local path, off for a UNC
   root. `--identify always` and `--identify never` override that.
   `probe.mime_magic` and `probe.mime_magic_desc` come from libmagic
   (`python-magic-bin` on Windows) and, when the vendored magic rules
   also match, from shared-mime-info. The same 8 KiB buffer feeds the
   built-in probe, so the file is not opened twice.

The winner in `mime` follows the shared-mime-info rule: if a glob type
is the magic type, or a subclass of it, that glob type wins (this is how
`report.doc` that is OLE storage stays a Word document). Otherwise the
highest-priority magic match wins. Otherwise the highest-weight glob
wins.

`probe.identify_basis` is one of:

| value | when |
|---|---|
| `name` | magic was not run |
| `bytes` | magic matched and the name had no glob |
| `agree` | glob and magic are equal, or one is a subclass of the other |
| `disagree` | both matched and neither rule above applies |

A disagreement stays visible after a winner is chosen. `report.pdf` whose
bytes are a PNG is `mime` from the rule above, with both inputs stored
and `identify_basis = disagree`.

Optional identifiers, each off unless its flag is set. A missing tool
records one scan-level error and leaves the name layer intact.

| flag | tool | what is stored |
|---|---|---|
| `--pronom` | [Siegfried](https://github.com/richardlehane/siegfried) `sf -json`, PRONOM signatures from [the National Archives](https://www.nationalarchives.gov.uk/pronom/) | `probe.pronom_id`, `probe.pronom_name`, `probe.pronom_version`, `probe.pronom_mime`, and the basis string Siegfried reports (extension, byte, or container). A v108 export of the registry lists about 2,200 formats. |
| `--trid-defs PATH` | [TrID](https://mark0.net/soft-trid-deflist-y.html) definition list, used as a suffix-to-description table | `probe.trid_desc`. The list published 30 Sep 2026 has 22,344 definitions. The defs file is not downloaded or bundled until its license is checked. |
| `--magika` | [Magika](https://github.com/google/magika), extra `filecat[magika]` | Run only when `identify_basis` is `disagree` or `kind` is `unknown`. Store `probe.magika_label` and `probe.magika_score`. A score below 0.5 does not change `mime`. |

Apache Tika's MIME set is already one of the inputs Siegfried can build
into a signature file. The program does not ship a second copy.

Signature files live under `C:\code\filecat\signatures\`. A scan never
fetches them. `filecat signatures status` prints the file names and the
dates recorded inside them.

## Overview

`filecat summary` reads the catalog and prints three tables. Counts and
bytes are sums of file records. Directories are not added again on top of
their children.

| table | group | columns |
|---|---|---|
| extensions | `suffix`, with `(none)` for names that have no dot | description from `mime_glob_desc`, file count, total bytes, percent of the root |
| types | `mime` when present, otherwise `kind` | same counts |
| directories | directory `rel_path` cut to `--depth` (default 2) | file count, total bytes, percent |

`--by extension`, `--by mime`, and `--by dir` select one table. With no
`--by`, all three print. Percent is of the bytes successfully sized in
that root. Entries with an `errors` value and no size are counted in a
final line, `unreadable`.

`filecat summary --disagree` lists files whose `identify_basis` is
`disagree`: path, suffix, glob type, magic type, size. That list is the
detail WinDirStat's extension view does not have.

The same aggregates are stored, so a UI can draw them later without
walking the tree again:

| backend | where |
|---|---|
| sqlite, postgres, mysql, mssql | tables `agg_suffix`, `agg_mime`, `agg_dir`, rebuilt at the end of a scan and by `filecat summary --rebuild` |
| mongodb | collections with those names |
| jsonl | `catalog.summary.json` beside the jsonl file |

## Installed programs

`filecat programs` inventories software on this PC. It does not walk a
NAS, and it does not treat every `.exe` and `.dll` as a product. Results
go in table or collection `programs` in the same catalog.

Read, with `winreg`:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
* `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
* the per-user AppX registration under
  `HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages`
  when that key is readable

Each record stores display name, publisher, display version, install
location, estimated size when the key has one, and which hive it came
from. A key with no display name is skipped.

Also store:

* each directory on `PATH`, and the `.exe` names directly inside it
  (one level, no recursion)
* each `.lnk` under the per-user and all-users Start Menu. Record the
  shortcut path. When the Shell Link header is the standard header,
  record the local path it points at. A shortcut that does not parse
  keeps the path and an `errors` entry.

When a file record is an `exe` and its VERSIONINFO product name equals a
program display name, `probe.installed_program` on the file record is
that display name. The join runs at the end of `filecat programs` against
whatever file records are already in the catalog. A programs scan does
not require a file scan first.

## Encoding and newlines

Run on every buffer treated as text, including an inflated gzip body and
a decoded catalogue index.

| check | record |
|---|---|
| Leading `EF BB BF` | `encoding.bom = "utf-8"` |
| Leading `FF FE` or `FE FF` | `encoding.bom = "utf-16-le"` or `"utf-16-be"` |
| No BOM, valid UTF-8 | `encoding.detected = "utf-8"` |
| No BOM, UTF-8 fails | `encoding.detected = "latin-1"` |

Latin-1 is the fallback so a byte is never dropped. The detector does not
use a statistical language guess. When XML names an encoding in its
declaration, record `encoding.declared` and `encoding.declared_matches`.

Newlines on the decoded text:

| value | condition |
|---|---|
| `lf` | only `\n` outside of `\r\n` |
| `crlf` | only `\r\n` |
| `cr` | only `\r` |
| `mixed` | more than one of those |
| `none` | no line break |

`sample` is the decoded text truncated to 4 KiB, with `sample_truncated`
set when the file was longer. Binary kinds omit `sample`.

## Executables

Use `pefile`. Record:

* Machine, magic (`PE32` or `PE32+`), subsystem.
* Linker major and minor from the optional header.
* Timestamp as a UTC instant.
* Characteristics and DLL characteristics, as the integer and the flag
  names pefile knows.
* Entry point, image size, and each section's name, virtual address,
  virtual size, raw size, and Shannon entropy of the raw bytes.
* CodeView PDB path when present. Store the string. Do not open it.
* Import directory: DLL name to symbols. An ordinal stays an ordinal.
* Whether a `VERSIONINFO` resource exists. Record product name and file
  version when it does.

### Rich header and toolchain

`parse_rich_header()` yields `(comp_id, count)` pairs. `comp_id` is
`(prod_id << 16) | build`. `count` is object files linked in, including
libraries. It is not a line count.

Map `prod_id` through the public names in
`https://github.com/dishather/richprint/blob/master/comp_id.txt`. An id
missing from that list is stored as the integer and the role `unmapped`.
The program must not invent a product name.

`probe.toolchain.linker` is the PE linker major.minor. `probe.toolchain.objects`
is the Rich rows: prod id, build, count, and role. Build 40116 on product
ids 241, 242, and 243 stays the 12.10 family (`Masm1210`, `Utc1810_C`,
`Utc1810_CPP`). Those rows are not labeled as a newer Visual Studio.

When section entropy and a packer marker say the image is packed, record
`probe.packed = true` and skip Rich and import reads that would describe
only the stub. Do not unpack.

## Archives, images, models, data

ZIP: record entry count, uncompressed total when the central directory
says it, and up to 100 entry names. Do not extract. `--list-zip-cap`
changes the 100.

Gzip, probed on the raw bytes before inflation:

| bytes | container | before inflate |
|---|---|---|
| `1F 8B` at offset 0 | `gzip` | the gzip header |
| `byte0 ^ 0xC8` makes bytes 1 and 2 into `1F 8B` | `gzip_xored` | drop one byte, XOR the rest with that key |

Record method, flags, mtime, and OS byte when the header parses. Inflation
for probing stops at 4 MiB. The file's own size stays `size`.

Catalogue pair, only when a `.cat` decodes as text under
`byte[i] ^= (0xDB + i) & 0xFF` and the lines look like `<path> <size>`:

* Kind `data`, `probe.format = "x3-cat"`.
* Skip the first line. Each kept entry stores the raw path, the size, and
  the running offset.
* The sibling whose name ends in `.dat` is `probe.format = "x3-dat"` and
  records the transform `byte ^= 0x33`. Payloads are not expanded unless
  `--expand-dat` is set, and then only up to `--member-cap` (default 1000).

`texture` / DDS: height, width, mip count, fourcc. `texture` / TGA: width,
height, pixel depth, image type. Image types outside {1, 2, 3, 9, 10, 11}
leave the file to the next probe. `image` / JPEG, PNG, GIF: width and
height from the header. No pixel decode.

`mesh` / `BOB1`: chunk tags present, and a count of vertex tags `0x001B`
(38 bytes) and `0x001F` (46 bytes). Another vertex tag sets
`probe.unknown_vertex_tag` and stops the walk. Other model filenames
(`.obj`, `.stl`, `.glb`) are `mesh` with `probe.ext_only = true` until a
header parser for that format is added.

Text whose first line is `VER:` and an integer is `mesh` with
`probe.format = "scene-text"` and that integer stored. This is the scene
grammar already seen on `.pbd` files.

A file named `lang.dat` whose entire body is an integer plus a newline
records `probe.language_id`. A gzip whose inflated body begins `XSA3` and
ends `/XSA` within the probe window is `save`, and the tag order among
`XSA3`, `SYSB`, `TIME`, `STOR`, `/XSA` in that window is stored.

CSV and semicolon tables record the separator, the field count on the
first record, and the record count up to 10_000 (`probe.truncated` past
that). Column meanings are not assigned.

## Ollama

Off unless `--ollama` is set. `--model` is required with it. The default
base URL is `http://127.0.0.1:11434`, overridable with `--ollama-url` or
`OLLAMA_HOST`.

A full disk must not call the model once per file. The default, when the
flag is on, is files whose `kind` is `unknown`, whose size is at most
256 KiB, and whose decoded sample is non-empty, up to 200 calls per scan.
`--ollama-kinds` and `--ollama-max-files` change that bound.

Call `POST /api/chat` with `stream: false` and `temperature: 0`. Timeout
60 seconds. The user message is the record with `sample` already capped.
No raw file is attached. The system message is versioned
(`llm.prompt_version`) and asks for:

```
{"summary": "one or two sentences", "labels": ["..."], "unsure": true}
```

`labels` has at most eight short strings. A reply that is not that JSON
is stored as `llm.raw` and `llm.error`. The program never copies model
keys onto `kind`, `sha256`, encodings, Rich rows, sizes, or offsets.

If the server is down or the model name is unknown, affected records get
`llm.error` and the scan continues.

## Tests

Fixtures are built in `C:\code\filecat\tests\` by the tests. They are not
taken from a personal folder or a share.

| fixture | must record |
|---|---|
| Latin-1 text that is not valid UTF-8, CR LF | `detected=latin-1`, `newlines=crlf` |
| UTF-8 BOM, LF only | `bom=utf-8`, `newlines=lf` |
| Mixed CR LF and LF | `newlines=mixed` |
| XML declaring `encoding="UTF-8"` while the bytes are Latin-1 | `declared_matches=false` |
| JPEG header large enough for width and height | `kind=image`, those dimensions |
| `DDS ` 4×4, fourcc `DXT1` | `kind=texture` |
| ZIP with two named entries | `kind=archive`, both names |
| 7z with an LZMA2-compressed header, two files, a folder and an empty file | `kind=archive`, `container=7z`, those four names with sizes and CRCs |
| PE with a known linker version in a tiny synthetic image | `kind=exe`, that linker |
| File of 64 MiB + 1 byte | `sha256` omitted, `sha256_partial` set |
| Directory listing that raises access denied on one child | that child has `errors`, the sibling is still recorded |
| File named `note.pdf` whose bytes are a PNG signature | `mime_glob` is PDF, `mime_magic` is PNG, `identify_basis=disagree`, `kind=image` |
| File named `note.pdf` with `--identify never` | `identify_basis=name`, `mime` from the glob |
| Three files, two suffixes, known sizes | `summary --by extension` totals equal the sum of those sizes |

An optional check reads `FILECAT_EXE` when it is set and asserts the Rich
row count for one prod id printed by the same `pefile` the tests import.
It does not run by default.

Resume: a scan whose second directory raises `TimeoutError` writes the
resume marker after the first directory, and a second scan does not
rehash the first directory's unchanged files.

## Done when

* `filecat scan` of a synthetic tree writes JSONL and SQLite documents
  that compare equal.
* The fixture table and the resume check pass.
* A scan with `--ollama` against a refused port finishes with measured
  fields intact and `llm.error` set.
* A UNC root that is offline fails that root with one error record and
  still scans any other roots on the command line.
* The README in `C:\code\filecat\` points at this note and lists the
  database extras.
* `filecat summary --by extension` on the fixture tree matches a hand
  count of files and bytes.
* `filecat programs` run against a `.reg` fixture records the display
  name, version, and hive from that file, and writes nothing under the
  scanned roots.

## Open points

| id | question |
|---|---|
| F1 | Whether the partial-hash cutoff should be 64 MiB or something larger once a real NAS pass shows how long full hashes take. |
| F2 | Which Ollama model is worth turning on. The model flag stays required, and the 200-call cap stays, until one pass is reviewed by hand. |
| F3 | Whether SQL Server should take `--trusted` beside `--dsn`. |
| F4 | A query language beyond `summary` and `show`. Until then the database is the query tool. |
| F5 | Which extra model headers (glTF, STL, OBJ) earn a real parser after the first inventory shows they are common on the shares. |
| F6 | Whether `--identify local` is the right UNC default once one share has been timed with `--identify always`. |
| F7 | The TrID defs license. Until it is checked, `--trid-defs` only accepts a path the user supplies. |
