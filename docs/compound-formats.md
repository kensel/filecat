# Compound documents

Many application formats are ZIP or gzip files inside: `.docx`, `.xlsx`,
`.odt`, `.epub`, `.jar`, `.apk`, `.3mf`, X3 savegames and others. The probe
sees the ZIP or gzip header either way. Listing every entry of every `.docx`
as an archive member multiplies the `members` store 10 to 50 times over
without telling anyone anything: every Word document has a
`word/styles.xml` and a `[Content_Types].xml`.

`src/filecat/data/compound_formats.toml` decides, per file, whether its
entries are worth storing. Background: research note
[05, section 1](research/05-catalog-tuning-agent-boundary.md#1-stopping-the-members-explosion-compound-document-filtering).

## What happens to a file

1. **True archive.** The extension is in `[archive]` (`.zip`, `.7z`,
   `.tar.gz`, `.iso`, X3 `.cat/.dat` ...), or nothing below matches. Every
   entry becomes a member row, as before.
2. **Compound document.** The exact file name is in a format's `names`, the
   extension is in its `types`, or, for a ZIP with an extension that says
   nothing (`.bin`, no extension), every one of a format's `markers` is
   among the entries. Then for each entry:

   | rule (checked in this order) | stored? | `anomaly` |
   |---|---|---|
   | directory entry | no | |
   | matches an `anomalies` glob | yes | the rule's reason (`macros`, `embedded_object`, `activex` ...) |
   | its role (`probe/members.py`) is in `anomaly_roles` | yes | `embedded_<role>` (`embedded_exe`, `embedded_archive`, `embedded_script`) |
   | matches an `expected` glob | no | |
   | anything else | yes, unless `record_unexpected = false` | `unexpected` |

The role check comes before `expected` on purpose: an `.exe` under
`word/media/` is under an expected path and still worth a row.

`--expand-compound` stores every entry again, still marking the anomalies.

## What the file record keeps

`probe.compound` on the file's own record:

```json
{"format": "ooxml",
 "mime": "application/vnd.ms-word.document.macroEnabled.12",
 "entries": 14, "expected": 11, "anomalies": 3,
 "reasons": {"macros": 1, "embedded_object": 1, "unexpected": 1},
 "metadata_parts": ["docProps/core.xml", "docProps/app.xml"],
 "marker_missing": true}
```

- `entries`, `expected`, `anomalies`: counts. `probe.entry_count` is still
  the full central directory; `probe.members_count` and `probe.entries`
  describe only the rows stored.
- `marker_missing`: the extension selected a format but its marker entries
  are absent (a `.docx` without `[Content_Types].xml`): renamed, damaged,
  or not what it claims to be.
- `metadata_parts`: which of the format's `metadata` parts exist. Nothing
  reads them yet; see below.

Compound documents scanned before v0.1.1 still hold every entry until a
scan lists them again, or `filecat member-sets migrate` trims them
([members.md](members.md#moving-existing-rows-filecat-member-sets-migrate)).

Gzip-wrapped formats (`x3_save`, `nbt`, `blend_gz`) get `format` and `mime`.
They never had member rows unless a tar was inside; being listed now also
stops a tar sniff from expanding them.

## Editing the file

Each `[compound.<id>]` table takes `description`, `container` (`zip` or
`gzip`), `kind`, `types` (extension to MIME type), `names`, `markers`,
`expected`, `anomalies`, `anomaly_roles` and `metadata`. Globs: `*` stays
within one path segment, `**` crosses segments, and a leading `**/` also
matches nothing at all; matching ignores case.
`tests/test_probe_compound.py` checks that the file loads and that no
extension belongs to two formats, or to a format and `[archive]`.

Files measured before this change keep their old member rows until they are
measured again (`filecat scan --force` on the affected roots).

## Embedded metadata (planned for v0.2.0)

The `metadata` lists are where v0.2.0 starts reading creator, title,
subject, revision, application and version. For Office documents that is
`docProps/core.xml` and `app.xml`, for OpenDocument `meta.xml`, for EPUB the
`.opf` package, for JARs `META-INF/MANIFEST.MF`. The same release covers
formats that are not compound documents: EXIF/XMP in images, and tags in
audio and video (ID3, Vorbis comments, MP4 atoms, Matroska tags). See
[roadmap.md](roadmap.md).
