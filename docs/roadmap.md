# Roadmap

Planned releases. The design background for most of it is
[research note 05](research/05-catalog-tuning-agent-boundary.md).

## v0.1.1: compound documents (done)

Section 1 of note 05. `data/compound_formats.toml` separates true archives
from ZIP/gzip-based application formats; a `.docx`, `.jar` or `.epub`
stores only its anomalies (macros, embedded objects, executables,
unexpected paths) as members. See [compound-formats.md](compound-formats.md).

## v0.1.2: content-addressed text samples

Note 05, section 2.A. The 4 KiB text sample and the Ollama result move off
the file record into a `samples` store keyed by content hash (`sha256`, or
`sha256_partial` above 64 MiB), so ten copies of a file share one sample
and one model call.

The first run with v0.1.2 migrates the existing records, which can be more
than 20 million, so the migration must be crash-safe:

- resumable: progress is checkpointed, and a restart continues from the
  last checkpoint rather than from the beginning;
- idempotent: a sample is written before the file record loses its inline
  copy, so a crash between the two steps leaves both, never neither, and
  redoing the step is harmless;
- batched, so it never holds the whole collection in memory, and reports
  progress;
- records without a hash keep their inline sample until they get one.

## v0.1.3: members keyed by archive hash

Note 05, section 2.B. The parent key of `members` changes from
(root, archive path) to the archive's content hash, so an archive present
in four places stores its members once, and moving or renaming it orphans
nothing. Same crash-safe migration approach as v0.1.2.

## v0.2.0: Rust agents and embedded metadata

- The Rust agents go in (research note 02). Note 05, section 3 sets the
  division of labour: the agent does listing, hashing and storage topology
  on the NAS; the central Python server keeps store detection, manifest
  verification, probing and Ollama.
- Embedded metadata: creator, title, subject, revision and application
  version from Office and OpenDocument files (the `metadata` parts listed
  in `compound_formats.toml`), EXIF/XMP from images, and tags from audio
  and video.
