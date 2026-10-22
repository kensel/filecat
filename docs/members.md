# Archive members and member sets

A probe lists what is inside an archive (ZIP, tar, 7z, ISO, MPQ, PCK, X3
catalogs, disk images) as member rows: one per entry, with its path, size,
role and what else the format records. The rows are stored apart from the
archive's record, which keeps a summary under `probe` (`members_count`,
`member_roles`, the first `entries`). `filecat members REL_PATH --root ROOT`
prints them, and so does the record view of `filecat serve`.

Compound documents (`.docx`, `.jar`, `.epub`...) store only their
anomalies; see [compound-formats.md](compound-formats.md).

## Member sets

An archive present in four places (two shares and two backup generations)
used to store its rows four times, under each copy's root and path, and
moving or renaming it left the old rows behind. Background: research note
[05, section 2.B](research/05-catalog-tuning-agent-boundary.md#b-deduplicating-members-by-archive-content-hash).

SQLite, PostgreSQL, MySQL, SQL Server and MongoDB file the rows of an
archive that has a content hash once per hash, as a member set:

- the key is the archive's `sha256`, or `sha256_partial` above 64 MiB;
- a header (`member_sets`) holds the key, `hash_type`, the row `count` and a
  `digest` of the rows; the rows (`set_members`) carry `members_id` instead
  of a root and path;
- the archive's record names its set with `members_id`.

A scan that lists an archive whose set is already stored with the same rows
writes nothing more. A listing that differs (another `--max-members`, or
`--expand-compound`) replaces the set, and every copy shows the newest
listing.

Archives without a hash (`--hash none`) keep their rows under their path,
as before, and so do the JSONL backends. `filecat migrate` follows the
target: sets are copied as sets, written out under each archive's path for
a JSONL target, and filed by hash when a JSONL catalog moves into a
database.

## Moving existing rows: `filecat member-sets migrate`

Archives scanned before v0.1.3 keep their rows under their path until a scan
lists them again; unchanged files are not. To move them all:

```
filecat member-sets migrate [--backend ... --out ... | --dsn ...] [--batch 1000] [--limit N]
filecat member-sets stats
```

It reads the records in the backend's own key order, as
[`filecat samples migrate`](samples.md#moving-existing-records-filecat-samples-migrate)
does, and only looks up rows for records whose summary says they have some.
Per batch:

1. each archive's rows are written as a member set and committed, header
   last;
2. the records are rewritten naming their sets, and flushed;
3. the rows under the old paths are deleted;
4. the checkpoint is saved (`<catalog>.members-migrate.json`, or
   `.filecat-<backend>.members-migrate.json` here for a server).

It is safe to stop at any point. A stop before step 2 leaves sets no record
names yet. A stop during step 2 or 3 leaves records that name a set and
still have rows under their path; the rerun deletes those. Every archive
shows its members throughout. `--limit` stops after that many records for a
trial run; run it again to continue.

The same pass trims compound documents listed before v0.1.1: a `.docx`
whose every entry was stored keeps only its anomalies (macros, embedded
objects, unexpected paths) and gets the `probe.compound` summary a scan
would give it, and the kind a scan gives it (`document` for Office files). `--expand-compound` keeps
every entry instead.

## Pruning

Sets that no record names any more (the archive was deleted, changed or
dropped) stay until pruned, and so do samples:

```
filecat member-sets prune
filecat samples prune
```

Each is one pass on the server, which reads every record once. A scan
writes a set or sample a moment before the record that names it, so prune
refuses while `filecat roots` shows a scan in progress (`--force` prunes
anyway). Dropped records (`filecat dropped`) do not keep their set or
sample from being pruned.

## MongoDB

Collections the backend creates (`files`, `members`, `samples`,
`member_sets`, `set_members`) start out with zstd block compression, and a
new catalog's `sha256` index covers only records that have a hash
(`partialFilterExpression`). Existing collections keep the compression and
indexes they were created with until they are rebuilt (note 05, section
2.C), in place:

```
filecat mongo-rebuild --dry-run            # sizes, compression, what would be rebuilt
filecat mongo-rebuild [--collection files ...]
```

Each collection is copied on the server into `<name>__rebuild` (zstd), its
indexes are created there (`files.sha256` as a partial index), the counts
are compared, and `renameCollection` swaps the copy in for the original.
A collection already on zstd only gets its `sha256` index rebuilt, if that
is what it lacks. Nothing may write meanwhile, so it refuses while a scan
is running (`--force` to go ahead), and it needs free disk space for a
compressed copy of each collection in turn. It also gives back the space
of deleted documents, as `compact` would: after `filecat member-sets
migrate`, `members` shrinks to the rows still kept under a path.
`filecat migrate` into a new database rebuilds them the same way.
