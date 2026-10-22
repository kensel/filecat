# Text samples and Ollama results

A probe keeps a decoded text sample of up to 4 KiB on records it can read
as text (and a printable one on unknown files), and `--ollama` adds an
`llm` result. Ten copies of a file across shares and backup generations
used to mean ten copies of both, and ten model calls. Background: research
note [05, section 2.A](research/05-catalog-tuning-agent-boundary.md#a-moving-4-kib-text-samples--ollama-tags-to-a-content-keyed-samples-collection).

## The samples store

SQLite, PostgreSQL, MySQL, SQL Server and MongoDB keep one sample document
per content hash, in a `samples` table or collection:

```json
{"sample_id": "e3b0c442...", "hash_type": "sha256", "size": 16795,
 "encoding": {"detected": "utf-8"}, "sample": "Economic Paper Requirements...",
 "sample_truncated": true,
 "llm": {"model": "...", "prompt_version": "filecat-1", "summary": "...", "labels": ["..."]}}
```

- The key is the file's `sha256`, or `sha256_partial` for files over
  64 MiB (`hash_type` says which).
- The file record keeps `sample_id` instead of `sample`, `sample_truncated`
  and `llm`. Its `encoding` and `newlines` stay on the record.
- A record without a hash (`--hash none`, or data listed only) keeps its
  sample inline until a later scan or `enrich` hashes it.
- MongoDB creates the collection with zstd block compression; `_id` is the
  hash.
- The JSONL backends keep samples inline, as before.

`filecat show`, the web viewer's record view and `filecat migrate` to a
JSONL catalog put the sample back on the record, so readers see the same
fields as before.

## Ollama once per content

`--ollama` sends each unique sample once: copies of a file are one
candidate, and the result is stored on the sample document, where every
copy shares it. A sample that already has a result from the same model and
prompt version is not sent again; a different `--model`, or an earlier
error, asks again. Inline samples (no hash, or a JSONL catalog) work as
before, with the result on the record.

## Moving existing records: `filecat samples migrate`

Records written before v0.1.2 hold their samples inline. New scans write
the store, but unchanged files are not rewritten, so existing records move
with:

```
filecat samples migrate [--backend ... --out ... | --dsn ...] [--batch 1000] [--limit N]
filecat samples stats
```

It reads the records in batches in the backend's own key order (the row
`id`, or `_id` in MongoDB), which rewriting a record does not change. Per
batch:

1. the batch's samples are written to the store and committed (a sample
   already there is kept, and an inline `llm` fills in only a sample that
   has none);
2. the records are rewritten without their inline copy and flushed;
3. the checkpoint is saved: written to a temporary file, synced, then
   renamed over the previous one.

That order makes it safe to stop at any point: Ctrl+C, a crash, a lost
connection or a reboot.

- A stop before step 2 finishes leaves samples no record names yet, never
  a record naming a missing sample.
- Rerunning a batch is harmless: the records it already rewrote have no
  inline sample left, so they are skipped.
- The checkpoint only saves time. It lives beside the catalog
  (`<catalog>.samples-migrate.json`), or in the current directory for a
  server (`.filecat-<backend>.samples-migrate.json`). It holds a tag of the
  catalog, never the DSN, and is ignored for any other catalog. Without it
  a rerun starts over and is still correct.
- `--limit` stops after that many records, for a trial run; run it again
  to continue. When the pass reaches the end, the checkpoint is removed.

A scan may run while the migration does; whichever writes a record last
leaves it in the new form.

## Pruning

Samples no record names any more, after files are deleted or changed, stay
in the store until `filecat samples prune` removes them. It refuses while a
scan is running; see [members.md](members.md#pruning).
