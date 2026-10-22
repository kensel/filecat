# Plan: size-capped parts inside each root (JSONL "option 3")

Status: **not started**. The per-root directory layout
(`src/filecat/backends/jsonl_dir.py`) is in place. This plan adds a second
level, splitting one root's documents into size-capped part files. Do it
when a single root's file is large enough that its flush rewrites hurt.

## Why

A JSONL flush (`JsonlBackend._merge`) streams the whole target file into a
temp file and swaps it in. This happens every 2,000 puts or every 5 seconds.
With one file per root, that cost is now proportional to the root being
scanned, not the whole catalog. A single huge share is still one file,
though: `\\nas-vm\Backup-NAS-VM` holds about 240k documents, roughly 800 MB of
JSONL. The cost of a full scan of such a root still grows with the square
of its size.

## Target layout

```
DIR/
  <slug>.<root_id>/                 one folder per root (replaces the single file)
    part-0001.jsonl                 documents, each at most PART_MAX_BYTES (default 256 MiB)
    part-0002.jsonl
    members-0001.jsonl              archive members, capped the same way
    summary.json                    stored aggregates of this root
  programs.jsonl
```

The invariants stay the same: UTF-8, one document per line, and each
`(root_id, rel_path)` appears exactly once across all parts of a root
(spec: "Rescan rewrites so each (root, rel_path) appears once").

## Steps

1. **Part-aware single-root store.** Add `JsonlPartsBackend(root_dir)` in a
   new module, holding an ordered list of part files.
   - **Key index:** a key -> (part number, byte offset) index, built lazily
     by scanning the parts, as `JsonlBackend._ensure_index` does for one
     file. It costs about 100 bytes per key (about 25 MB for 240k keys).
     Optionally persist it as `index.json` with each part's size and mtime,
     and rebuild it when those don't match.
   - **put / flush:** group buffered documents by the part that already
     holds their key, using the index. Keys found nowhere go to the "new"
     group.
   - **Flush rewrites:** stream-merge each touched part, as `_merge` does
     today, but only that part. Append the new group to the last part,
     starting `part-NNNN+1` when the last part would pass `PART_MAX_BYTES`.
     Appending needs no rewrite at all, which is the common case during a
     first scan.
   - **delete:** a delete is a merge of the one part that holds the key.
   - **Compaction (optional):** run it when a part shrinks below about 25%
     of the cap because of deletes. Merge it into its neighbour, or skip
     this for now.

2. **Members.** Apply the same parts treatment to `members-NNNN.jsonl`,
   keyed by archive `(root_id, archive_rel_path)`. An archive's rows must
   stay contiguous in one part, so `put_members` replaces them inside
   whichever part holds them, or appends to the last part.

3. **Hook into `JsonlDirBackend`.** `_part()` returns a
   `JsonlPartsBackend` for roots stored as folders, and keeps
   `JsonlBackend` for roots still stored as a single
   `<slug>.<root_id>.jsonl` file. Widen `_files()` to recognise both forms,
   so both layouts can live in one catalog during the transition.

4. **When to split a root.** Options, in order of simplicity:
   - (a) Always use folders for new roots, and convert existing single
     files with `filecat migrate` (the backend interface already copies
     everything).
   - (b) Convert a root's single file into `part-0001.jsonl` automatically
     the first time it passes `PART_MAX_BYTES` during a flush (rename the
     file, then create the folder).

   Prefer (a) first, then add (b) if mixed catalogs turn out to be common.

5. **Settings.** Add `--jsonl-part-mb` (default 256) and `[jsonl] part_mb`
   in `filecat.toml` (`config.py`: render, show, apply). Report the part
   count in `config test`.

6. **Readers outside filecat.** Document that a root's documents are
   `cat part-*.jsonl`, and that the order across parts is append order.
   PowerShell: `Get-Content part-*.jsonl | ConvertFrom-Json`.

7. **Tests.**
   - Add `jsonl_parts` to `tests/test_backend_contract.py` and
     `tests/test_browse.py` (they already parametrize over backends), with
     a tiny `PART_MAX_BYTES` (e.g. 2 KB) so tests create many parts.
   - Rescan or update a key that lives in an early part: only that part's
     mtime changes. Appending new keys rewrites no existing part.
   - Uniqueness: after random puts, updates and deletes, every key appears
     exactly once across the parts.
   - Persisted index: a stale index (part edited behind its back) is
     detected and rebuilt.
   - Round trips with `filecat migrate` in both directions (single file
     <-> per-root folders <-> parts), as in `tests/test_jsonl_dir.py`.

8. **Docs.** README "Backends" / layout section, the `jsonl_dir.py`
   docstring, and the requirements' backend table.

## Open questions

- Cap parts by size (simple, matches the goal) or by document count
  (easier to reason about)? Size is recommended.
- Should `summary.json` keep its current per-root format? Yes: it is
  already per root.
- Concurrency: two processes writing the same root were never safe in any
  JSONL layout. Keep that as a documented limitation.
