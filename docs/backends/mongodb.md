# MongoDB backend: queries

Reference queries for the `files` collection written by `--backend mongodb`
(database from the DSN, default `filecat`). Each document is the catalog record
itself; the fields used here are:

| Field | Meaning |
|---|---|
| `sha256` | full-content hash; only files up to 64 MiB get one (see `hashing.py`) |
| `sha256_partial` | digest of the first and last 1 MiB, for files above 64 MiB |
| `size` | bytes (null when unreadable) |
| `kind` | `dir` for folders, otherwise a file kind |
| `root`, `rel_path` | scan root and path beneath it |

Indexes created by the backend: `(root_id, rel_path)` unique, `sha256` (in a
catalog created by v0.1.3 or later, only over records that have one), `size`,
`kind`, `suffix`, `mime`. There is no index on `sha256_partial`, so the
queries below that group on it read the whole size band.

Run in `mongosh`, or as `db.files.aggregate(pipeline, { allowDiskUse: true })`
from any driver.

## Duplicates of 100 MiB or more

Files above 64 MiB never carry a full `sha256`, so a query on `sha256` returns
nothing at this size. These queries group on `(sha256_partial, size)` instead.
That makes the sets **candidates**: equal size and equal first and last 1 MiB.
It is a strong signal for copies of the same VHD, ISO or archive, but not proof.
Confirm a set by hashing the files in full before deleting anything.

Both queries ignore folders and files under 100 MiB (104,857,600 bytes; use
`100000000` for decimal MB). `wasted_bytes` is `size * (copies - 1)`.

If a set's `paths` list could pass the 16 MB document limit, replace `$push`
with `$firstN: { n: 20, input: { root: "$root", rel_path: "$rel_path" } }`.

### Top 100 by size (most wasted space first)

```js
db.files.aggregate([
  { $match: {
      kind: { $ne: "dir" },
      sha256_partial: { $type: "string", $ne: "" },
      size: { $gte: 104857600 }
  }},
  { $group: {
      _id: { p: "$sha256_partial", s: "$size" },
      size:   { $first: "$size" },
      copies: { $sum: 1 },
      paths:  { $push: { root: "$root", rel_path: "$rel_path" } }
  }},
  { $match: { copies: { $gt: 1 } } },
  { $addFields: { wasted_bytes: { $multiply: ["$size", { $subtract: ["$copies", 1] }] } } },
  { $sort: { wasted_bytes: -1, size: -1 } },
  { $limit: 100 }
], { allowDiskUse: true })
```

### Top 100 by number of copies

```js
db.files.aggregate([
  { $match: {
      kind: { $ne: "dir" },
      sha256_partial: { $type: "string", $ne: "" },
      size: { $gte: 104857600 }
  }},
  { $group: {
      _id: { p: "$sha256_partial", s: "$size" },
      size:   { $first: "$size" },
      copies: { $sum: 1 },
      paths:  { $push: { root: "$root", rel_path: "$rel_path" } }
  }},
  { $match: { copies: { $gt: 1 } } },
  { $addFields: { wasted_bytes: { $multiply: ["$size", { $subtract: ["$copies", 1] }] } } },
  { $sort: { copies: -1, size: -1 } },
  { $limit: 100 }
], { allowDiskUse: true })
```
