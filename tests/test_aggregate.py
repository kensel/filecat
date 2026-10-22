"""Unit tests for filecat.aggregate.build_aggregates, independent of any backend."""
from __future__ import annotations

from filecat.aggregate import build_aggregates, dir_key


def test_dir_key_root_level_file_is_dot():
    assert dir_key("readme.txt", depth=2) == "."


def test_dir_key_cut_to_depth():
    assert dir_key("a/b/c/d.txt", depth=2) == "a/b"
    assert dir_key("a/b/c/d.txt", depth=1) == "a"
    assert dir_key("a/d.txt", depth=2) == "a"


def test_build_aggregates_suffix_mime_dir_and_percent():
    root = r"D:\fixture-root"
    docs = [
        {"root": root, "kind": "text", "suffix": "txt", "mime": "text/plain",
         "rel_path": "a.txt", "size": 100, "probe": {"mime_glob_desc": "Plain text"}},
        {"root": root, "kind": "text", "suffix": "txt", "mime": "text/plain",
         "rel_path": "sub/b.txt", "size": 200},
        {"root": root, "kind": "data", "suffix": "bin", "rel_path": "sub/c.bin", "size": 300},
        {"root": root, "kind": "dir", "rel_path": "sub", "size": 0},
    ]
    agg = build_aggregates(docs, depth=2)
    root_agg = agg["roots"][root]

    assert root_agg["total_files"] == 3
    assert root_agg["total_bytes"] == 600
    assert root_agg["unreadable"] == 0

    suffix_by_key = {r["suffix"]: r for r in root_agg["suffix"]}
    assert suffix_by_key["txt"]["files"] == 2
    assert suffix_by_key["txt"]["bytes"] == 300
    assert suffix_by_key["txt"]["description"] == "Plain text"
    assert suffix_by_key["bin"]["bytes"] == 300
    assert abs(suffix_by_key["txt"]["percent"] - 50.0) < 1e-9
    assert abs(suffix_by_key["bin"]["percent"] - 50.0) < 1e-9

    mime_by_key = {r["mime"]: r for r in root_agg["mime"]}
    assert mime_by_key["text/plain"]["bytes"] == 300
    assert mime_by_key["data"]["bytes"] == 300  # no mime -> falls back to kind

    dir_by_key = {r["dir"]: r for r in root_agg["dir"]}
    assert dir_by_key["."]["bytes"] == 100
    assert dir_by_key["sub"]["bytes"] == 500


def test_build_aggregates_link_counts_as_zero_byte_file():
    root = "/mnt/root"
    docs = [{"root": root, "kind": "link", "suffix": "", "rel_path": "shortcut", "size": 0}]
    agg = build_aggregates(docs, depth=2)["roots"][root]
    assert agg["total_files"] == 1
    assert agg["total_bytes"] == 0
    assert agg["suffix"][0]["suffix"] == "(none)"


def test_build_aggregates_unreadable_excludes_errored_entries_without_size():
    root = "/mnt/root"
    docs = [
        {"root": root, "kind": "text", "suffix": "txt", "rel_path": "ok.txt", "size": 50},
        {"root": root, "kind": "unknown", "rel_path": "denied.bin",
         "errors": [{"stage": "stat", "message": "access denied"}]},
    ]
    agg = build_aggregates(docs, depth=2)["roots"][root]
    assert agg["total_files"] == 2
    assert agg["total_bytes"] == 50
    assert agg["unreadable"] == 1
    assert len(agg["suffix"]) == 1  # the unreadable entry isn't grouped
