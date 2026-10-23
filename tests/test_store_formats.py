"""data/store_formats.json describes every backup and database format the
code recognises, and nothing else."""
from __future__ import annotations

import importlib
import json

from filecat import backup, dbfiles


def _code_formats():
    out = {}
    for fmt in backup.formats():
        out[fmt.name] = ("backup", fmt)
    for eng in dbfiles.engines():
        out[eng.name] = ("database", eng)
    return out


def test_catalog_and_code_list_the_same_formats():
    assert set(dbfiles.catalog()) == set(_code_formats())


def test_catalog_entries_match_the_code():
    for name, (category, fmt) in _code_formats().items():
        entry = dbfiles.catalog()[name]
        assert entry["category"] == category, name
        assert importlib.import_module(entry["module"]).__name__ == type(fmt).__module__, name
        store = backup.Store(fmt, "")
        assert entry["summary_key"] == store.probe_key, name
        assert entry["data_tag"] == store.data_key, name
        for key in ("name", "detection", "listed_only", "measured_normally", "actions", "notes", "rollup_children"):
            assert key in entry, (name, key)
        default = "virtual" if store.virtual else "list"
        assert entry["actions"]["default"] == default, name


def test_database_thresholds_come_from_the_catalog():
    by = {e.name: e for e in dbfiles.engines()}
    assert (by["postgres"].quiet_seconds, by["postgres"].min_bytes) == (90 * 86400, 1024 * 1024)
    assert (by["mssql"].quiet_seconds, by["mssql"].min_bytes) == (3600, 0)
    for eng in by.values():
        when = dbfiles.catalog()[eng.name]["actions"]
        assert when["measure_flag"] == "--measure-databases"


def test_catalog_is_plain_json_with_unique_ids():
    with open(dbfiles.CATALOG_PATH, encoding="utf-8") as f:
        raw = json.load(f)
    ids = [f["id"] for f in raw["formats"]] + [p["id"] for p in raw["planned"]]
    assert len(ids) == len(set(ids))


def _raw():
    with open(dbfiles.CATALOG_PATH, encoding="utf-8") as f:
        return json.load(f)


def test_archive_ids_are_unique_across_the_catalog():
    raw = _raw()
    ids = [e["id"] for key in ("formats", "planned", "archives", "archives_identified_only") for e in raw[key]]
    assert len(ids) == len(set(ids))


def test_implemented_archives_name_real_code():
    for entry in _raw()["archives"]:
        module = importlib.import_module(entry["module"])
        assert callable(getattr(module, entry["function"])), entry["id"]
        for key in ("spec", "magic", "reads", "globs", "dispatch"):
            assert entry[key], (entry["id"], key)


def test_identified_only_archives_use_freedesktop_types():
    import xml.etree.ElementTree as ET
    from importlib import resources
    xml = resources.files("filecat.data").joinpath("freedesktop.org.xml")
    with xml.open("rb") as f:
        known = {m.get("type") for m in ET.parse(f).getroot()}
    for entry in _raw()["archives_identified_only"]:
        assert entry["mime"] in known, entry["id"]


def test_rollup_children_are_the_folders_the_code_lists_only():
    """The bulk folders of a store (docs/rollups.md section 4.1) are exactly
    folders whose files the format records from the listing; only folders, and
    only formats with a bulk pool have any."""
    by = {n: e["rollup_children"] for n, e in dbfiles.catalog().items()}
    assert by["synology-hyperbackup"] == ["Pool"] and by["synology-abb"] == ["@data"]
    assert by["postgres"] == ["base", "pg_wal", "pg_xact", "pg_multixact", "global"]
    assert by["mysql"] == ["*"] and by["mongodb"] == ["journal", "diagnostic.data", "_tmp"]
    for name in ("mssql", "veeam", "duplicity", "windows-backup", "windows-image-backup", "synology-abg",
                 "thunderbird-ietng", "synology-abb-view"):
        assert by[name] == [], name
    for name, (category, fmt) in _code_formats().items():
        store = backup.Store(fmt, "")
        assert list(store.rollup_patterns) == by[name], name
        for child in by[name]:
            if "*" not in child:
                assert fmt.opaque(f"{child}/file"), (name, child)


def test_store_children_are_folders_only_and_match_by_pattern():
    class Entry:
        def __init__(self, name, is_dir):
            self.name, self._dir = name, is_dir

        def is_dir(self, follow_symlinks=True):
            return self._dir

        def is_symlink(self):
            return False

    mysql = backup.Store(dbfiles.engine("mysql"), "")
    names = [e.name for e in mysql.rollup_children(
        [Entry("sales", True), Entry("ibdata1", False), Entry("#innodb_redo", True), Entry("mysql", True)])]
    assert names == ["sales", "#innodb_redo", "mysql"]
    hb = backup.Store(next(f for f in backup.formats() if f.name == "synology-hyperbackup"), "")
    assert [e.name for e in hb.rollup_children([Entry("Pool", True), Entry("Config", True), Entry("Pool", False)])]         == ["Pool"]
    assert hb.tag == "[BACKUP]" and mysql.tag == "[DATABASE]"
