"""`filecat mongo-rebuild` against a real server ($FILECAT_TEST_MONGODB), in a
database of its own that is dropped afterwards."""
from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit

import pytest

from filecat import cli, mongo_rebuild, rootinfo
from filecat.record import root_id

DSN = os.environ.get("FILECAT_TEST_MONGODB")
pytestmark = pytest.mark.skipif(not DSN, reason="FILECAT_TEST_MONGODB not set")
DB = "filecat_rebuild_test"
SNAPPY = {"wiredTiger": {"configString": "block_compressor=snappy"}}


@pytest.fixture
def old_catalog():
    """A catalog as an older filecat left it: snappy collections, a sha256
    index over every record."""
    import pymongo
    parts = urlsplit(DSN)
    dsn = urlunsplit(parts._replace(path="/" + DB))
    client = pymongo.MongoClient(dsn)
    client.drop_database(DB)
    db = client[DB]
    for name in ("files", "members"):
        db.create_collection(name, storageEngine=SNAPPY)
    root = r"C:\rebuild-root"
    db.files.insert_many([{"root_id": root_id(root), "root": root, "rel_path": f"f{i:03d}.bin",
                           "size": i, "kind": "data", **({"sha256": f"{i:064x}"} if i % 2 else {})}
                          for i in range(250)])
    db.files.create_index([("root_id", 1), ("rel_path", 1)], unique=True)
    db.files.create_index("sha256")
    db.files.create_index("size")
    db.members.insert_many([{"root_id": "r", "archive_rel_path": "a.zip", "index": i, "path": f"m{i}"}
                            for i in range(40)])
    db.members.create_index([("root_id", 1), ("archive_rel_path", 1), ("index", 1)], unique=True)
    yield dsn, db
    client.drop_database(DB)
    client.close()


def test_dry_run_changes_nothing(old_catalog, capsys):
    dsn, db = old_catalog
    assert cli.main(["mongo-rebuild", "--backend", "mongodb", "--dsn", dsn, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "files" in out and "snappy" in out and "rebuild" in out and "dry run" in out
    assert mongo_rebuild.storage(db, "files")["compressor"] == "snappy"


def test_rebuild_in_place(old_catalog, capsys):
    dsn, db = old_catalog
    before = {d["rel_path"]: d for d in db.files.find({}, {"_id": 0})}
    assert cli.main(["mongo-rebuild", "--backend", "mongodb", "--dsn", dsn]) == 0
    for name in ("files", "members", "samples", "member_sets", "set_members"):
        assert mongo_rebuild.storage(db, name)["compressor"] == "zstd", name
    assert {d["rel_path"]: d for d in db.files.find({}, {"_id": 0})} == before
    assert db.members.count_documents({}) == 40
    ix = db.files.index_information()
    assert ix["sha256_1"]["partialFilterExpression"] == {"sha256": {"$type": "string"}}
    assert ix["root_id_1_rel_path_1"]["unique"] and "size_1" in ix
    assert db.members.index_information()["root_id_1_archive_rel_path_1_index_1"]["unique"]
    assert not [n for n in db.list_collection_names() if n.endswith(mongo_rebuild.SUFFIX)]
    # a second run finds nothing to do
    capsys.readouterr()
    assert cli.main(["mongo-rebuild", "--backend", "mongodb", "--dsn", dsn]) == 0
    assert "nothing to rebuild" in capsys.readouterr().out


def test_only_the_index_when_already_zstd(old_catalog):
    dsn, db = old_catalog
    db.files.drop()
    db.create_collection("files", storageEngine=mongo_rebuild.ZSTD)
    db.files.insert_one({"rel_path": "x", "sha256": "0" * 64})
    db.files.create_index("sha256")
    assert [a for n, a, _ in mongo_rebuild.plan(db, ["files"])] == ["index"]
    assert cli.main(["mongo-rebuild", "--backend", "mongodb", "--dsn", dsn, "--collection", "files"]) == 0
    assert db.files.index_information()["sha256_1"]["partialFilterExpression"] == \
        {"sha256": {"$type": "string"}}


def test_refuses_while_a_scan_runs(old_catalog, capsys):
    dsn, db = old_catalog
    root = r"\\nas\share"
    db.roots.insert_one({"root_id": root_id(root), "root": root, "last_attempt": {
        "status": "running", "started_at": rootinfo.now(), "heartbeat_at": rootinfo.now()}})
    assert cli.main(["mongo-rebuild", "--backend", "mongodb", "--dsn", dsn]) == 1
    assert "a scan is running" in capsys.readouterr().err
    assert mongo_rebuild.storage(db, "files")["compressor"] == "snappy"


def test_a_count_mismatch_leaves_the_original(old_catalog, monkeypatch):
    dsn, db = old_catalog
    coll_cls = type(db.files)
    real_count = coll_cls.count_documents

    def count(self, filter, *a, **k):
        """The copy reports one document fewer than the original."""
        n = real_count(self, filter, *a, **k)
        return n - 1 if self.name.endswith(mongo_rebuild.SUFFIX) else n

    monkeypatch.setattr(coll_cls, "count_documents", count)
    assert cli.main(["mongo-rebuild", "--backend", "mongodb", "--dsn", dsn, "--collection", "files"]) == 1
    monkeypatch.undo()
    assert mongo_rebuild.storage(db, "files")["compressor"] == "snappy"
    assert db.files.count_documents({}) == 250
    assert "files__rebuild" not in db.list_collection_names()
