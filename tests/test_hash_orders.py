"""A3: cross-node size-collision hash orders.

One node's `hash_node` buckets sizes per node, so two byte-identical files on two
DIFFERENT nodes are never hashed and `dupes()` (no node filter, confirmed hashes
only) never sees them. Genesis names the unhashed paths whose size collides with a
file on another node (`files.hash_orders`, <= HASH_ORDER_MAX), the node hashes
exactly those (`files.hash_paths` via `node_run.run_hash_orders`) and pushes, and the
fleet's duplicate groups then cover them. Proven end to end against real files.db
indexes: node index -> push -> fleet index -> order -> hash -> push -> dupes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from awstorage import files as F  # noqa: N812
from awstorage.guards import Guards
from awstorage.node_run import apply_orders, run_hash_orders, run_once
from awstorage.remote import push_files

BLOB = os.urandom(200_000)
OTHER = os.urandom(200_000)  # same size as BLOB, different bytes


class _Fleet:
    """Stands in for the gateway: ingests file pushes into a FLEET files.db and answers
    storage_requests with the hash order Genesis would compute from it."""

    def __init__(self, fleet):
        self.fleet, self.calls = fleet, []

    def call_tool(self, name, args):
        self.calls.append(name)
        if name == "storage_ingest_files":
            return F.ingest_push(self.fleet, "platform", args["node_id"],
                                 json.loads(args["body_json"]))
        if name == "storage_requests":
            paths = F.hash_orders(self.fleet, args["node_id"])
            orders = [{"kind": "hash", "node": args["node_id"], "paths": paths}] if paths else []
            return {"node_id": args["node_id"], "orders": orders, "count": len(orders)}
        return {"error": f"unknown tool {name!r}"}


@pytest.fixture()
def two_nodes(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "x.bin").write_bytes(BLOB)
    (a / "small.txt").write_bytes(b"s" * 5000)
    (b / "y.bin").write_bytes(BLOB)       # byte-identical to a/x.bin, on ANOTHER node
    (b / "z.bin").write_bytes(OTHER)      # same size, different bytes
    dbs = {}
    for node, root in (("n1", a), ("n2", b)):
        db = F.open_index(tmp_path / f"{node}.db")
        st = F.scan_files(db, [root], node=node, guards=Guards())
        dbs[node] = (db, tmp_path / f"{node}.db", root)
        assert st["files_seen"] >= 1
    fleet = F.open_index(tmp_path / "fleet.db")
    loop = _Fleet(fleet)
    for node, (db, _p, _r) in dbs.items():
        push_files(loop, db, node)
    yield dbs, fleet, loop
    for db, _p, _r in dbs.values():
        db.close()
    fleet.close()


def test_one_node_hashing_misses_cross_node_dupes(two_nodes):
    dbs, fleet, _loop = two_nodes
    # n1 has one 200k file, so its own size buckets never hash it
    assert F.hash_orders(fleet, "n1") and dbs["n1"][0].execute(
        "SELECT COUNT(sha256) FROM files").fetchone()[0] == 0
    assert F.dupes(fleet, min_bytes=1)["groups"] == []


def test_orders_name_only_cross_node_size_collisions(two_nodes):
    _dbs, fleet, _loop = two_nodes
    n1 = F.hash_orders(fleet, "n1")
    n2 = F.hash_orders(fleet, "n2")
    assert [p.rsplit("/", 1)[-1] for p in n1] == ["x.bin"]  # small.txt has no twin
    assert sorted(p.rsplit("/", 1)[-1] for p in n2) == ["y.bin", "z.bin"]
    assert F.hash_orders(fleet, "nobody") == []


def test_orders_are_capped_and_skip_never_and_hashed(two_nodes, monkeypatch):
    _dbs, fleet, _loop = two_nodes
    monkeypatch.setattr(F, "HASH_ORDER_MAX", 1)
    assert len(F.hash_orders(fleet, "n2", limit=10 ** 9)) == 1
    monkeypatch.undo()
    with fleet:
        fleet.execute("UPDATE files SET never = 1 WHERE node = 'n2' AND path LIKE '%z.bin'")
        fleet.execute("UPDATE files SET sha256 = ? WHERE node = 'n2' AND path LIKE '%y.bin'",
                      ("0" * 64,))
    assert F.hash_orders(fleet, "n2") == []


def test_end_to_end_orders_hash_push_then_dupes_cover_them(two_nodes, monkeypatch):
    dbs, fleet, loop = two_nodes
    for node in ("n1", "n2"):
        _db, path, root = dbs[node]
        monkeypatch.setenv("AWSTORAGE_FILES_DB", str(path))  # the node's own index
        s = run_once(loop, node_id=node, roots=[root], orders_only=True)
        ho = s["hash_orders"]
        assert ho["hashed"] == ho["requested"] >= 1 and ho["pushed"]["written"] >= 1, ho
        assert s["errors"] == []
    g = F.dupes(fleet, min_bytes=1)["groups"]
    assert len(g) == 1 and g[0]["count"] == 2 and g[0]["bytes"] == len(BLOB)
    assert {p["node"] for p in g[0]["paths"]} == {"n1", "n2"}
    # confirmed: nothing left to order, and z.bin is hashed but alone
    assert F.hash_orders(fleet, "n1") == [] and F.hash_orders(fleet, "n2") == []


def test_hash_paths_counts_what_it_did_not_hash(two_nodes, tmp_path):
    dbs, _fleet, _loop = two_nodes
    db, _p, root = dbs["n1"]
    x = F.norm_path(root / "x.bin")
    st = F.hash_paths(db, "n1", [x, x, F.norm_path(tmp_path / "not-indexed.bin")])
    assert (st["requested"], st["hashed"], st["missing"]) == (2, 1, 1)
    again = F.hash_paths(db, "n1", [x])
    assert (again["hashed"], again["already"]) == (0, 1)
    (root / "x.bin").write_bytes(BLOB[:-1] + b"!")  # changed since indexed (size same)
    os.utime(root / "x.bin", ns=(1, 1))
    with db:
        db.execute("UPDATE files SET sha256 = NULL WHERE path = ?", (x,))
    st3 = F.hash_paths(db, "n1", [x])
    assert st3["hashed"] == 0 and st3["skipped"] == 1  # never hashed blind


def test_hash_budget_truncates(two_nodes):
    dbs, _fleet, _loop = two_nodes
    db, _p, root = dbs["n1"]
    st = F.hash_paths(db, "n1", [F.norm_path(root / "x.bin")], budget_bytes=10)
    assert st["truncated"] and st["hashed"] == 0


def test_one_file_over_the_budget_does_not_starve_the_paths_after_it(two_nodes):
    dbs, _fleet, _loop = two_nodes
    db, _p, root = dbs["n1"]
    (root / "a-first.txt").write_bytes(b"a" * 4000)
    (root / "zz-last.txt").write_bytes(b"z" * 4000)     # sorts AFTER the oversized x.bin
    F.scan_files(db, [root], node="n1", guards=Guards())
    with db:
        db.execute("UPDATE files SET sha256 = NULL WHERE node = 'n1'")
    first, big, last = (F.norm_path(root / n) for n in ("a-first.txt", "x.bin", "zz-last.txt"))
    st = F.hash_paths(db, "n1", [first, big, last], budget_bytes=10_000)   # x.bin is 200 kB
    assert st["truncated"] and st["hashed"] == 2, st
    got = dict(db.execute("SELECT path, sha256 FROM files WHERE node = 'n1'").fetchall())
    assert got[first] and got[last] and not got[big]


def test_order_for_another_node_is_never_run(two_nodes):
    dbs, _fleet, loop = two_nodes
    _db, path, root = dbs["n1"]
    st = run_hash_orders(loop, "n1", [{"kind": "hash", "node": "n2",
                                      "paths": [F.norm_path(root / "x.bin")]}], index=path)
    assert st["requested"] == 0 and st["pushed"] is None


def test_apply_orders_never_treats_a_hash_order_as_a_proposal(tmp_path):
    rows = apply_orders([{"kind": "hash", "status": "approved", "action": "delete",
                          "paths": [str(tmp_path)]}], roots=[tmp_path])
    assert rows == [] and tmp_path.exists()
