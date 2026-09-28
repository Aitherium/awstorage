"""The file index (awstorage.files): incremental seq-tracked scan, tombstones, dir rollup,
FTS search, dupes with hard-link collapse and actionable bytes, tenancy, the delta push
protocol end to end (node files.db -> ingest -> fleet files.db), row validation and
hostile-input bounds. Every test asserts a number the implementation could get wrong."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from awstorage import files as F
from awstorage.guards import Guards
from awstorage.remote import GatewayError, push_files

BLOB = os.urandom(300_000)  # > 2 * PARTIAL_BYTES, so partial != full


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    r = tmp_path / "root"
    (r / "docs").mkdir(parents=True)
    (r / "media").mkdir()
    (r / "backup").mkdir()
    (r / ".git").mkdir()
    (r / "keys").mkdir()
    (r / "docs" / "Quarterly_Report_2026.pdf").write_bytes(b"%PDF report body" * 400)
    (r / "docs" / "notes.txt").write_bytes(b"plain notes " * 500)
    (r / "media" / "clip.bin").write_bytes(BLOB)
    (r / "backup" / "clip-copy.bin").write_bytes(BLOB)
    mid = bytearray(BLOB)  # same size, head and tail as clip.bin: partial collides
    mid[150_000] ^= 0xFF
    (r / "backup" / "clip-near.bin").write_bytes(bytes(mid))
    (r / "keys" / "id_rsa").write_bytes(b"-----BEGIN KEY-----" * 300)
    (r / ".git" / "HEAD").write_bytes(b"ref: refs/heads/x")
    return r


@pytest.fixture()
def db(tmp_path: Path):
    d = F.open_index(tmp_path / "files.db")
    yield d
    d.close()


def _row(db, path: Path, tenant: str = "platform") -> dict:
    cols = [c[1] for c in db.execute("PRAGMA table_info(files)")]
    r = db.execute("SELECT * FROM files WHERE tenant = ? AND path = ?",
                   (tenant, F.norm_path(path))).fetchone()
    return dict(zip(cols, r)) if r else {}


def _scan(db, root, **k):
    return F.scan_files(db, [root], node=k.pop("node", "n1"), guards=Guards(), **k)


def test_open_index_pragmas_and_schema(tmp_path):
    d = F.open_index(tmp_path / "x" / "files.db")
    try:
        assert d.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # INCREMENTAL
        assert d.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
        pk = [c[1] for c in d.execute("PRAGMA table_info(files)") if c[5]]
        assert pk == ["tenant", "node", "path"]
        for t in ("dirs", "roots", "files_deleted", "dupe_groups"):
            assert "tenant" in [c[1] for c in d.execute(f"PRAGMA table_info({t})")], t
    finally:
        d.close()


def test_scan_indexes_flags_and_skips_git(db, root):
    st = _scan(db, root)
    assert st["files_seen"] == 6 and st["new"] == 6
    assert not _row(db, root / ".git" / "HEAD"), ".git internals must not be indexed"
    r = _row(db, root / "docs" / "Quarterly_Report_2026.pdf")
    assert (r["ext"], r["mime"], r["name"], r["git_root"]) == (
        "pdf", "application/pdf", "Quarterly_Report_2026.pdf", F.norm_path(root))
    assert _row(db, root / "keys" / "id_rsa")["sensitive"] == 1
    assert r["sensitive"] == 0 and isinstance(r["scanned_at"], str) and "T" in r["scanned_at"]


def test_auto_hash_only_candidates_min_bytes_and_confirms(db, root):
    (root / "docs" / "tiny-a").write_bytes(b"x" * 100)
    (root / "docs" / "tiny-b").write_bytes(b"x" * 100)
    _scan(db, root, hash_mode="auto")
    assert _row(db, root / "docs" / "tiny-a")["partial_hash"] is None, "below min_bytes 4096"
    assert _row(db, root / "docs" / "notes.txt")["partial_hash"] is None, "unique size"
    a = _row(db, root / "media" / "clip.bin")
    b = _row(db, root / "backup" / "clip-copy.bin")
    n = _row(db, root / "backup" / "clip-near.bin")
    assert a["partial_hash"] == b["partial_hash"] == n["partial_hash"]
    assert a["sha256"] == b["sha256"] == hashlib.sha256(BLOB).hexdigest()
    assert n["sha256"] and n["sha256"] != a["sha256"]
    assert a["ino"] and a["dev"], "the hash stage records the inode"


def test_rescan_writes_and_rehashes_only_what_changed(db, root):
    _scan(db, root, hash_mode="full")
    seq1 = F.current_seq(db)
    st2 = _scan(db, root, hash_mode="full")
    assert (st2["unchanged"], st2["changed"], st2["full_hashed"], st2["bytes_read"]) == (
        6, 0, 0, 0)
    assert F.current_seq(db) == seq1, "an unchanged rescan must not bump seq"
    p = root / "docs" / "notes.txt"
    p.write_bytes(b"plain notes, edited and longer " * 300)
    os.utime(p, ns=(time.time_ns(), time.time_ns() + 5_000_000_000))
    old_sha = _row(db, root / "media" / "clip.bin")["sha256"]
    st3 = _scan(db, root, hash_mode="full")
    assert (st3["changed"], st3["unchanged"], st3["full_hashed"]) == (1, 5, 1)
    assert _row(db, root / "media" / "clip.bin")["sha256"] == old_sha
    assert _row(db, p)["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()
    assert _row(db, p)["seq"] > seq1 >= _row(db, root / "media" / "clip.bin")["seq"]


def test_changed_file_loses_its_stale_hash(db, root):
    _scan(db, root, hash_mode="full")
    p = root / "media" / "clip.bin"
    p.write_bytes(BLOB[:-1])
    _scan(db, root, hash_mode="none")
    r = _row(db, p)
    assert r["bytes"] == len(BLOB) - 1 and r["sha256"] is None and r["partial_hash"] is None


def test_hash_dropped_when_file_changes_mid_read(db, root, monkeypatch):
    _scan(db, root, hash_mode="none")
    real_stat = os.stat
    calls = {"n": 0}

    def flaky(path, *a, **k):
        st = real_stat(path, *a, **k)
        calls["n"] += 1
        if calls["n"] % 2 == 0:  # the post-read stat sees a different mtime
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
                                   st.st_gid, st.st_size, st.st_atime, st.st_mtime + 1,
                                   st.st_ctime))
        return st
    monkeypatch.setattr(F.os, "stat", flaky)
    F.hash_node(db, "n1", mode="full", workers=1)
    assert db.execute("SELECT COUNT(*) FROM files WHERE sha256 IS NOT NULL").fetchone()[0] == 0


def test_hash_budget_bytes_truncates_and_reports_remaining(db, root):
    st = _scan(db, root, hash_mode="full", hash_budget_bytes=len(BLOB) + 10)
    assert st["hash_truncated"] and st["bytes_read"] <= len(BLOB) + 10
    assert st["bytes_remaining"] > 0


def test_deletions_become_tombstones_but_not_after_truncated_walk(db, root):
    _scan(db, root, hash_mode="none")
    (root / "docs" / "notes.txt").unlink()
    st = _scan(db, root, hash_mode="none", time_budget_s=0)
    assert st["truncated"] and st["removed"] == 0
    assert _row(db, root / "docs" / "notes.txt"), "a truncated walk proves nothing"
    st = _scan(db, root, hash_mode="none")
    assert st["removed"] == 1 and not _row(db, root / "docs" / "notes.txt")
    tomb = db.execute("SELECT path, seq FROM files_deleted").fetchall()
    assert [t[0] for t in tomb] == [F.norm_path(root / "docs" / "notes.txt")]
    assert tomb[0][1] == F.current_seq(db)


def test_prune_is_scoped_to_root_and_node(db, root, tmp_path):
    other = tmp_path / "rootother"  # shares the name prefix "root"
    other.mkdir()
    (other / "keep.txt").write_bytes(b"k")
    F.scan_files(db, [root, other], node="n1", hash_mode="none")
    F.scan_files(db, [root], node="n2", hash_mode="none")
    for f in (root / "docs").iterdir():
        f.unlink()
    F.scan_files(db, [root], node="n1", hash_mode="none")
    assert _row(db, other / "keep.txt"), "sibling root sharing a name prefix was pruned"
    assert db.execute("SELECT COUNT(*) FROM files WHERE node='n2'").fetchone()[0] == 6


def test_dir_rollup_tracks_changes(db, root):
    _scan(db, root, hash_mode="none")
    t = F.tree(db, "n1", str(root), depth=2)
    by = {c["name"]: c for c in t["children"]}
    assert set(by) == {"docs", "media", "backup", "keys"}
    assert by["backup"]["bytes"] == 2 * len(BLOB) and by["backup"]["files"] == 2
    assert t["children"][0]["name"] == "backup", "biggest first"
    assert {c["name"] for c in by["docs"]["children"]} == {"notes.txt",
                                                         "Quarterly_Report_2026.pdf"}
    (root / "backup" / "clip-near.bin").unlink()
    _scan(db, root, hash_mode="none")
    by = {c["name"]: c for c in F.tree(db, "n1", str(root))["children"]}
    assert by["backup"]["bytes"] == len(BLOB) and by["backup"]["files"] == 1
    roots = F.tree(db, "n1")["children"]
    assert roots[0]["kind"] == "root" and roots[0]["files"] == 5


def test_tree_keyset_pagination(db, root):
    _scan(db, root, hash_mode="none")
    seen, cur = [], None
    for _ in range(10):
        t = F.tree(db, "n1", str(root), limit=1, cursor=cur)
        seen += [c["name"] for c in t["children"]]
        cur = t["next_cursor"]
        assert t["truncated"] == bool(cur)
        if not cur:
            break
    assert seen == ["backup", "media", "docs", "keys"]


def test_search_trigram_filters_paginates_and_refuses_short(db, root):
    _scan(db, root, hash_mode="none")
    _scan(db, root, hash_mode="none", node="n2")
    hits = F.search(db, "report quarterly")["items"]
    assert {h["node"] for h in hits} == {"n1", "n2"}
    assert all(h["path"].endswith("Quarterly_Report_2026.pdf") for h in hits)
    if F.fts_tokenizer(db) == "trigram":
        assert F.search(db, "arterl")["items"], "trigram matches inside a word"
    assert F.search(db, "report", nodes="n2")["items"][0]["node"] == "n2"
    assert F.search(db, "report", nodes=[])["items"] == []
    assert len(F.search(db, "", ext="bin", min_bytes=200_000, nodes="n1")["items"]) == 3
    assert F.search(db, "nosuchword")["items"] == []
    assert F.search(db, '"); DROP TABLE files; --')["items"] == []
    with pytest.raises(ValueError):
        F.search(db, "re")
    assert F.search(db, "re", ext="pdf", nodes="n1")["items"]
    seen, cur = [], None
    while True:
        page = F.search(db, "", limit=4, cursor=cur)
        seen += [(i["node"], i["path"]) for i in page["items"]]
        cur = page["next_cursor"]
        if not cur:
            break
    assert len(seen) == 12 == len(set(seen))
    seen, cur = [], None
    while True:  # q set: the cursor is the FTS rowid
        page = F.search(db, "bin", limit=2, cursor=cur)
        seen += [(i["node"], i["path"]) for i in page["items"]]
        cur = page["next_cursor"]
        if not cur:
            break
    assert len(seen) == 6 == len(set(seen))
    with pytest.raises(ValueError):
        F.search(db, "", cursor="not-a-cursor")


def test_search_scan_cap_reports_partial(db, root, monkeypatch):
    _scan(db, root, hash_mode="none")
    monkeypatch.setattr(F, "SEARCH_SCAN_CAP", 1)
    res = F.search(db, "bin", ext="pdf")  # the capped scan sees 1 match, filters it out
    assert res["items"] == [] and res["partial"] and res["next_cursor"]


def test_redaction_for_non_platform(db, root):
    _scan(db, root, hash_mode="none")
    items = F.search(db, "", nodes="n1", redact=True)["items"]
    red = [i for i in items if i.get("redacted")]
    assert len(red) == 1 and red[0]["path"].endswith("/keys/[redacted]")
    assert F.search(db, "id_rsa", redact=True)["items"] == [], "name search must not confirm"
    assert F.search(db, "id_rsa")["items"], "platform sees it"
    kids = F.tree(db, "n1", str(root / "keys"), redact=True)["children"]
    assert [k["name"] for k in kids] == ["[redacted]"]


def test_dupes_collapse_hardlinks_and_count_actionable(db, root):
    link = root / "media" / "clip-hardlink.bin"
    os.link(root / "media" / "clip.bin", link)
    _scan(db, root)
    d = F.dupes(db, min_bytes=1)
    g = [x for x in d["groups"] if x["sha256"] == hashlib.sha256(BLOB).hexdigest()][0]
    assert g["count"] == 2, "a hard link is not a copy"
    assert g["wasted_bytes"] == len(BLOB)
    # every member is inside the root's git tree -> nothing is actionable
    assert g["actionable_bytes"] == 0
    assert d["total_wasted_bytes"] >= len(BLOB)
    assert F.dupes(db, min_bytes=len(BLOB) + 1)["groups"] == []
    assert F.dupes(db, nodes="other")["groups"] == []
    scoped = F.dupes(db, nodes="n1", min_bytes=1)
    assert [x["sha256"] for x in scoped["groups"]] == [x["sha256"] for x in d["groups"]]


def test_actionable_bytes_outside_git(db, tmp_path):
    r = tmp_path / "plain"
    r.mkdir()
    for n in ("a.bin", "b.bin", "c.bin"):
        (r / n).write_bytes(BLOB)
    F.scan_files(db, [r], node="n1", guards=Guards())
    g = F.dupes(db, min_bytes=1)["groups"][0]
    assert (g["count"], g["wasted_bytes"], g["actionable_bytes"]) == (3, 2 * len(BLOB),
                                                                    2 * len(BLOB))
    member = F.dupe_group(db, g["sha256"], limit=2)
    assert len(member["paths"]) == 2 and member["next_cursor"]
    rest = F.dupe_group(db, g["sha256"], limit=2, cursor=member["next_cursor"])
    assert len(rest["paths"]) == 1 and rest["next_cursor"] is None


def test_dupes_never_cross_tenants(db):
    sha = "ab" * 32
    for tenant in ("t1", "t2"):
        F.apply_changes(db, tenant, "n", upserts=[{
            "path": "D:/x/f.bin", "name": "f.bin", "parent": "D:/x", "bytes": 10,
            "mtime_ns": 1, "ext": "bin", "mime": None, "partial_hash": None, "sha256": sha,
            "dev": None, "ino": None, "nlink": None, "git_root": None, "sensitive": 0,
            "never": 0, "seq": 1, "scanned_at": "2026-01-01T00:00:00+00:00"}])
    assert F.dupes(db, tenant="t1", min_bytes=1)["groups"] == []
    assert db.execute("SELECT COUNT(*) FROM dupe_groups").fetchone()[0] == 0


# -- the delta push protocol, end to end --------------------------------------------

class _Loop:
    """Stands in for the gateway: ingests each part into a FLEET files.db."""

    def __init__(self, fleet, tenant="platform"):
        self.fleet, self.tenant, self.calls = fleet, tenant, []

    def call_tool(self, name, args):
        assert name == "storage_ingest_files"
        body = json.loads(args["body_json"])
        assert (body["part"], body["parts"]) == (args["part"], args["parts"])
        self.calls.append(body)
        try:
            return F.ingest_push(self.fleet, self.tenant, args["node_id"], body)
        except F.ResyncRequired as exc:
            return {"detail": {"resync": True, "last_seq": exc.last_seq}}


def test_push_full_then_delta_then_resync(db, root, tmp_path):
    fleet = F.open_index(tmp_path / "fleet.db")
    try:
        _scan(db, root)
        loop = _Loop(fleet)
        r1 = push_files(loop, db, "n1", volumes=[{"mount": "C:/", "total_bytes": 1}])
        assert r1["roots"][0]["resync"] and r1["written"] == 6
        assert fleet.execute("SELECT COUNT(*) FROM files WHERE node='n1'").fetchone()[0] == 6
        assert F.nodes_status(fleet, tenant="platform")[0]["volumes"][0]["mount"] == "C:/"
        # delta: one change + one delete travel; unchanged rows do not
        (root / "docs" / "notes.txt").unlink()
        p = root / "media" / "new.txt"
        p.write_bytes(b"new file")
        _scan(db, root)
        loop.calls.clear()
        r2 = push_files(loop, db, "n1")
        assert not r2["roots"][0]["resync"]
        sent = sum(len(c["upserts"]) for c in loop.calls)
        assert sent == 1 and loop.calls[-1]["deletes"] == [F.norm_path(root / "docs" / "notes.txt")]
        assert not F.search(fleet, "notes")["items"] and F.search(fleet, "new")["items"]
        assert F.changes(fleet, tenant="platform", node="n1", since_seq=0)["deletes"]
        # the fleet lost its state -> 409 -> the pusher resends in full, once
        with fleet:
            fleet.execute("UPDATE file_push_state SET last_seq = 999")
        (root / "media" / "new2.txt").write_bytes(b"x")
        _scan(db, root)
        loop.calls.clear()
        r3 = push_files(loop, db, "n1")
        assert r3["roots"][0]["resync"] and loop.calls[0]["since_seq"] > 0
        assert loop.calls[-1]["since_seq"] == 0
        assert fleet.execute("SELECT COUNT(*) FROM files WHERE node='n1'").fetchone()[0] == 7
    finally:
        fleet.close()


def test_resync_prunes_only_after_every_part(db, root, tmp_path):
    fleet = F.open_index(tmp_path / "fleet.db")
    try:
        _scan(db, root)
        push_files(_Loop(fleet), db, "n1")
        with fleet:  # a ghost row the node no longer has
            F.apply_changes(fleet, "platform", "n1", upserts=[{
                "path": F.norm_path(root / "ghost.txt"), "name": "ghost.txt",
                "parent": F.norm_path(root), "bytes": 1, "mtime_ns": 1, "ext": "txt",
                "mime": None, "partial_hash": None, "sha256": None, "dev": None, "ino": None,
                "nlink": None, "git_root": None, "sensitive": 0, "never": 0, "seq": 1,
                "scanned_at": "x"}])
        parts = list(F.push_parts(db, node="n1", root=F.norm_root(root), since_seq=0,
                                  scan_id="s1", max_rows=2))
        assert len(parts) == 3 and all(p["parts"] == 3 for p in parts)
        for p in parts[:2]:
            r = F.ingest_push(fleet, "platform", "n1", p)
            assert not r["complete"] and r["pruned"] == 0
        assert F.search(fleet, "ghost")["items"], "not pruned before part 3 arrives"
        r = F.ingest_push(fleet, "platform", "n1", parts[2])
        assert r["complete"] and r["pruned"] == 1 and not F.search(fleet, "ghost")["items"]
        # a truncated resync never prunes
        with fleet:
            fleet.execute("UPDATE file_push_state SET last_seq = 0")
        F.apply_changes(fleet, "platform", "n1", upserts=[{
            "path": F.norm_path(root / "ghost2.txt"), "name": "ghost2.txt",
            "parent": F.norm_path(root), "bytes": 1, "mtime_ns": 1, "ext": "txt",
            "mime": None, "partial_hash": None, "sha256": None, "dev": None, "ino": None,
            "nlink": None, "git_root": None, "sensitive": 0, "never": 0, "seq": 1,
            "scanned_at": "x"}])
        for p in F.push_parts(db, node="n1", root=F.norm_root(root), since_seq=0,
                              scan_id="s2", truncated=True):
            r = F.ingest_push(fleet, "platform", "n1", p)
        assert r["complete"] and r["pruned"] == 0 and F.search(fleet, "ghost2")["items"]
    finally:
        fleet.close()


def test_ingest_validates_rows_and_recomputes_flags(db):
    body = {"scan_id": "s", "root": "D:/a", "since_seq": 0, "to_seq": 5, "part": 1,
            "parts": 1, "truncated": True, "upserts": [
                {"path": "D:/a/b.iso", "bytes": 10, "mtime": 1.5, "sha256": "A" * 64,
                 "node": "someone-else", "tenant": "evil", "seq": 3},
                {"path": "D:/a/.ssh/config", "bytes": 1, "mtime_ns": 1, "sensitive": 0},
                {"path": "D:/a/bad", "bytes": -1, "mtime_ns": 1},
                {"path": "D:/a/bad2", "bytes": 1, "mtime_ns": 1, "sha256": "zz"},
                {"path": "D:/a/bad3", "bytes": 1, "mtime_ns": 1, "partial_hash": "a" * 64,
                 "partial_algo": "md5-whatever"},
                {"path": "D:/elsewhere/x", "bytes": 1, "mtime_ns": 1},
                {"path": "D:/a/future", "bytes": 1, "mtime_ns": 1, "seq": 99},
                {"path": "", "bytes": 1, "mtime_ns": 1},
                "not a dict"], "deletes": ["D:/other/x"]}
    res = F.ingest_push(db, "t9", "n9", body)
    assert (res["written"], res["rejected"]) == (2, 8)
    rows = {r[0]: r for r in db.execute("SELECT path, tenant, node, sha256, sensitive,"
                                        " mtime_ns FROM files")}
    assert rows["D:/a/b.iso"][1:4] == ("t9", "n9", "a" * 64)
    assert rows["D:/a/b.iso"][5] == 1_500_000_000
    assert rows["D:/a/.ssh/config"][4] == 1, "the server recomputes sensitive"
    with pytest.raises(F.BadPush):
        F.ingest_push(db, "t9", "n9", {**body, "part": 2, "parts": 1})
    with pytest.raises(F.ResyncRequired):
        F.ingest_push(db, "t9", "n9", {**body, "since_seq": 4, "to_seq": 6, "upserts": []})


def test_hostile_inputs_are_bounded(db, root):
    _scan(db, root)
    with pytest.raises(ValueError):
        F.search(db, "report", newer_days=float("inf"))
    assert F.search(db, "", min_bytes=10 ** 30)["items"] == []
    assert F.dupes(db, min_bytes=10 ** 30)["groups"] == []
    body = {"scan_id": "s", "root": "D:/a", "since_seq": 0, "to_seq": 1, "part": 1,
            "parts": 1, "upserts": [{"path": "D:/a/x", "bytes": 1, "mtime": float("nan")},
                                    {"path": "D:/a/y", "bytes": 2 ** 70, "mtime_ns": 1}]}
    assert F.ingest_push(db, "t", "n", body)["rejected"] == 2
    with pytest.raises(F.BadPush):
        F.ingest_push(db, "t", "n", {**body, "scan_id": "../../etc"})


def test_push_refused_part_and_zero_written_raise(db, root):
    _scan(db, root)

    class Refuser:
        def call_tool(self, name, args):
            return {"detail": "node 'n1' is not in your scope"}

    with pytest.raises(GatewayError, match="not in your scope"):
        push_files(Refuser(), db, "n1")

    class Swallower:
        def call_tool(self, name, args):
            return {"written": 0, "unchanged": 0, "rejected": 6}

    with pytest.raises(GatewayError, match="FAILED push"):
        push_files(Swallower(), db, "n1")


def test_large_prune_runs_maintenance(db, root, monkeypatch):
    _scan(db, root, hash_mode="none")
    called = []
    monkeypatch.setattr(F, "BIG_PRUNE", 0)
    monkeypatch.setattr(F, "maintain", lambda d: called.append(1))
    parts = list(F.push_parts(db, node="n1", root=F.norm_root(root), since_seq=0,
                              scan_id="s1"))
    fleet = db  # same file is fine: a different node id
    for p in parts:
        F.ingest_push(fleet, "platform", "fleetnode", p)
    F.apply_changes(fleet, "platform", "fleetnode", upserts=[{
        "path": F.norm_path(root / "zz.txt"), "name": "zz.txt", "parent": F.norm_path(root),
        "bytes": 1, "mtime_ns": 1, "ext": "txt", "mime": None, "partial_hash": None,
        "sha256": None, "dev": None, "ino": None, "nlink": None, "git_root": None,
        "sensitive": 0, "never": 0, "seq": 1, "scanned_at": "x"}])
    with fleet:
        fleet.execute("UPDATE file_push_state SET last_seq = 0")
    for p in F.push_parts(db, node="n1", root=F.norm_root(root), since_seq=0, scan_id="s2"):
        F.ingest_push(fleet, "platform", "fleetnode", p)
    assert called, "a prune past BIG_PRUNE must optimize FTS + vacuum"


def test_cli_files_roundtrip(tmp_path, root, capsys, monkeypatch):
    from awstorage.cli import main
    monkeypatch.setenv("AWSTORAGE_NODE", "n-cli")
    idx = str(tmp_path / "cli-files.db")
    assert main(["files", "scan", str(root), "--index", idx, "--quiet"]) == 0
    capsys.readouterr()
    assert main(["files", "find", "report", "--index", idx, "--local", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["items"]) == 1 and out["items"][0]["node"] == "n-cli"
    assert out["indexed_roots"] and out["stale"] is False
    assert main(["files", "dupes", "--index", idx, "--local", "--json", "--min-bytes",
                 "1"]) == 0
    assert json.loads(capsys.readouterr().out)["total_wasted_bytes"] == len(BLOB)
    assert main(["files", "tree", str(root), "--index", idx, "--local", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["children"]) == 4
    assert main(["files", "nodes", "--index", idx, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["nodes"][0]["node"] == "n-cli"
    assert main(["files", "scan", str(tmp_path / "nope"), "--index", idx]) == 2
    assert main(["files", "find", "re", "--index", idx, "--local"]) == 2
    assert main(["whoami", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["node"] == "n-cli"
