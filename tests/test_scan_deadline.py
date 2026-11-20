"""Issue #17973: `wake aither-file-index` was killed at 5640 s, 600 s past its own
5040 s scan budget. Three overruns, each pinned here:

* the walk checked its deadline only between directories, while the batch flush that
  runs inside a file's `yield` takes about a minute on a 20M-row index;
* hash_node ran whole-index SQL (a stage's first page, the bytes_remaining sum, each
  root's hashed_pct) with 0 s left;
* roots always ran in the same order, so the root that ate the budget left the same
  later roots with 0 s on every pass.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from awstorage import files as fx
from awstorage.guards import Guards


class _Clock:
    """`time` for files.py with a monotonic() the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def __getattr__(self, name):
        return getattr(time, name)


@pytest.fixture()
def clock(monkeypatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(fx, "time", c)
    return c


def _tree(tmp_path: Path) -> Path:
    r = tmp_path / "root"
    # "a_inner" sorts first, so where scandir is alphabetical it is pushed BEFORE the cut.
    (r / "big" / "a_inner").mkdir(parents=True)
    (r / "top.txt").write_bytes(b"t")
    for i in range(10):
        (r / "big" / f"f{i}.txt").write_bytes(b"x" * (i + 1))
    (r / "big" / "a_inner" / "deep.txt").write_bytes(b"d")
    return r


def test_walk_cuts_mid_directory_and_puts_it_back_whole(tmp_path, clock):
    r = _tree(tmp_path)
    stack: list = [[str(r), None]]
    gen = fx._walk(str(r), set(), clock.now + 100, stack=stack)
    from_big = 0
    with pytest.raises(TimeoutError):
        for item in gen:
            if item is not None and "/big/" in item[0] and "/a_inner/" not in item[0]:
                from_big += 1
                if from_big == 3:
                    clock.now += 1000  # this "flush" ran past the deadline
    assert from_big == 3, "the cut must come right after the slow file, not at dir end"
    # big goes back exactly once and whole; its `a_inner` (pushed while listing big)
    # is dropped so it is not walked twice -- re-listing big finds it again.
    assert [fx.norm_path(p) for p, _g in stack] == [fx.norm_path(r / "big")]


def test_walk_always_finishes_its_first_directory(tmp_path, clock):
    """Progress guarantee: a pass whose deadline is already gone after the first
    file still lists one whole directory, so a resumable walk converges even when a
    single directory is slower than the whole budget."""
    r = tmp_path / "root"
    (r / "sub").mkdir(parents=True)
    for i in range(5):
        (r / f"a{i}.txt").write_bytes(b"a")
    stack: list = [[str(r), None]]
    got = []
    with pytest.raises(TimeoutError):
        for item in fx._walk(str(r), set(), clock.now + 100, stack=stack):
            got.append(item)
            clock.now += 1000
    assert len([g for g in got if g is not None]) == 5
    assert [fx.norm_path(p) for p, _g in stack] == [fx.norm_path(r / "sub")]


def test_walk_cut_does_not_tombstone_or_lose_rows(tmp_path, clock, monkeypatch):
    """Through _walk_into with a flush that 'takes' past the deadline: rows written
    before the cut stay, the walk is truncated, nothing is pruned."""
    monkeypatch.setattr(fx, "TXN_ROWS", 2)
    r = _tree(tmp_path)
    db = fx.open_index(tmp_path / "files.db")
    try:
        real = fx.apply_changes

        def slow(*a, **k):
            out = real(*a, **k)
            clock.now += 400
            return out

        monkeypatch.setattr(fx, "apply_changes", slow)
        st = fx._new_stats("n1", "platform")
        files, _b, _e, truncated, removed = fx._walk_into(
            db, str(r), tenant="platform", node="n1", exclude=set(),
            deadline=clock.now + 500, g=Guards(), skip_dir=None,
            scanned_at=fx.iso_now(), st=st)
        assert truncated and removed == 0
        n = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        total = sum(1 for p in r.rglob("*") if p.is_file())  # every file in _tree
        assert 0 < n == files < total, (n, files, total)
    finally:
        db.close()


def test_hash_node_skips_whole_index_sql_when_too_little_is_left(tmp_path, monkeypatch):
    monkeypatch.setattr(fx._usn, "supported", lambda: False)
    r = tmp_path / "root"
    r.mkdir()
    blob = b"z" * 20_000
    (r / "a.bin").write_bytes(blob)
    (r / "b.bin").write_bytes(blob)
    db = fx.open_index(tmp_path / "files.db")
    try:
        fx.scan_files(db, [r], node="n1", hash_mode="none", guards=Guards())
        st = fx.hash_node(db, "n1", mode="auto", time_budget_s=5, min_left_s=30)
        assert st["hash_truncated"] and st["hash_skipped"] == "budget_left_below_min"
        assert st["partial_hashed"] == st["full_hashed"] == st["bytes_read"] == 0
        # hash_truncated IS the contract: hash work was owed and not done (the CLI
        # reads it). bytes_remaining is NOT measured on a skip -- that SUM is one of
        # the whole-index queries being avoided -- so it keeps its prior value.
        assert st["bytes_remaining"] == 0
        # Without the floor the same call hashes (the default stays unchanged).
        st2 = fx.hash_node(db, "n1", mode="auto", time_budget_s=5)
        assert "hash_skipped" not in st2 and st2["full_hashed"] == 2
    finally:
        db.close()


def test_scan_files_passes_the_hash_floor(tmp_path, monkeypatch):
    monkeypatch.setattr(fx._usn, "supported", lambda: False)
    seen = {}

    def spy(*a, **k):
        seen.update(k)
        return k["stats"]

    monkeypatch.setattr(fx, "hash_node", spy)
    r = tmp_path / "root"
    r.mkdir()
    db = fx.open_index(tmp_path / "files.db")
    try:
        fx.scan_files(db, [r], node="n1", time_budget_s=5040, guards=Guards())
        assert seen["min_left_s"] == fx.HASH_MIN_LEFT_S
        fx.scan_files(db, [r], node="n1", time_budget_s=8, guards=Guards())
        assert seen["min_left_s"] == 4, "a tiny budget keeps half of itself for hashing"
    finally:
        db.close()


def test_roots_rotate_each_pass_per_node(tmp_path, monkeypatch):
    monkeypatch.setattr(fx._usn, "supported", lambda: False)
    roots = []
    for n in ("c", "d", "e"):
        p = tmp_path / n
        p.mkdir()
        (p / "f.txt").write_bytes(b"f")
        roots.append(p)
    db = fx.open_index(tmp_path / "files.db")
    try:
        def order(node="n1"):
            st = fx.scan_files(db, roots, node=node, hash_mode="none", guards=Guards())
            return [Path(x["root"]).name for x in st["roots"]]

        assert order() == ["c", "d", "e"]
        assert order() == ["d", "e", "c"]
        assert order() == ["e", "c", "d"]
        assert order() == ["c", "d", "e"]
        assert order("n2") == ["c", "d", "e"], "the rotation is per node"
        one = fx.scan_files(db, roots[:1], node="n3", hash_mode="none", guards=Guards())
        assert len(one["roots"]) == 1
        assert db.execute("SELECT COUNT(*) FROM meta WHERE k LIKE 'scan_rotation|%|n3'"
                          ).fetchone()[0] == 0, "a single root needs no counter"
    finally:
        db.close()
