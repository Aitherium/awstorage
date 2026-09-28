"""0.3.1 sweep contract: a file held open is `busy`, never a failure.

Measured on the live 3-hourly sweep (2026-09-28, 0.2.1): an emergency pass freed 35 GB
(C: 9.3 -> 44.6 GB free) and still exited 1, because one Qt lockfile under %TEMP% was
held open by a running app ("emergency delete incomplete: 1 error(s)"). A scheduled job
that exits 1 on every in-use lockfile has a receipt nobody can read. Each case below is
shown both ways: a held file is busy (exit 0), any OTHER OSError is still a failure.
"""

from __future__ import annotations

import contextlib
import errno
import os
import sys
import time
from pathlib import Path

import awstorage
import pytest
from awstorage._fs import is_busy_error, remove_tree, remove_tree_detail
from awstorage.catalog import Catalog
from awstorage.policy import list_quarantine

sw = sys.modules["awstorage.sweep"]


def _mk(p: Path, data: bytes = b"x", age_h: float = 0.0) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    if age_h:
        t = time.time() - age_h * 3600
        os.utime(p, (t, t))
    return p


def _age_dir(p: Path, age_h: float) -> None:
    t = time.time() - age_h * 3600
    os.utime(p, (t, t))


def _pol(root: Path, **over) -> dict:
    r = {"name": "t", "paths": [root.as_posix() + "/*"], "class": "build-temp",
         "max_idle": "10h", "action": "delete", "live_guard": {"window": "2h"}}
    r.update(over)
    return {"retention": [r]}


HOT = {"emergency_free_gb": 1, "disk_free": lambda _p: 0}
EMERGENCY = {"action": "quarantine", "emergency_delete": True}


def _run(root: Path, tmp: Path, **kw) -> dict:
    kw.setdefault("policy", _pol(root))
    kw.setdefault("harvest_to", tmp / "shelf")
    kw.setdefault("seal", False)
    kw.setdefault("dry_run", False)
    return awstorage.sweep(**kw)


@contextlib.contextmanager
def held(path: Path, monkeypatch):
    """Hold `path` open the way a running app does.

    Windows: a real handle from open() -- CPython opens without FILE_SHARE_DELETE, so
    unlink genuinely fails with a sharing violation (winerror 32). Elsewhere an open
    handle never blocks unlink, so os.unlink on that one path raises PermissionError.
    """
    if os.name == "nt":
        f = open(path, "rb")  # noqa: SIM115 -- the point is to hold the handle
        try:
            yield "handle"
        finally:
            f.close()
        return
    real = os.unlink
    name = path.name

    def unlink(p, *a, **k):
        if _is(p, name):
            raise PermissionError(errno.EACCES, "held open", str(p))
        return real(p, *a, **k)
    monkeypatch.setattr(os, "unlink", unlink)
    try:
        yield "simulated"
    finally:
        monkeypatch.setattr(os, "unlink", real)


def _is(p, name: str) -> bool:
    # _fs hands os.unlink the long-path form on Windows; match on the file name.
    return os.path.basename(os.fspath(p)) == name


def _world(root: Path) -> tuple[Path, Path]:
    item = root / "qtsingleapp"
    _mk(item / "big.bin", b"\x00" * 50_000, 30)
    lock = _mk(item / "sub" / "lockfile", b"pid", 30)
    _age_dir(item / "sub", 30)
    _age_dir(item, 30)
    return item, lock


# -- _fs ---------------------------------------------------------------------------

def test_is_busy_error_classifies():
    assert is_busy_error(PermissionError(errno.EACCES, "x"))
    busy32 = OSError(errno.EACCES, "sharing violation")
    busy32.winerror = 32  # type: ignore[attr-defined]
    assert is_busy_error(busy32)
    assert not is_busy_error(OSError(errno.EIO, "io"))
    assert not is_busy_error(FileNotFoundError(errno.ENOENT, "gone"))
    assert not is_busy_error(ValueError("not an OSError"))


def test_remove_tree_detail_splits_busy_from_errors(tmp_path: Path, monkeypatch):
    item, lock = _world(tmp_path)
    with held(lock, monkeypatch):
        removed, errs, busy = remove_tree_detail(item)
    assert errs == [], errs
    assert removed >= 50_000 and lock.exists() and not (item / "big.bin").exists()
    # the lockfile itself, then its dirs left non-empty BECAUSE of it
    assert busy and "lockfile" in busy[0]
    assert any("holds a busy file" in b for b in busy)
    # the compat API still reports it (policy.apply treats any leftover as failed)
    _mk(item / "again.bin", b"y", 30)
    with held(lock, monkeypatch):
        _r, errs2 = remove_tree(item)
    assert errs2 and any("lockfile" in e for e in errs2)


# -- the sweep ---------------------------------------------------------------------

def test_emergency_delete_with_a_held_file_is_partial_busy_exit_0(tmp_path, monkeypatch):
    root = tmp_path / "r"
    item, lock = _world(root)
    cat = Catalog(tmp_path / "c.db")
    with held(lock, monkeypatch):
        rec = _run(root, tmp_path, policy=_pol(root, **EMERGENCY), catalog=cat, **HOT)
    assert rec["exit_code"] == 0, rec["errors"]
    assert rec["errors"] == []
    [b] = rec["busy"]
    assert b["outcome"] == "partial-busy" and b["bytes_freed"] >= 50_000
    assert b["action"] == "deleted-emergency" and "lockfile" in b["first"]
    assert rec["bytes_freed"] >= 50_000 and rec["bytes_emergency_deleted"] >= 50_000
    # a busy item is never counted as removed
    assert rec["items_removed"] == 0 and rec["emergency_deleted"] == 0
    assert rec["skipped_busy"] == []  # something WAS freed; skipped means untouched
    [row] = [i for i in rec["items"] if i["path"].endswith("qtsingleapp")]
    assert row["outcome"] == "partial-busy" and row["bytes_freed"] >= 50_000
    assert lock.exists() and not (item / "big.bin").exists()
    assert "partial-busy" in [r["outcome"] for r in cat.list_ledger()]
    cat.close()
    # next pass, handle released: the rest goes and the item counts as removed
    rec2 = _run(root, tmp_path, policy=_pol(root, **EMERGENCY), **HOT)
    assert rec2["exit_code"] == 0 and rec2["busy"] == [] and not item.exists()
    assert rec2["emergency_deleted"] == 1


def test_emergency_delete_of_only_a_held_file_is_skipped_busy(tmp_path, monkeypatch):
    root = tmp_path / "r"
    item = root / "solo"
    lock = _mk(item / "lockfile", b"pid", 30)
    _age_dir(item, 30)
    with held(lock, monkeypatch):
        rec = _run(root, tmp_path, policy=_pol(root, **EMERGENCY), **HOT)
    assert rec["exit_code"] == 0 and rec["errors"] == []
    [b] = rec["busy"]
    assert b["outcome"] == "skipped-busy" and b["bytes_freed"] == 0
    assert [Path(p).name for p in rec["skipped_busy"]] == ["solo"]
    assert rec["items_removed"] == 0 and rec["bytes_freed"] == 0 and lock.exists()


def test_delete_action_with_a_held_file_is_partial_busy_exit_0(tmp_path, monkeypatch):
    root = tmp_path / "r"
    item, lock = _world(root)
    with held(lock, monkeypatch):
        rec = _run(root, tmp_path)
    assert rec["exit_code"] == 0 and rec["errors"] == []
    [b] = rec["busy"]
    assert b["outcome"] == "partial-busy" and b["action"] == "delete"
    assert rec["bytes_freed"] >= 50_000 and rec["items_removed"] == 0 and lock.exists()


def test_a_non_permission_oserror_still_fails_exit_1(tmp_path, monkeypatch):
    root = tmp_path / "r"
    item, lock = _world(root)
    real = os.unlink

    def broken(p, *a, **k):
        if _is(p, lock.name):
            raise OSError(errno.EIO, "I/O error", str(p))
        return real(p, *a, **k)
    monkeypatch.setattr(os, "unlink", broken)
    rec = _run(root, tmp_path, policy=_pol(root, **EMERGENCY), **HOT)
    monkeypatch.setattr(os, "unlink", real)
    assert rec["exit_code"] == 1 and rec["busy"] == []
    assert any("emergency delete incomplete" in e for e in rec["errors"])
    assert rec["items_removed"] == 0 and rec["emergency_deleted"] == 0


def test_busy_plus_a_real_error_is_still_a_failure(tmp_path, monkeypatch):
    # One held file AND one I/O error in the same item: the I/O error wins (exit 1).
    root = tmp_path / "r"
    _world(root)
    _mk(root / "qtsingleapp" / "bad.bin", b"z", 30)
    real = os.unlink

    def unlink(p, *a, **k):
        if _is(p, "lockfile"):
            raise PermissionError(errno.EACCES, "held open", str(p))
        if _is(p, "bad.bin"):
            raise OSError(errno.EIO, "I/O error", str(p))
        return real(p, *a, **k)
    monkeypatch.setattr(os, "unlink", unlink)
    rec = _run(root, tmp_path, policy=_pol(root, **EMERGENCY), **HOT)
    monkeypatch.setattr(os, "unlink", real)
    assert rec["exit_code"] == 1 and rec["busy"] == [] and rec["items_removed"] == 0


def test_purge_of_a_quarantine_entry_with_a_held_file_is_busy(tmp_path, monkeypatch):
    root = tmp_path / "r"
    item, lock = _world(root)
    pol = _pol(root, action="quarantine", purge_after="1d")
    rec = _run(root, tmp_path, policy=pol)
    assert rec["exit_code"] == 0 and rec["items_removed"] == 1 and not item.exists()
    qlock = next((root / ".awstorage-quarantine").rglob("lockfile"))
    qbin = next((root / ".awstorage-quarantine").rglob("big.bin"))
    [q] = list_quarantine([root])
    old = time.time() - 2 * 86400
    os.utime(q["entry"], (old, old))  # purge age is the entry's mtime
    with held(qlock, monkeypatch):
        rec = _run(root, tmp_path, policy=pol)
    assert rec["exit_code"] == 0 and rec["errors"] == [], rec["errors"]
    assert [p["outcome"] for p in rec["purged"]] == ["partial-busy"]
    assert rec["busy"] and rec["busy"][0]["action"] == "purge"
    assert qlock.exists() and not qbin.exists()


@pytest.mark.skipif(os.name != "nt", reason="a real sharing violation needs Windows")
def test_windows_handle_is_a_genuine_sharing_violation(tmp_path: Path):
    p = _mk(tmp_path / "lockfile", b"pid")
    with open(p, "rb"):
        with pytest.raises(OSError) as ei:
            os.unlink(p)
    assert is_busy_error(ei.value) and getattr(ei.value, "winerror", None) in (5, 32)
