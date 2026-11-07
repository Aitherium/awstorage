"""Incremental `files scan` from the NTFS USN change journal (awstorage.usn + the USN
path of files.index_root): the record parser on fixed bytes, every fallback to a full
walk, and the proof that matters -- a rename + delete + modify sequence applied from
journal records yields exactly the rows (and dir rollups) a fresh full walk gives.

The fake volume resolves file reference numbers against the real temp tree (frn =
st_ino), so the equivalence tests run on any OS; the live test drives the real journal
and runs only on Windows NTFS where the journal can be read un-elevated."""

from __future__ import annotations

import os
import shutil
import struct
import sys
import time
from pathlib import Path

import pytest
from awstorage import files as fx
from awstorage import usn as un

# -- fixed byte fixtures (hand-checked against winioctl.h layouts) ------------------
# USN_RECORD_V2: len 72, v2.0, frn 0x0001000000000123, parent 0x0005000000000005,
# usn 0x1000, reason CLOSE|DATA_EXTEND|FILE_CREATE, attrs ARCHIVE, name "a.txt" @60.
V2_HEX = ("48000000020000002301000000000100050000000000050000100000000000000000000000000000"
          "020100800000000000000000200000000a003c0061002e007400780074000000")
# USN_RECORD_V3: len 80, v3.0, frn (0x77 << 64) | 0x42, parent 5, usn 0x1048,
# reason FILE_DELETE, attrs DIRECTORY, name "d" @76.
V3_HEX = ("50000000030000004200000000000000770000000000000005000000000000000000000000000000"
          "481000000000000000000000000000000002000000000000000000001000000002004c0064000000")


def test_parse_v2_record_fixed_bytes():
    (r,) = list(un.parse_records(bytes.fromhex(V2_HEX)))
    assert (r.frn, r.parent_frn, r.usn, r.reason, r.attributes, r.name) == (
        0x0001000000000123, 0x0005000000000005, 0x1000, 0x80000102, 0x20, "a.txt")
    assert not r.is_dir


def test_parse_v3_record_fixed_bytes_and_read_buffer():
    buf = struct.pack("<q", 0x2000) + bytes.fromhex(V2_HEX) + bytes.fromhex(V3_HEX)
    nxt, recs = un.parse_read_buffer(buf)
    assert nxt == 0x2000 and [r.name for r in recs] == ["a.txt", "d"]
    v3 = recs[1]
    assert v3.frn == (0x77 << 64) | 0x42 and v3.parent_frn == 5 and v3.usn == 0x1048
    assert v3.is_dir and v3.reason == un.REASON_FILE_DELETE


def test_parse_stops_at_zero_padding():
    assert len(list(un.parse_records(bytes.fromhex(V2_HEX) + b"\x00" * 16))) == 1


@pytest.mark.parametrize("mutate", [
    lambda b: b[:40],                                         # truncated record
    lambda b: struct.pack("<I", 4096) + b[4:],                # length past the buffer
    lambda b: b[:4] + struct.pack("<H", 4) + b[6:],           # unsupported major version
    lambda b: b[:56] + struct.pack("<HH", 40, 60) + b[60:],   # name span past the record
    lambda b: b[:2],                                          # torn header
])
def test_parse_rejects_malformed_records(mutate):
    with pytest.raises(un.UsnError) as e:
        list(un.parse_records(mutate(bytes.fromhex(V2_HEX))))
    assert e.value.reason == "bad_record"


def test_parse_journal_data_and_read_request_layout():
    raw = struct.pack("<QqqqqQQ", 0xABC, 100, 900, 50, 1 << 40, 1 << 25, 1 << 23) + b"\0" * 8
    j = un.parse_journal_data(raw)
    assert (j.journal_id, j.first_usn, j.next_usn, j.lowest_valid_usn) == (0xABC, 100, 900, 50)
    with pytest.raises(un.UsnError):
        un.parse_journal_data(raw[:20])
    req = un.pack_read_request(900, 0xABC)
    assert len(req) == 44 and struct.unpack("<qIIQQQHH", req) == (
        900, 0xFFFFFFFF, 0, 0, 0, 0xABC, 2, 3)


# -- the fake volume ------------------------------------------------------------------

class FakeVolume:
    """Resolves frn -> current path by scanning the real tree under `top`; serves the
    journal records the test appended."""

    def __init__(self, top: Path, state: dict) -> None:
        self.top, self.state = top, state
        self.volume_name = state.get("volume_name", "fakevol")

    def query(self) -> un.JournalInfo:
        s = self.state
        if s.get("query_error"):
            raise un.UsnError(s["query_error"])
        return un.JournalInfo(s["journal_id"], s["first_usn"], s["next_usn"], 0, 1 << 40)

    def read_until(self, start, end, journal_id):
        if self.state.get("read_error"):
            raise un.UsnError(self.state["read_error"])
        return [r for r in self.state["records"] if start <= r.usn < end]

    def resolve(self, frn):
        if frn in self.state.get("deny", ()):
            return None, un.ERROR_ACCESS_DENIED
        for d, subdirs, names in os.walk(self.top):
            for n in [*subdirs, *names]:
                p = os.path.join(d, n)
                if os.lstat(p).st_ino == frn:
                    return p, 0
        if os.stat(self.top).st_ino == frn:
            return str(self.top), 0
        return None, 87

    def close(self) -> None:
        self.state["closed"] = self.state.get("closed", 0) + 1


class Journal:
    """Records mutations as NTFS would log them (no names: unprivileged reads)."""

    def __init__(self, state: dict) -> None:
        self.state = state

    def log(self, path: Path, reason: int, *, parent: Path | None = None,
            is_dir: bool | None = None, frn: int | None = None) -> None:
        s = self.state
        isd = path.is_dir() if is_dir is None else is_dir
        rec = un.UsnRecord(frn if frn is not None else os.lstat(path).st_ino,
                          os.stat(parent or path.parent).st_ino, s["next_usn"], reason,
                          un.FILE_ATTRIBUTE_DIRECTORY if isd else 0x20, "")
        s["records"].append(rec)
        s["next_usn"] += 96


@pytest.fixture()
def vol(monkeypatch, tmp_path):
    state = {"journal_id": 7, "first_usn": 0, "next_usn": 1000, "records": []}
    monkeypatch.setattr(fx._usn, "supported", lambda: True)
    monkeypatch.setattr(fx, "_usn_volume", lambda root: FakeVolume(tmp_path, state))
    return state


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    r = (tmp_path / "root").resolve()
    for d in ("docs", "media", "backup/deep", "keep", "proj/src"):
        (r / d).mkdir(parents=True)
    (r / ".git").mkdir()
    (r / "docs" / "notes.txt").write_bytes(b"notes " * 100)
    (r / "docs" / "report.pdf").write_bytes(b"%PDF" * 500)
    (r / "media" / "clip.bin").write_bytes(os.urandom(5000))
    (r / "backup" / "a.bin").write_bytes(b"a" * 3000)
    (r / "backup" / "deep" / "b.bin").write_bytes(b"b" * 7000)
    (r / "keep" / "k.txt").write_bytes(b"k" * 10)
    (r / "proj" / "src" / "m.py").write_bytes(b"print(1)")
    return r


def _db(tmp_path: Path, name: str):
    return fx.open_index(tmp_path / name)


def _scan(db, root: Path) -> dict:
    return fx.scan_files(db, [root], node="n1", hash_mode="none")


_ROW = ("path", "name", "parent", "bytes", "mtime_ns", "ext", "mime", "git_root",
        "sensitive", "never")


def _rows(db) -> list[tuple]:
    return db.execute("SELECT " + ", ".join(_ROW) + " FROM files ORDER BY path").fetchall()


def _dirs(db) -> list[tuple]:
    return db.execute("SELECT path, parent, name, bytes, files FROM dirs ORDER BY path"
                      ).fetchall()


def _fresh_walk(tmp_path: Path, root: Path, monkeypatch) -> tuple[list, list]:
    with monkeypatch.context() as m:
        m.setattr(fx._usn, "supported", lambda: False)
        db = _db(tmp_path, "fresh.db")
        st = _scan(db, root)
        assert st["mode"] == "walk"
        out = _rows(db), _dirs(db)
        db.close()
    return out


def _bump_mtime(p: Path) -> None:
    t = time.time_ns() + 7_000_000_000
    os.utime(p, ns=(t, t))


# -- the equivalence proof --------------------------------------------------------------

def test_rename_delete_modify_via_usn_equals_a_full_walk(tmp_path, root, vol, monkeypatch):
    db = _db(tmp_path, "files.db")
    first = _scan(db, root)
    assert first["mode"] == "walk" and first["usn_fallback_reason"] == "no_cursor"
    seq0 = fx.current_seq(db)
    j = Journal(vol)
    # modify
    notes = root / "docs" / "notes.txt"
    notes.write_bytes(b"notes, longer now " * 300)
    _bump_mtime(notes)
    j.log(notes, un.REASON_DATA_EXTEND | un.REASON_CLOSE)
    # create a file
    (root / "docs" / "new.txt").write_bytes(b"new" * 40)
    j.log(root / "docs" / "new.txt", un.REASON_FILE_CREATE | un.REASON_CLOSE)
    # delete a file (the record is written while it still exists)
    clip = root / "media" / "clip.bin"
    j.log(clip, un.REASON_FILE_DELETE | un.REASON_CLOSE)
    clip.unlink()
    # rename a directory INTO a new directory: backup -> archive/backup2
    (root / "archive").mkdir()
    j.log(root / "archive", un.REASON_FILE_CREATE | un.REASON_CLOSE)
    j.log(root / "backup", un.REASON_RENAME_OLD_NAME, parent=root)
    (root / "backup").rename(root / "archive" / "backup2")
    j.log(root / "archive" / "backup2", un.REASON_RENAME_NEW_NAME | un.REASON_CLOSE)
    # a new repository inside docs re-labels its rows
    (root / "docs" / ".git").mkdir()
    j.log(root / "docs" / ".git", un.REASON_FILE_CREATE | un.REASON_CLOSE)
    # ... and one in a directory with no files of its own (only a subtree)
    (root / "proj" / ".git").mkdir()
    j.log(root / "proj" / ".git", un.REASON_FILE_CREATE | un.REASON_CLOSE)

    st = _scan(db, root)
    assert st["mode"] == "usn", st
    r0 = st["roots"][0]
    assert r0["usn_records"] == len(vol["records"]) and r0["usn_unresolved"] == 0
    assert (st["new"], st["changed"], st["removed"]) == (3, 3, 3), st
    # keep/ was never touched: never re-read
    assert st["files_seen"] < 8
    rows, dirs = _rows(db), _dirs(db)
    assert (rows, dirs) == _fresh_walk(tmp_path, root, monkeypatch)
    assert dict((r[0], r[7]) for r in rows)[fx.norm_path(root / "docs" / "new.txt")] == \
        fx.norm_path(root / "docs")
    # the delta push carries exactly the changes
    parts = list(fx.push_parts(db, node="n1", root=fx.norm_root(root), since_seq=seq0,
                               scan_id="s1"))
    ups = {u["path"] for p in parts for u in p["upserts"]}
    dels = {d for p in parts for d in p["deletes"]}
    assert fx.norm_path(notes) in ups and fx.norm_path(clip) in dels
    assert fx.norm_path(root / "backup" / "deep" / "b.bin") in dels
    assert fx.norm_path(root / "archive" / "backup2" / "deep" / "b.bin") in ups
    assert fx.norm_path(root / "keep" / "k.txt") not in ups
    # the cursor advanced: a scan with no new records reads nothing and changes nothing
    again = _scan(db, root)
    assert again["mode"] == "usn" and again["roots"][0]["usn_records"] == 0
    assert (again["new"], again["changed"], again["removed"]) == (0, 0, 0)
    db.close()


def test_removed_repository_relabels_its_tree(tmp_path, root, vol, monkeypatch):
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    j = Journal(vol)
    j.log(root / ".git", un.REASON_FILE_DELETE)
    (root / ".git").rmdir()
    st = _scan(db, root)
    assert st["mode"] == "usn" and st["changed"] == 7, st
    assert (_rows(db), _dirs(db)) == _fresh_walk(tmp_path, root, monkeypatch)
    assert {r[7] for r in _rows(db)} == {None}
    db.close()


def test_whole_subtree_deleted_frns_proven_by_delete_records(tmp_path, root, vol,
                                                             monkeypatch):
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    j = Journal(vol)
    deep, backup = root / "backup" / "deep", root / "backup"
    j.log(deep / "b.bin", un.REASON_FILE_DELETE)
    j.log(deep, un.REASON_FILE_DELETE)
    j.log(backup / "a.bin", un.REASON_FILE_DELETE)
    j.log(backup, un.REASON_FILE_DELETE)
    shutil.rmtree(backup)
    st = _scan(db, root)
    assert st["mode"] == "usn" and st["roots"][0]["usn_unresolved"] == 0
    assert st["removed"] == 2
    assert (_rows(db), _dirs(db)) == _fresh_walk(tmp_path, root, monkeypatch)
    db.close()


# -- every fallback is a walk, with the reason in the JSON --------------------------------

def _walk_then(tmp_path, root, vol, **change) -> dict:
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    vol.update(change)
    (root / "keep" / "k.txt").write_bytes(b"changed")      # NOT journaled: walk must see it
    _bump_mtime(root / "keep" / "k.txt")
    st = _scan(db, root)
    db.close()
    return st


@pytest.mark.parametrize("change, reason", [
    ({"journal_id": 8}, "journal_id_changed"),
    ({"first_usn": 5000, "next_usn": 9000}, "journal_wrapped"),
    ({"read_error": "journal_wrapped"}, "journal_wrapped"),
    ({"query_error": "access_denied"}, "access_denied"),
    ({"volume_name": "othervol"}, "volume_changed"),
    ({"next_usn": 10}, "cursor_ahead"),
])
def test_fallbacks_walk_and_report(tmp_path, root, vol, change, reason):
    st = _walk_then(tmp_path, root, vol, **change)
    assert st["mode"] == "walk" and st["usn_fallback_reason"] == reason
    assert st["roots"][0]["usn_fallback_reason"] == reason
    assert st["changed"] == 1, "the walk found the change the journal did not report"


def test_access_denied_opening_the_volume_walks(tmp_path, root, monkeypatch):
    monkeypatch.setattr(fx._usn, "supported", lambda: True)

    def denied(_root):
        raise un.UsnError("access_denied", "CreateFileW failed (winerror 5)", 5)
    monkeypatch.setattr(fx, "_usn_volume", denied)
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    st = _scan(db, root)
    assert st["mode"] == "walk" and st["usn_fallback_reason"] == "access_denied"
    assert fx._usn_load(db, "platform", "n1", fx.norm_root(root)) is None
    db.close()


def test_unexpected_error_in_fast_path_walks(tmp_path, root, vol, monkeypatch):
    db = _db(tmp_path, "files.db")
    _scan(db, root)

    def boom(*a, **k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(fx, "_usn_apply", boom)
    st = _scan(db, root)
    assert st["mode"] == "walk" and "kaboom" in st["usn_fallback_reason"]
    db.close()


def test_config_change_walks(tmp_path, root, vol):
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    st = fx.scan_files(db, [root], node="n1", hash_mode="none",
                      exclude_dirs=set(fx.DEFAULT_EXCLUDE_DIRS) | {"keep"})
    assert st["mode"] == "walk" and st["usn_fallback_reason"] == "config_changed"
    db.close()


def test_unresolvable_record_marks_root_for_a_full_walk(tmp_path, root, vol):
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    vol["records"].append(un.UsnRecord(999_999_999, 888_888_888, vol["next_usn"],
                                      un.REASON_DATA_EXTEND, 0x20, ""))
    vol["next_usn"] += 96
    st = _scan(db, root)
    r0 = st["roots"][0]
    assert st["mode"] == "usn" and r0["usn_unresolved"] == 1 and r0["usn_walk_next"] is True
    nxt = _scan(db, root)
    assert nxt["mode"] == "walk" and nxt["usn_fallback_reason"] == "marked_for_walk"
    after = _scan(db, root)
    assert after["mode"] == "usn", "the walk re-armed the cursor"
    db.close()


def test_denied_directory_is_counted_not_silent(tmp_path, root, vol):
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    secret = root / "keep"
    vol["deny"] = {os.stat(secret).st_ino}
    Journal(vol).log(secret / "k.txt", un.REASON_DATA_OVERWRITE)
    st = _scan(db, root)
    assert st["mode"] == "usn" and st["roots"][0]["usn_denied"] == 1
    db.close()


def test_truncated_usn_pass_keeps_the_cursor(tmp_path, root, vol):
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    before = fx._usn_load(db, "platform", "n1", fx.norm_root(root))
    Journal(vol).log(root / "docs" / "notes.txt", un.REASON_DATA_OVERWRITE)
    st = fx.scan_files(db, [root], node="n1", hash_mode="none", time_budget_s=0)
    assert st["mode"] == "usn" and st["truncated"] is True
    assert fx._usn_load(db, "platform", "n1", fx.norm_root(root)) == before
    db.close()


def test_not_windows_reports_walk(tmp_path, root, monkeypatch):
    monkeypatch.setattr(fx._usn, "supported", lambda: False)
    db = _db(tmp_path, "files.db")
    _scan(db, root)
    st = _scan(db, root)
    assert st["mode"] == "walk" and st["usn_fallback_reason"] == "not_windows"
    assert db.execute("SELECT COUNT(*) FROM meta WHERE k LIKE 'usn|%'").fetchone()[0] == 0
    db.close()


# -- live: the real journal ---------------------------------------------------------------

def _live_journal() -> bool:
    """Windows NTFS temp dir whose USN journal this user can query?"""
    if sys.platform != "win32":
        return False
    import tempfile
    try:
        v = un.Volume(tempfile.gettempdir())
        try:
            v.query()
        finally:
            v.close()
    except un.UsnError:
        return False
    return True


@pytest.mark.skipif(not _live_journal(), reason="needs Windows NTFS with a readable USN journal")
def test_live_journal_matches_a_full_walk(tmp_path, root, monkeypatch):
    outside = (tmp_path / "outside").resolve()
    (outside / "inner").mkdir(parents=True)
    (outside / "inner" / "x.bin").write_bytes(b"x" * 999)
    db = _db(tmp_path, "files.db")
    first = _scan(db, root)
    assert first["mode"] == "walk"
    (root / "docs" / "notes.txt").write_bytes(b"live edit " * 77)
    _bump_mtime(root / "docs" / "notes.txt")
    (root / "media" / "clip.bin").unlink()
    (root / "backup").rename(root / "renamed")
    (outside / "inner").rename(root / "keep" / "moved_in")
    (root / "fresh" / "sub").mkdir(parents=True)
    (root / "fresh" / "sub" / "f.txt").write_bytes(b"f" * 12)
    st = _scan(db, root)
    assert st["mode"] == "usn", st
    assert st["roots"][0]["usn_unresolved"] == 0, st
    assert (_rows(db), _dirs(db)) == _fresh_walk(tmp_path, root, monkeypatch)
    db.close()
