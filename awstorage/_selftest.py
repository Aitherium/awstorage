"""Sweep self-test: each guard is SEEN FIRING, not assumed.

Kept in its own module because `_doctor.py` is generated and a self-test written
there is deleted by the next regeneration (awdelphi lost 125 lines that way).
`awstorage --self-test` / `python -m awstorage --self-test` runs the apply/revert
checks in cli.self_test and then this.

Each check builds a tiny world in a temp dir, runs the real `sweep()`, and fails
loudly if the guard did NOT fire -- a self-test that can only pass is decoration.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ._fs import is_link, remove_tree
from .sweep import sweep


def make_dir_link(link: Path, target: Path) -> str | None:
    """A junction on Windows (no privilege needed), else a symlink. None = cannot."""
    if os.name == "nt" and shutil.which("cmd"):
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                           capture_output=True, timeout=30, check=False)
        if r.returncode == 0 and is_link(link):
            return "junction"
    try:
        os.symlink(str(target), str(link), target_is_directory=True)
        return "symlink"
    except (OSError, NotImplementedError):
        return None


def fake_secret() -> str:
    # Assembled at runtime so no scanner mistakes this file for a leaked key.
    return "sk-" + "ant-" + "selftest" + "Q" * 32


def _mk(p: Path, data: bytes, age_h: float = 0.0) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    if age_h:
        t = time.time() - age_h * 3600
        os.utime(p, (t, t))
    return p


@contextlib.contextmanager
def _held(path: Path, kind: type):
    """Make os.unlink fail on `path` with `kind` (PermissionError = held open by an
    app; OSError = a genuine I/O fault). On Windows PermissionError is a REAL handle
    (CPython opens without FILE_SHARE_DELETE, so unlink hits a sharing violation)."""
    if kind is PermissionError and os.name == "nt":
        with open(path, "rb"):
            yield
        return
    real = os.unlink
    name = path.name

    def unlink(p, *a, **k):
        if os.path.basename(os.fspath(p)) == name:
            if kind is PermissionError:
                raise PermissionError(errno.EACCES, "held open (simulated)", str(p))
            raise OSError(errno.EIO, "I/O error (simulated)", str(p))
        return real(p, *a, **k)
    os.unlink = unlink
    try:
        yield
    finally:
        os.unlink = real


def _policy(root: Path, **over) -> dict:
    rule = {"name": "st", "paths": [str(root).replace("\\", "/") + "/*"],
            "class": "build-temp", "max_idle": "10h", "action": "delete",
            "live_guard": {"window": "2h"}}
    rule.update(over)
    return {"retention": [rule]}


def run() -> int:
    fails: list[str] = []

    def check(ok: bool, what: str) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {what}")
        if not ok:
            fails.append(what)

    with tempfile.TemporaryDirectory() as td:
        td_p = Path(td)
        root, shelf = td_p / "scratch", td_p / "shelf"

        # 1+2. harvest before delete; the secret is withheld and never written.
        item = root / "sess-a"
        _mk(item / "REPORT.md", b"# what the session learned\n", 30)
        _mk(item / "creds.json", ('{"key": "' + fake_secret() + '"}').encode(), 30)
        _mk(item / "big.bin", b"\x00" * 4096, 30)
        rec = sweep(policy=_policy(root), dry_run=False, harvest_to=shelf, seal=False,
                    receipt=td_p / "r1.json")
        copy = next(shelf.rglob("REPORT.md"), None)
        check(rec["exit_code"] == 0 and not item.exists() and copy is not None
              and copy.read_bytes() == b"# what the session learned\n",
              "harvest-before-delete: report copied + verified, then the item removed")
        man = next(shelf.rglob("manifest.json"), None)
        mtext = man.read_text(encoding="utf-8") if man else ""
        check(bool(man) and "withheld: secret-pattern" in mtext
              and fake_secret() not in mtext and next(shelf.rglob("creds.json"), None) is None,
              "secret withheld: listed by name only, never copied, match never written")

        # 3. live guard: a fresh file, and a registered live id.
        _mk(root / "sess-live" / "x.md", b"busy", 0.1)
        _mk(root / "sess-reg" / "x.md", b"old", 30)
        # Save and restore: a self-test must not erase the caller's own live-id list.
        prior = os.environ.get("AWSTORAGE_LIVE_IDS")
        os.environ.update({"AWSTORAGE_LIVE_IDS": "sess-reg"})
        try:
            rec = sweep(policy=_policy(root), dry_run=False, harvest_to=shelf, seal=False)
        finally:
            os.environ.pop("AWSTORAGE_LIVE_IDS", None)
            if prior is not None:
                os.environ.update({"AWSTORAGE_LIVE_IDS": prior})
        live = {Path(p).name for p in rec["skipped_live"]}
        check({"sess-live", "sess-reg"} <= live and (root / "sess-live").exists()
              and (root / "sess-reg").exists(),
              "live guard: fresh item and registered live id both skipped")

        # 4. junction / symlink inside an item: the link goes, its target stays.
        outside = td_p / "precious"
        _mk(outside / "keep.txt", b"not yours")
        jitem = root / "sess-j"
        _mk(jitem / "a.txt", b"old", 30)
        kind = make_dir_link(jitem / "link", outside)
        if kind is None:
            print("  skip junction guard: this host can make neither a junction nor a symlink")
        else:
            os.utime(jitem / "a.txt", (time.time() - 30 * 3600,) * 2)
            rec = sweep(policy=_policy(root), dry_run=False, harvest_to=shelf, seal=False)
            check(not jitem.exists() and (outside / "keep.txt").read_bytes() == b"not yours",
                  f"{kind} not followed: item removed, link target untouched")
            j2 = td_p / "toplink"
            make_dir_link(j2, outside)
            remove_tree(j2)
            check(not os.path.lexists(j2) and (outside / "keep.txt").exists(),
                  f"remove_tree on a top-level {kind}: unlinked, target untouched")

        # 5. emergency: 6h-idle item under a 10h rule is eligible only below the floor.
        _mk(root / "sess-e" / "n.md", b"note", 6)
        rec = sweep(policy=_policy(root), dry_run=True, harvest_to=shelf, seal=False,
                    emergency_free_gb=1, disk_free=lambda _p: 10 * 2**30)
        calm = any(i["path"].endswith("sess-e") for i in rec["items"])
        rec = sweep(policy=_policy(root), dry_run=True, harvest_to=shelf, seal=False,
                    emergency_free_gb=1, disk_free=lambda _p: 0)
        hot = any(i["path"].endswith("sess-e") and i["outcome"] == "dry-run"
                  for i in rec["items"])
        check(not calm and hot and bool(rec["emergency"]),
              "emergency: max_idle halved only when free space is under the floor")

        # 6. receipt on failure: offdrive shelf on the same drive -> kept, exit 1.
        _mk(root / "sess-f" / "r.md", b"x", 30)
        rpath = td_p / "fail.json"
        rec = sweep(policy=_policy(root), dry_run=False, harvest_to=shelf, seal=False,
                    harvest_offdrive=True, receipt=rpath)
        got = json.loads(rpath.read_text(encoding="utf-8")) if rpath.is_file() else {}
        check(got.get("exit_code") == 1 and (root / "sess-f").exists(),
              "receipt on failure: harvest refused -> item kept, receipt exit_code 1")
        rpath2 = td_p / "cnj.json"
        sweep(["no-such-rule"], harvest_to=shelf, receipt=rpath2)
        got = json.loads(rpath2.read_text(encoding="utf-8")) if rpath2.is_file() else {}
        check(got.get("exit_code") == 2 and bool(got.get("could_not_judge")),
              "receipt on could-not-judge: unknown rule -> exit_code 2, receipt written")

        # 7. emergency delete: under the floor a flagged quarantine rule DELETES after a
        #    verified harvest; an unflagged rule still quarantines; a failed harvest
        #    (off-drive refusal) deletes nothing.
        er = td_p / "em"
        _mk(er / "sess-x" / "R.md", b"# x", 30)
        _mk(er / "sess-y" / "R.md", b"# y", 30)
        hot = {"emergency_free_gb": 1, "disk_free": lambda _p: 0}
        qx = {"action": "quarantine", "emergency_delete": True}
        rec = sweep(policy=_policy(er, paths=[str(er / "sess-x").replace("\\", "/")], **qx),
                    dry_run=False, harvest_to=shelf, seal=False, **hot)
        rec2 = sweep(policy=_policy(er, paths=[str(er / "sess-y").replace("\\", "/")],
                                    action="quarantine"),
                     dry_run=False, harvest_to=shelf, seal=False, **hot)
        qroot = er / ".awstorage-quarantine"
        check(rec["emergency_deleted"] == 1 and rec["bytes_freed"] > 0
              and not (er / "sess-x").exists() and rec2["emergency_deleted"] == 0
              and rec2["bytes_quarantined"] > 0 and qroot.is_dir()
              and any(qroot.rglob("sess-y")),
              "emergency delete: flagged rule deletes under the floor; unflagged quarantines")
        _mk(er / "sess-z" / "R.md", b"# z", 30)
        rec = sweep(policy=_policy(er, paths=[str(er / "sess-z").replace("\\", "/")], **qx),
                    dry_run=False, harvest_to=shelf, seal=False, harvest_offdrive=True, **hot)
        check(rec["emergency_deleted"] == 0 and (er / "sess-z" / "R.md").exists(),
              "emergency delete: refused when the harvest did not verify (item kept)")

        # 8. measure cap: an item past the cap is judged by its top mtime + a sample --
        #    all old -> eligible; one fresh sampled file -> live, untouched.
        cr = td_p / "cap"
        _mk(cr / "old" / "d" / "a.bin", b"z", 30)
        _mk(cr / "warm" / "d" / "b.md", b"z", 5)
        for d in (cr / "old" / "d", cr / "old", cr / "warm" / "d", cr / "warm"):
            t = time.time() - 30 * 3600
            os.utime(d, (t, t))
        rec = sweep(policy=_policy(cr), dry_run=True, harvest_to=shelf, seal=False,
                    measure_cap_s=0)
        verdict = {Path(c["path"]).name: c["verdict"] for c in rec["capped"]}
        check(verdict == {"old": "eligible", "warm": "live"},
              "measure cap: capped old item eligible, capped item with a fresh file live")

        # 9. a file held open during an emergency delete is BUSY, not a failure: the
        #    rest is freed, exit 0, receipt `busy`; any other OSError still exits 1.
        br = td_p / "busy"
        _mk(br / "sess-b" / "big.bin", b"\x00" * 8192, 30)
        lock = _mk(br / "sess-b" / "lockfile", b"pid", 30)
        os.utime(br / "sess-b", (time.time() - 30 * 3600,) * 2)
        bpol = _policy(br, action="quarantine", emergency_delete=True)
        with _held(lock, PermissionError):
            rec = sweep(policy=bpol, dry_run=False, harvest_to=shelf, seal=False,
                        emergency_free_gb=1, disk_free=lambda _p: 0)
        b = rec.get("busy") or [{}]
        check(rec["exit_code"] == 0 and b[0].get("outcome") == "partial-busy"
              and rec["bytes_freed"] >= 8192 and rec["items_removed"] == 0
              and lock.exists() and not (br / "sess-b" / "big.bin").exists(),
              "held file in an emergency delete: partial-busy, bytes counted, exit 0")
        with _held(lock, OSError):
            rec = sweep(policy=bpol, dry_run=False, harvest_to=shelf, seal=False,
                        emergency_free_gb=1, disk_free=lambda _p: 0)
        check(rec["exit_code"] == 1 and not rec.get("busy") and lock.exists(),
              "non-permission OSError in an emergency delete: still a failure, exit 1")

    if fails:
        print(f"self-test FAIL: {len(fails)} sweep guard(s) did not fire")
        return 1
    return 0
