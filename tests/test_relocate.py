"""awstorage.relocate: the floor-simulating planner and the executor.

Every test runs in tmp dirs with an injected robocopy (a fake that moves bytes with
shutil) and a filesystem whose drive letters are MAPPED onto tmp subdirectories -- no
real drive, robocopy, mklink or junction outside tmp is ever touched. The one test that
creates a real junction does so inside tmp_path, Windows only.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
from awstorage import relocate as rl
from awstorage.catalog import Catalog
from awstorage.cli import main as cli_main

GIB = rl.GIB
FLOORS = {"C:": 40.0, "D:": 50.0, "E:": 30.0, "default": 30.0}
NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)


class MappedFS(rl.HostFS):
    """Drive letters mapped onto tmp dirs; junctions recorded, never created."""

    def __init__(self, tmp: Path, *, real_links: bool = False) -> None:
        self.roots = {str(tmp / "C"): "C:", str(tmp / "D"): "D:", str(tmp / "E"): "E:"}
        self.reparse: set = set()
        self.big: dict = {}
        self.alloc: dict = {}
        self.aliases: dict = {}
        self.links: dict = {}
        self.real_links = real_links

    def drive_of(self, path: str):
        p = os.path.abspath(path)
        for root, d in self.roots.items():
            if p == root or p.startswith(root + os.sep):
                return d
        return None

    def exists(self, path: str) -> bool:
        return path in self.links or super().exists(self.canon(path))

    def is_reparse(self, path: str) -> bool:
        if self.real_links:
            return super().is_reparse(path)
        return path in self.reparse or path in self.links

    def canon(self, path: str) -> str:
        p = os.path.abspath(path)
        for alias, real in self.aliases.items():  # a fake 8.3 name / junction parent
            if p == alias or p.startswith(alias + os.sep):
                return real + p[len(alias):]
        return self.links.get(p) or super().canon(p)

    def stats(self, path: str, max_files: int = rl.MAX_FILES, **kw):
        st = super().stats(path, max_files, **kw)
        if path in self.big and st["files"]:
            st["bytes"] = st["alloc_bytes"] = self.big[path]
        if path in self.alloc and st["files"]:
            st["alloc_bytes"] = self.alloc[path]
        return st

    def make_junction(self, link, target, runner=None):
        if self.real_links:
            return super().make_junction(link, target, runner)
        self.links[link] = target

    def remove_junction(self, link):
        if self.real_links:
            return super().remove_junction(link)
        self.links.pop(link, None)


class FakeRobocopy:
    """robocopy <src> <dst> /E /MOVE ...: move every file, drop the source tree.
    `leave_one` leaves one file behind on the first call (a verification mismatch).
    With /XO /XN /XC (the rollback) a file that already exists at <dst> is skipped and
    stays at <src>, as real robocopy does."""

    def __init__(self, leave_one: bool = False, rc: int = 1) -> None:
        self.calls: list = []
        self.leave_one = leave_one
        self.rc = rc

    def __call__(self, argv):
        self.calls.append(list(argv))
        assert argv[0] == "robocopy" and "/MOVE" in argv and "/MT:16" in argv
        src, dst = Path(argv[1]), Path(argv[2])
        if self.rc >= 8:
            return self.rc, "ERROR 112 (0x00000070) There is not enough space on the disk."
        skip = self.leave_one and len(self.calls) == 1
        files = sorted(p for p in src.rglob("*") if p.is_file())
        keep = "/XO" in argv and "/XN" in argv and "/XC" in argv
        for i, f in enumerate(files):
            if skip and i == 0:
                continue
            out = dst / f.relative_to(src)
            if keep and out.exists():
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(f), str(out))
        if not any(p.is_file() for p in src.rglob("*")):
            shutil.rmtree(src)
        return self.rc, "moved"


def _tree(root: Path, n: int = 3, age_days: float = 30.0) -> Path:
    (root / "sub").mkdir(parents=True)
    old = NOW.timestamp() - age_days * 86400
    for i in range(n):
        f = (root / "sub" if i % 2 else root) / f"f{i}.bin"
        f.write_bytes(bytes([i]) * (100 + i))
        os.utime(f, (old, old))
    return root


def _free(table: dict):
    return lambda d: int(table[d] * GIB)


def _plan(tmp: Path, fs: MappedFS, free: dict, **kw):
    return rl.plan_relocation(
        [str(tmp / "D" / "cache" / "models")], "C:", FLOORS, _free(free), NOW, fs=fs,
        dest_root=str(tmp / "C"), handles_fn=lambda p: 0, mounts=[], **kw)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    base = tmp_path / "relocate"
    monkeypatch.setenv("AWSTORAGE_RELOCATE_DIR", str(base))
    (tmp_path / "C").mkdir()
    src = _tree(tmp_path / "D" / "cache" / "models")
    fs = MappedFS(tmp_path)
    return {"tmp": tmp_path, "base": base, "src": src, "fs": fs,
            "catalog": tmp_path / "catalog.db", "events": []}


def _apply(env, plan, runner, free, **kw):
    kw.setdefault("notify", lambda ev: env["events"].append(ev) or
                  [{"channel": "test", "ok": True, "reason": None}])
    kw.setdefault("handles_fn", lambda p: 0)  # the real psutil probe walks every process
    return rl.apply_plan(plan, runner, env["fs"], NOW, base=env["base"],
                         free_space_fn=_free(free), floors=FLOORS,
                         catalog=env["catalog"], node="testnode", **kw)


# ── planner ───────────────────────────────────────────────────────────────────

def test_planner_refuses_the_2026_09_28_floor_crossing(env):
    """C: 124 GB free, 88 GB incoming (+2%), floor 40 -> 34.2 GB: refused."""
    env["fs"].big[str(env["src"])] = 88 * GIB
    plan = _plan(env["tmp"], env["fs"], {"C:": 124, "D:": 400})
    assert plan["ok"] is False
    c = plan["projection"]["C:"]
    assert c["ok"] is False and c["floor_gb"] == 40.0 and c["free_before_gb"] == 124.0
    assert abs(c["free_after_gb"] - (124 - 88 * 1.02)) < 0.01
    assert plan["projection"]["D:"]["ok"] is True
    assert plan["projection"]["D:"]["free_after_gb"] == 488.0
    assert any("C:" in r and "floor" in r for r in plan["refusals"])
    rl.save_plan(plan, env["base"])
    with pytest.raises(rl.RelocateRefusedError):
        rl.approve_plan(plan["plan_id"], approved_by="owner", via="test", base=env["base"])
    assert not (env["base"] / "approved").exists()


def test_planner_accepts_a_safe_plan_with_the_contract_shape(env):
    env["fs"].big[str(env["src"])] = 88 * GIB
    plan = _plan(env["tmp"], env["fs"], {"C:": 300, "D:": 400})
    assert plan["ok"] is True and plan["refusals"] == []
    assert set(plan) == {"plan_id", "created_at", "moves", "projection", "ok", "refusals"}
    m = plan["moves"][0]
    assert set(m) == {"id", "source", "dest", "bytes", "files", "newest_mtime",
                      "evidence", "link"}
    assert m["bytes"] == 88 * GIB and m["files"] == 3 and m["link"] == "junction"
    assert m["dest"].startswith(str(env["tmp"] / "C")) and m["dest"].endswith("models")
    assert m["evidence"] == {"cold_days": 30, "open_handles": 0, "container_mounted": False}
    assert plan["projection"]["C:"]["ok"] and plan["projection"]["C:"]["free_after_gb"] > 40
    json.dumps(plan)  # serialisable as-is


def test_planner_refuses_hot_data(env):
    hot = env["src"] / "fresh.bin"
    hot.write_bytes(b"x" * 10)  # mtime = now
    plan = rl.plan_relocation([str(env["src"])], "C:", FLOORS, _free({"C:": 300, "D:": 400}),
                              fs=env["fs"], dest_root=str(env["tmp"] / "C"),
                              handles_fn=None)
    assert not plan["ok"]
    assert any("HOT" in r for r in plan["refusals"])
    assert plan["moves"][0]["evidence"]["open_handles"] is None


def test_planner_refuses_a_reparse_point_source(env):
    env["fs"].reparse.add(str(env["src"]))
    plan = _plan(env["tmp"], env["fs"], {"C:": 300, "D:": 400})
    assert not plan["ok"]
    assert any("reparse point" in r for r in plan["refusals"])


def test_planner_refuses_existing_dest_do_not_move_mounts_and_handles(env):
    dest = Path(rl._dest_for(str(env["src"]), "C:", str(env["tmp"] / "C")))
    dest.mkdir(parents=True)
    topo = {"relocate_do_not_move": [str(env["tmp"] / "D" / "cache")]}
    plan = rl.plan_relocation([str(env["src"])], "C:", FLOORS, _free({"C:": 300, "D:": 400}),
                              NOW, fs=env["fs"], dest_root=str(env["tmp"] / "C"),
                              topology=topo, handles_fn=lambda p: 2)
    text = " | ".join(plan["refusals"])
    assert "already exists" in text and "do-not-move" in text
    # A protected tree is refused without being walked.
    assert plan["moves"][0]["files"] == 0 and "open file handle" not in text
    shutil.rmtree(dest)
    plan = rl.plan_relocation([str(env["src"])], "C:", FLOORS, _free({"C:": 300, "D:": 400}),
                              NOW, fs=env["fs"], dest_root=str(env["tmp"] / "C"),
                              mounts=[str(env["src"] / "sub")], handles_fn=lambda p: 2)
    text = " | ".join(plan["refusals"])
    assert "bind-mounted" in text and "open file handle" in text
    assert plan["moves"][0]["evidence"]["container_mounted"] is True


def test_planner_refuses_same_drive_and_unreadable_free_space(env):
    def boom(_d):
        raise OSError("no such drive")

    plan = rl.plan_relocation([str(env["src"])], "D:", FLOORS, boom, NOW, fs=env["fs"],
                              dest_root=str(env["tmp"] / "D2"), handles_fn=None)
    text = " | ".join(plan["refusals"])
    assert "already on D:" in text and "cannot read free space" in text


# ── apply ─────────────────────────────────────────────────────────────────────

def _approved(env, free):
    plan = _plan(env["tmp"], env["fs"], free)
    assert plan["ok"], plan["refusals"]
    rl.save_plan(plan, env["base"])
    rl.approve_plan(plan["plan_id"], approved_by="owner", via="test", base=env["base"],
                    fs=env["fs"])
    return plan


def test_apply_with_fake_runner_verifies_and_links(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert r["exit_code"] == 0 and r["outcome"] == "applied", r
    mv = r["moves"][0]
    dest = Path(plan["moves"][0]["dest"])
    assert mv["verified"] == {"source_files_left": 0, "dest_files": 3,
                              "dest_bytes": 100 + 101 + 102}
    assert sorted(p.name for p in dest.rglob("*.bin")) == ["f0.bin", "f1.bin", "f2.bin"]
    assert env["fs"].links == {str(env["src"]): str(dest)} and mv["linked"]
    assert len(runner.calls) == 1
    saved = rl.load_result(plan["plan_id"], env["base"])
    assert saved["outcome"] == "applied"
    cat = Catalog(str(env["catalog"]))
    rows = [x for x in cat.list_ledger() if x["action"] == "relocate"]
    cat.close()
    assert len(rows) == 1 and rows[0]["outcome"] == "applied"
    assert json.loads(rows[0]["detail"])["plan_id"] == plan["plan_id"]
    assert [e["outcome"] for e in env["events"]] == ["applied"]
    # Re-running is a no-op, not a second move.
    again = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert again["exit_code"] == 0 and len(runner.calls) == 1


def test_apply_rolls_back_on_verification_mismatch(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    runner = FakeRobocopy(leave_one=True)
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert r["exit_code"] == 1 and r["outcome"] == "failed"
    mv = r["moves"][0]
    assert mv["outcome"] == "rolled-back" and mv["rolled_back"] is True
    assert "verification failed" in mv["reason"]
    assert len(runner.calls) == 2 and runner.calls[1][1] == plan["moves"][0]["dest"]
    assert sorted(p.name for p in env["src"].rglob("*.bin")) == ["f0.bin", "f1.bin", "f2.bin"]
    assert not Path(plan["moves"][0]["dest"]).exists()
    assert env["fs"].links == {}
    assert [e["outcome"] for e in env["events"]] == ["rolled-back"]


def test_apply_rolls_back_on_robocopy_failure(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    r = _apply(env, plan, FakeRobocopy(rc=16), {"C:": 300, "D:": 400})
    assert r["moves"][0]["outcome"] == "rolled-back" and "robocopy exited 16" in \
        r["moves"][0]["reason"]
    assert len(list(env["src"].rglob("*.bin"))) == 3


def test_apply_refuses_unapproved(env):
    plan = _plan(env["tmp"], env["fs"], {"C:": 300, "D:": 400})
    rl.save_plan(plan, env["base"])
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert r["exit_code"] == 1 and "not approved" in r["reason"]
    assert runner.calls == [] and rl.load_result(plan["plan_id"], env["base"]) is None


def test_apply_refuses_a_plan_changed_after_approval(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    plan["moves"][0]["dest"] = str(env["tmp"] / "C" / "elsewhere")
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert r["exit_code"] == 1 and "digest" in r["reason"] and runner.calls == []


def test_apply_rechecks_floors_at_execution_time(env):
    """Approved at 300 GB free; by execution C: has 40.5 GB, and 1 GB (+2%) would
    cross its 40 GB floor -> refused, nothing moved."""
    env["fs"].big[str(env["src"])] = 1 * GIB
    plan = _approved(env, {"C:": 300, "D:": 400})
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 40.5, "D:": 400})
    assert r["exit_code"] == 1 and r["moves"][0]["outcome"] == "refused"
    assert "floor" in r["moves"][0]["reason"] and "NOW" in r["moves"][0]["reason"]
    assert runner.calls == [] and len(list(env["src"].rglob("*.bin"))) == 3
    assert [e["outcome"] for e in env["events"]] == ["refused"]  # told, not silent


def test_notification_failure_is_recorded_never_fatal(env):
    plan = _approved(env, {"C:": 300, "D:": 400})

    def broken(_ev):
        raise ConnectionError("relay down")

    r = _apply(env, plan, FakeRobocopy(), {"C:": 300, "D:": 400}, notify=broken)
    assert r["exit_code"] == 0
    n = r["moves"][0]["notifications"]
    assert n and n[0]["ok"] is False and "relay down" in n[0]["reason"]


def test_apply_approved_skips_during_maintenance_marker(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    marker = env["tmp"] / "maintenance.marker"
    marker.write_text("window", encoding="utf-8")
    runner = FakeRobocopy()
    kw = dict(marker=marker, runner=runner, fs=env["fs"], free_space_fn=_free(
        {"C:": 300, "D:": 400}), floors=FLOORS, catalog=False,
        notify=lambda ev: [], node="t", handles_fn=lambda p: 0)
    out = rl.apply_approved(base=env["base"], **kw)
    assert out["exit_code"] == 0 and "maintenance" in out["skipped"] and runner.calls == []
    assert rl.load_result(plan["plan_id"], env["base"]) is None
    marker.unlink()
    out = rl.apply_approved(base=env["base"], **kw)
    assert out["exit_code"] == 0 and out["pending"] == [plan["plan_id"]]
    assert out["results"][0]["outcome"] == "applied" and len(runner.calls) == 1
    out = rl.apply_approved(base=env["base"], **kw)
    assert out["pending"] == [] and len(runner.calls) == 1


@pytest.mark.skipif(os.name != "nt", reason="junctions exist only on Windows")
def test_real_junction_inside_tmp(env):
    env["fs"].real_links = True
    plan = _approved(env, {"C:": 300, "D:": 400})
    r = _apply(env, plan, FakeRobocopy(), {"C:": 300, "D:": 400})
    assert r["outcome"] == "applied", r
    assert rl.HostFS().is_reparse(str(env["src"]))
    assert (env["src"] / "f0.bin").read_bytes() == b"\x00" * 100  # resolves through it
    os.rmdir(env["src"])  # the link only; the moved bytes stay
    assert (Path(plan["moves"][0]["dest"]) / "f0.bin").exists()


# ── floors from the topology file / CLI ───────────────────────────────────────

def test_floors_from_topology_and_mini_parser():
    text = ('drive_floors_gb:\n  "C:": 40\n  D: 50\n  default: 30\n'
            'relocate_do_not_move:\n  - "E:/WSL"\nother: 1\n')
    mini = rl._mini_topology(text)
    floors = rl.floors_from_topology(mini)
    assert floors == {"C:": 40.0, "D:": 50.0, "default": 30.0}
    assert rl.floor_for(floors, "Q:") == 30.0
    assert rl.do_not_move_roots(mini) == ["E:/WSL"]
    with pytest.raises(rl.RelocateError):
        rl.floors_from_topology({"drive_floors_gb": {"C:": "forty"}})


def test_repo_topology_declares_the_floors():
    repo = Path(__file__).resolve().parents[3]
    # parents[3] is the monorepo's AitherOS/ only inside the monorepo. A
    # published awstorage has no fleet topology to read, so skip ONLY when this
    # is not a monorepo checkout -- inside it, a missing topology file stays a
    # failure (the floors it declares are what this test protects).
    if not (repo / "packages" / "awstorage").is_dir():
        pytest.skip("standalone awstorage checkout: no fleet storage topology here")
    topo, floors, where = rl.load_relocate_topology(
        str(repo / "config" / "storage-topology.yaml"))
    assert floors["C:"] >= 40 and "default" in floors and where.endswith(".yaml")
    assert "E:/WSL" in rl.do_not_move_roots(topo)


def test_cli_plan_status_approve(env, capsys):
    # Q: does not exist on any test box: free space is unreadable -> refused, exit 1.
    rc = cli_main(["relocate", "plan", "--source", str(env["src"]), "--dest-drive", "Q:",
                   "--no-handle-probe", "--json"])
    assert rc == 1
    plan = json.loads(capsys.readouterr().out)
    assert plan["ok"] is False and (env["base"] / "plans" / f"{plan['plan_id']}.json").exists()
    assert cli_main(["relocate", "show", plan["plan_id"]]) == 0
    assert cli_main(["relocate", "approve", plan["plan_id"]]) == 1          # no owner flag
    assert cli_main(["relocate", "approve", plan["plan_id"], "--i-am-the-owner"]) == 1
    assert cli_main(["relocate", "apply", plan["plan_id"]]) == 1           # not approved
    assert cli_main(["relocate", "show", "no-such-plan"]) == 2
    capsys.readouterr()
    assert cli_main(["relocate", "status", "--json"]) == 0
    st = json.loads(capsys.readouterr().out)
    assert [p["state"] for p in st["plans"]] == ["refused"]


# ── review findings (2026-09-28): each test fails on the pre-fix code ─────────

class CopyThenWrite:
    """First call: robocopy copied every file but could not delete f0 (locked), and a
    writer then appended to the SOURCE f0. Later calls behave like FakeRobocopy."""

    def __init__(self, append: bytes = b"NEWER-APPENDED-DATA") -> None:
        self.calls: list = []
        self.append = append
        self.fake = FakeRobocopy()

    def __call__(self, argv):
        self.calls.append(list(argv))
        if len(self.calls) > 1:
            return self.fake(argv)
        src, dst = Path(argv[1]), Path(argv[2])
        for f in sorted(p for p in src.rglob("*") if p.is_file()):
            out = dst / f.relative_to(src)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(f), str(out))
            if f.name != "f0.bin":
                f.unlink()
        if self.append:
            with open(src / "f0.bin", "ab") as fh:
                fh.write(self.append)
        return 1, "copied; f0.bin in use"


class Crash(BaseException):
    """The process dying mid-robocopy (reboot, wake timeout): nothing catches it."""


class CrashMid:
    def __init__(self) -> None:
        self.calls: list = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        src, dst = Path(argv[1]), Path(argv[2])
        f = sorted(p for p in src.rglob("*") if p.is_file())[0]
        out = dst / f.relative_to(src)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(f), str(out))
        raise Crash("host rebooted mid-move")


def test_rollback_never_overwrites_a_source_file_written_after_the_copy(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    runner = CopyThenWrite()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    back = runner.calls[1]
    assert back[1] == plan["moves"][0]["dest"] and {"/XO", "/XN", "/XC"} <= set(back)
    mv = r["moves"][0]
    assert mv["outcome"] == "rollback-failed" and r["outcome"] == "rollback-failed"
    assert "differ from the source copy" in mv["reason"]
    # The live bytes survived; the stale copy is left at the destination for a human.
    assert (env["src"] / "f0.bin").read_bytes().endswith(b"NEWER-APPENDED-DATA")
    assert (Path(plan["moves"][0]["dest"]) / "f0.bin").read_bytes() == b"\x00" * 100
    assert [e["outcome"] for e in env["events"]] == ["rollback-failed"]


def test_rollback_drops_an_identical_copy_the_forward_move_could_not_delete(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    r = _apply(env, plan, CopyThenWrite(append=b""), {"C:": 300, "D:": 400})
    assert r["moves"][0]["outcome"] == "rolled-back", r["moves"][0]["reason"]
    assert sorted(p.name for p in env["src"].rglob("*.bin")) == ["f0.bin", "f1.bin", "f2.bin"]
    assert not Path(plan["moves"][0]["dest"]).exists()


def test_apply_refuses_a_tree_written_since_the_plan(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    os.utime(env["src"] / "f0.bin", (NOW.timestamp(), NOW.timestamp()))
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert r["moves"][0]["outcome"] == "refused" and "HOT" in r["moves"][0]["reason"]
    assert runner.calls == []


def test_apply_refuses_open_handles_found_at_execution_time(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400}, handles_fn=lambda p: 3)
    assert r["moves"][0]["outcome"] == "refused" and "3 open file handle" in \
        r["moves"][0]["reason"]
    assert runner.calls == []


def test_planner_canonicalises_a_short_name_alias(env):
    short = str(env["tmp"] / "D" / "CACHE~1")
    env["fs"].aliases[short] = str(env["tmp"] / "D" / "cache")
    typed = os.path.join(short, "models")
    plan = rl.plan_relocation([typed], "C:", FLOORS, _free({"C:": 300, "D:": 400}), NOW,
                              fs=env["fs"], dest_root=str(env["tmp"] / "C"),
                              handles_fn=lambda p: 0, mounts=[])
    assert plan["ok"], plan["refusals"]
    assert plan["moves"][0]["source"] == str(env["src"])  # the RESOLVED path is recorded
    topo = {"relocate_do_not_move": [str(env["tmp"] / "D" / "cache")]}
    plan = rl.plan_relocation([typed], "C:", FLOORS, _free({"C:": 300, "D:": 400}), NOW,
                              fs=env["fs"], dest_root=str(env["tmp"] / "C"),
                              topology=topo, handles_fn=lambda p: 0, mounts=[])
    assert not plan["ok"] and any("do-not-move" in r for r in plan["refusals"])


@pytest.mark.skipif(os.name != "nt", reason="junctions exist only on Windows")
def test_planner_sees_through_a_real_parent_junction(env):
    alias = env["tmp"] / "alias"
    rl.HostFS().make_junction(str(alias), str(env["tmp"] / "D"))
    try:
        topo = {"relocate_do_not_move": [str(env["tmp"] / "D" / "cache")]}
        plan = rl.plan_relocation([str(alias / "cache" / "models")], "C:", FLOORS,
                                  _free({"C:": 300, "D:": 400}), NOW, fs=env["fs"],
                                  dest_root=str(env["tmp"] / "C"), topology=topo,
                                  handles_fn=lambda p: 0, mounts=[])
        assert not plan["ok"] and any("do-not-move" in r for r in plan["refusals"])
        assert os.path.normcase(plan["moves"][0]["source"]) == os.path.normcase(
            str(env["src"]))
    finally:
        os.rmdir(alias)  # the link only


def test_planner_refuses_a_tree_holding_a_vm_disk_or_credentials(env):
    (env["src"] / "sub" / "ext4.vhdx").write_bytes(b"v")
    old = NOW.timestamp() - 90 * 86400
    os.utime(env["src"] / "sub" / "ext4.vhdx", (old, old))
    plan = _plan(env["tmp"], env["fs"], {"C:": 300, "D:": 400})
    assert not plan["ok"] and any("protected entr" in r and "ext4.vhdx" in r
                                  for r in plan["refusals"])
    (env["src"] / "sub" / "ext4.vhdx").unlink()
    (env["src"] / ".ssh").mkdir()
    plan = _plan(env["tmp"], env["fs"], {"C:": 300, "D:": 400})
    assert not plan["ok"] and any("protected entr" in r for r in plan["refusals"])


def test_planner_refuses_a_parent_of_a_never_root(env):
    topo = {"planes": {"backups": {"canonical": {"local": str(env["src"] / "sub")}}}}
    plan = rl.plan_relocation([str(env["src"])], "C:", FLOORS, _free({"C:": 300, "D:": 400}),
                              NOW, fs=env["fs"], dest_root=str(env["tmp"] / "C"),
                              topology=topo, handles_fn=lambda p: 0, mounts=[])
    assert not plan["ok"] and any("contains never-set root" in r for r in plan["refusals"])


def test_planner_refuses_home_aither_and_its_parents(env, monkeypatch):
    home = env["tmp"] / "D" / "home"
    (home / ".aither" / "storage").mkdir(parents=True)
    _tree(home / "stuff")
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))
    for src, why in ((home, "do-not-move"), (home / ".aither" / "storage", "sensitive")):
        plan = rl.plan_relocation([str(src)], "C:", FLOORS, _free({"C:": 300, "D:": 400}),
                                  NOW, fs=env["fs"], dest_root=str(env["tmp"] / "C"),
                                  handles_fn=lambda p: 0, mounts=[])
        assert not plan["ok"] and any(why in r for r in plan["refusals"]), plan["refusals"]


def _handwritten(env, dest: str, pid: str = "rel-y") -> dict:
    plan = {"plan_id": pid, "created_at": "2026-09-28T12:00:00Z", "ok": True,
            "refusals": [], "projection": {"C:": {"free_before_gb": 300.0,
                                                  "free_after_gb": 299.0,
                                                  "floor_gb": 40.0, "ok": True}},
            "moves": [{"id": "m1", "source": str(env["src"]), "dest": dest, "bytes": 303,
                       "files": 3, "newest_mtime": "2026-08-29T12:00:00Z",
                       "evidence": {"cold_days": 30, "open_handles": 0,
                                    "container_mounted": False}, "link": "junction"}]}
    rl.save_plan(plan, env["base"])
    return plan


def test_approve_rejudges_a_handwritten_plan_file(env):
    for i, dest in enumerate((str(env["src"] / "inner"),         # inside the source
                              str(env["tmp"] / "elsewhere" / "x"))):  # no drive letter
        plan = _handwritten(env, dest, pid=f"rel-y{i}")
        with pytest.raises(rl.RelocateRefusedError) as exc:
            rl.approve_plan(plan["plan_id"], approved_by="owner", via="test",
                            base=env["base"], fs=env["fs"], topology={})
        assert ("overlaps the source" if i == 0 else "not on a Windows drive letter") \
            in str(exc.value)
        assert rl.load_approval(plan["plan_id"], env["base"]) is None


def test_apply_rejudges_a_plan_approved_behind_approve_plans_back(env):
    """The card consumer writes approved/ itself: apply must not trust the plan file."""
    plan = _handwritten(env, str(env["src"] / "inner"))
    rl._write_json(env["base"] / "approved" / "rel-y.json",
                   {"plan_id": "rel-y", "plan_sha256": rl.plan_digest(plan)})
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert r["exit_code"] == 1 and r["moves"][0]["outcome"] == "refused"
    assert "overlaps the source" in r["moves"][0]["reason"] and runner.calls == []
    assert [e["outcome"] for e in env["events"]] == ["refused"]


def test_projection_charges_ntfs_allocation_not_logical_bytes(env):
    st = env["fs"].stats(str(env["src"]), cluster=4096)
    assert st["bytes"] == 303
    assert st["alloc_bytes"] == 3 * (4096 + rl.MFT_RECORD) + rl.MFT_RECORD  # + dir "sub"
    env["fs"].big[str(env["src"])] = 2 * GIB          # logical: 2 GiB
    env["fs"].alloc[str(env["src"])] = int(7.2 * GIB)  # on disk: 1.5M small files
    plan = _plan(env["tmp"], env["fs"], {"C:": 44, "D:": 400})
    assert not plan["ok"] and plan["projection"]["C:"]["ok"] is False
    assert plan["projection"]["C:"]["free_after_gb"] < 40


def test_apply_flags_a_destination_that_ended_below_its_floor(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    seq = iter([300 * GIB, 35 * GIB])
    r = rl.apply_plan(plan, FakeRobocopy(), env["fs"], NOW, base=env["base"],
                      free_space_fn=lambda d: next(seq), floors=FLOORS, catalog=False,
                      node="t", handles_fn=lambda p: 0,
                      notify=lambda ev: env["events"].append(ev) or [])
    mv = r["moves"][0]
    assert mv["outcome"] == "applied" and "below its 40 GB floor" in mv["floor_breach"]
    assert env["events"][0]["floor_breach"] and not rl._benign(env["events"][0])


def test_journal_recovers_a_move_that_died_mid_robocopy(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    with pytest.raises(Crash):
        _apply(env, plan, CrashMid(), {"C:": 300, "D:": 400})
    j = rl.journal_path(plan["plan_id"], env["base"])
    assert j.exists() and json.loads(j.read_text())["current"]["id"] == "m1"
    assert rl.load_result(plan["plan_id"], env["base"]) is None
    assert [p["state"] for p in rl.status(env["base"])["plans"]] == ["interrupted"]
    assert Path(plan["moves"][0]["dest"]).exists()  # split: bytes on both sides
    r = _apply(env, plan, FakeRobocopy(), {"C:": 300, "D:": 400})
    mv = r["moves"][0]
    assert mv["outcome"] == "rolled-back" and mv["recovered"] and "died" in mv["reason"]
    assert sorted(p.name for p in env["src"].rglob("*.bin")) == ["f0.bin", "f1.bin", "f2.bin"]
    assert not Path(plan["moves"][0]["dest"]).exists() and not j.exists()
    assert env["events"][-1]["recovered"] is True and not rl._benign(env["events"][-1])


def test_journal_finishes_a_move_that_had_already_linked(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    src, dst = str(env["src"]), plan["moves"][0]["dest"]
    FakeRobocopy()(rl._robocopy(src, dst))  # the move completed ...
    env["fs"].links[src] = dst              # ... and linked, then the process died
    rl._write_json(rl.journal_path(plan["plan_id"], env["base"]), {
        "plan_id": plan["plan_id"], "rows": [],
        "current": {"id": "m1", "source": src, "dest": dst,
                    "before": {"files": 3, "bytes": 303}}})
    runner = FakeRobocopy()
    r = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert r["outcome"] == "applied" and r["moves"][0]["recovered"] and runner.calls == []


def test_roll_up_puts_rollback_failed_above_partial():
    assert rl._roll_up(["applied", "rollback-failed"]) == ("rollback-failed", 1)
    assert rl._roll_up(["applied", "rolled-back"]) == ("partial", 1)
    assert rl._roll_up(["applied", "applied"]) == ("applied", 0)
    assert rl._roll_up(["refused"]) == ("refused", 1)


def test_reapply_returns_the_recorded_results_exit_code(env):
    plan = _approved(env, {"C:": 300, "D:": 400})
    runner = FakeRobocopy(leave_one=True)
    first = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert first["outcome"] == "failed" and first["exit_code"] == 1
    again = _apply(env, plan, runner, {"C:": 300, "D:": 400})
    assert again["exit_code"] == 1 and "already recorded" in again["note"]
    assert len(runner.calls) == 2  # not re-applied
