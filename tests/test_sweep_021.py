"""0.2.1 sweep contracts: emergency delete, purge on every pass, per-item measure cap.

Measured on the first real run (2026-09-28): 1130 items removed, bytes_freed 0 (every
removal a same-drive quarantine), and one 106 GB dead session tree spent the whole
15 min budget being measured. Each guard below is shown refusing as well as acting.
"""

from __future__ import annotations

import json
import os
import sys
import time
import types
from pathlib import Path

import awstorage
import pytest
from awstorage import cli
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


def _rule(root: Path, **over) -> dict:
    r = {"name": "t", "paths": [root.as_posix() + "/*"], "class": "build-temp",
         "max_idle": "10h", "action": "delete", "live_guard": {"window": "2h"}}
    r.update(over)
    return r


def _pol(root: Path, **over) -> dict:
    return {"retention": [_rule(root, **over)]}


def _qpol(root: Path, **over) -> dict:
    over.setdefault("action", "quarantine")
    over.setdefault("purge_after", "1d")
    over.setdefault("emergency_delete", True)
    return _pol(root, **over)


def _run(root: Path, tmp: Path, **kw) -> dict:
    kw.setdefault("policy", _pol(root))
    kw.setdefault("harvest_to", tmp / "shelf")
    kw.setdefault("seal", False)
    return awstorage.sweep(**kw)


def _fake_clock(monkeypatch) -> None:
    # 10 s per monotonic read: deterministic, unlike a tiny budget vs a 15 ms tick.
    ticks = iter(range(0, 10**6, 10))
    fake = types.SimpleNamespace(**{k: getattr(time, k) for k in
                                    ("time", "strftime", "gmtime", "localtime")},
                                 monotonic=lambda: float(next(ticks)))
    monkeypatch.setattr(sw, "time", fake)


# -- emergency delete --------------------------------------------------------------

def test_presets_carry_emergency_delete_and_validation_refuses_misuse(tmp_path: Path):
    for n in ("agent-scratch", "temp-toplevel"):
        [r] = sw.resolve_rules([n])
        assert r["emergency_delete"] is True
    assert sw.validate_rule(_rule(tmp_path))["emergency_delete"] is False
    with pytest.raises(sw.SweepConfigError, match="regenerable"):
        sw.validate_rule(_rule(tmp_path, **{"class": "logs", "emergency_delete": True}))
    with pytest.raises(sw.SweepConfigError, match="requires harvest"):
        sw.validate_rule(_rule(tmp_path, harvest=False, emergency_delete=True))
    with pytest.raises(sw.SweepConfigError, match="true or false"):
        sw.validate_rule(_rule(tmp_path, emergency_delete="yes"))


def test_emergency_delete_frees_bytes_after_a_verified_harvest(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "REPORT.md", b"# kept", 30)
    _mk(root / "s" / "blob.bin", b"z" * 4000, 30)
    cat_path = tmp_path / "cat.db"
    rec = _run(root, tmp_path, dry_run=False, policy=_qpol(root), catalog=cat_path,
               emergency_free_gb=40, disk_free=lambda _p: 1 * 2**30)
    assert rec["exit_code"] == 0 and not (root / "s").exists()
    assert list_quarantine([root]) == []  # deleted, not moved aside on the same drive
    assert rec["emergency_deleted"] == 1 and rec["bytes_quarantined"] == 0
    assert rec["bytes_freed"] >= 4006 and rec["bytes_emergency_deleted"] >= 4006
    [it] = rec["items"]
    assert it["action"] == "deleted-emergency" and it["outcome"] == "applied"
    assert next((tmp_path / "shelf").rglob("REPORT.md")).read_bytes() == b"# kept"
    cat = Catalog(cat_path)
    rows = cat.list_ledger()
    cat.close()
    assert [(r["action"], r["outcome"]) for r in rows] == \
        [("sweep:t:deleted-emergency", "applied")]


def test_emergency_delete_dry_run_says_so_and_touches_nothing(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)
    rec = _run(root, tmp_path, dry_run=True, policy=_qpol(root), emergency_free_gb=40,
               disk_free=lambda _p: 0)
    [it] = rec["items"]
    assert it["outcome"] == "dry-run" and "deleted-emergency" in it["reason"]
    assert (root / "s").exists() and rec["emergency_deleted"] == 0


def test_emergency_delete_never_without_a_verified_harvest(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"abc", 30)
    monkeypatch.setattr(sw, "_sha256_file", lambda p: (3, "0" * 64))
    rec = _run(root, tmp_path, dry_run=False, policy=_qpol(root), emergency_free_gb=40,
               disk_free=lambda _p: 0)
    assert rec["exit_code"] == 1 and (root / "s" / "a.md").exists()
    assert rec["emergency_deleted"] == 0 and rec["bytes_freed"] == 0
    assert list_quarantine([root]) == [] and "verify failed" in rec["errors"][0]


def test_emergency_delete_not_for_a_rule_without_the_flag(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.bin", b"z" * 1000, 30)
    rec = _run(root, tmp_path, dry_run=False, policy=_qpol(root, emergency_delete=False),
               emergency_free_gb=40, disk_free=lambda _p: 0)
    assert rec["emergency_deleted"] == 0 and rec["bytes_quarantined"] == 1000
    assert rec["bytes_freed"] == 0 and len(list_quarantine([root])) == 1
    assert any("bytes_freed is 0" in n for n in rec["notes"])


def test_emergency_delete_not_above_the_floor(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.bin", b"z" * 1000, 30)
    rec = _run(root, tmp_path, dry_run=False, policy=_qpol(root), emergency_free_gb=40,
               disk_free=lambda _p: 500 * 2**30)
    assert rec["emergency_deleted"] == 0 and len(list_quarantine([root])) == 1


def test_emergency_delete_stops_once_the_drive_is_back_above_the_floor(tmp_path: Path):
    root = tmp_path / "r"
    for n in ("a", "b"):
        _mk(root / n / "x.bin", b"z" * 3000, 30)
    floor_gb = 4000 / 2**30  # 1000 B free + one delete (3000 B) reaches the floor
    rec = _run(root, tmp_path, dry_run=False, policy=_qpol(root),
               emergency_free_gb=floor_gb, disk_free=lambda _p: 1000)
    assert rec["emergency_deleted"] == 1 and len(list_quarantine([root])) == 1


# -- purge on every pass -----------------------------------------------------------

def test_purge_runs_and_counts_even_when_the_pass_is_truncated(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    _mk(root / "s" / "a.bin", b"z" * 1000, 30)
    _run(root, tmp_path, dry_run=False, policy=_qpol(root))
    [q] = list_quarantine([root])
    old = time.time() - 2 * 86400
    os.utime(q["entry"], (old, old))
    _mk(root / "s2" / "b.bin", b"y", 30)
    _fake_clock(monkeypatch)
    rec = _run(root, tmp_path, dry_run=False, policy=_qpol(root), time_budget_s=5)
    assert rec["truncated"] is True and (root / "s2").exists()
    assert rec["purged"][0]["outcome"] == "purged"
    assert rec["bytes_purged"] >= 1000 and rec["bytes_freed"] == rec["bytes_purged"]
    assert list_quarantine([root]) == []


# -- per-item measure cap ----------------------------------------------------------

def test_capped_measure_old_item_is_eligible_and_still_harvested(tmp_path: Path):
    root = tmp_path / "r"
    item = root / "giant"
    _mk(item / "deep" / "REPORT.md", b"# giant", 30)
    _mk(item / "deep" / "x.bin", b"z" * 100, 30)
    _age_dir(item / "deep", 30)
    _age_dir(item, 30)
    rec = _run(root, tmp_path, dry_run=False, measure_cap_s=0,
               policy=_pol(root, action="quarantine"))
    [c] = rec["capped"]
    assert c["verdict"] == "eligible" and c["path"].endswith("giant")
    assert c["files_seen"] == 0 and c["sample_files"] == 2
    assert rec["items_removed"] == 1 and not item.exists()
    [it] = rec["items"]
    assert it["capped"] is True and it["size"] == "unknown (capped)"
    assert next((tmp_path / "shelf").rglob("REPORT.md")).read_bytes() == b"# giant"
    man = json.loads(next((tmp_path / "shelf").rglob("manifest.json"))
                     .read_text(encoding="utf-8"))
    assert man["measure"].startswith("capped")


def test_capped_measure_with_a_fresh_sampled_file_is_live(tmp_path: Path):
    root = tmp_path / "r"
    item = root / "busy"
    _mk(item / "old.bin", b"z", 30)
    _mk(item / "sub" / "new.md", b"n", 5)  # past the 2h window, inside the 10h max_idle
    _age_dir(item / "sub", 30)
    _age_dir(item, 30)
    rec = _run(root, tmp_path, dry_run=False, measure_cap_s=0)
    [c] = rec["capped"]
    assert c["verdict"] == "live" and item.exists() and rec["items_removed"] == 0
    assert [Path(p).name for p in rec["skipped_live"]] == ["busy"]


def test_capped_measure_with_a_fresh_top_entry_is_live(tmp_path: Path):
    root = tmp_path / "r"
    item = root / "renamed"
    _mk(item / "old.bin", b"z", 30)  # the dir's own mtime stays "now"
    rec = _run(root, tmp_path, dry_run=False, measure_cap_s=0)
    [c] = rec["capped"]
    assert c["verdict"] == "live" and item.exists()


def test_a_walk_that_saw_a_fresh_file_is_never_capped(tmp_path: Path):
    root = tmp_path / "r"
    item = root / "s"
    _mk(item / "new.md", b"n", 5)
    _age_dir(item, 30)
    rec = _run(root, tmp_path, dry_run=False)  # default 120 s cap, never reached
    assert rec["capped"] == [] and item.exists() and rec["kept_fresh"] == 1


def test_uncapped_measure_is_unchanged(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.bin", b"z", 30)
    rec = _run(root, tmp_path, dry_run=False, measure_cap_s=None)
    assert rec["capped"] == [] and rec["items_removed"] == 1


def test_sample_age_is_bounded_and_sees_fresh(tmp_path: Path):
    item = tmp_path / "i"
    for i in range(30):
        _mk(item / f"f{i:02d}.bin", b"z", 30)
    _age_dir(item, 30)
    cut = time.time() - 3600
    s = sw.sample_age(str(item), cut, max_files=10)
    assert s["files"] == 10 and s["fresh"] is None
    _mk(item / "zz.bin", b"n", 0)
    _age_dir(item, 30)
    assert sw.sample_age(str(item), cut)["fresh"] == "zz.bin"


def test_cli_measure_cap_flag_and_capped_line(tmp_path: Path, capsys):
    root = tmp_path / "r"
    item = root / "g"
    _mk(item / "a.bin", b"z", 30)
    _age_dir(item, 30)
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(_pol(root)), encoding="utf-8")
    rc = cli.main(["sweep", "--policy", str(pol), "--harvest-to", str(tmp_path / "shelf"),
                   "--no-catalog", "--no-audit", "--measure-cap-s", "0"])
    out = capsys.readouterr().out
    assert rc == 0 and "capped measure (eligible)" in out and item.exists()
