"""Retention sweep contract tests: rules, age, harvest, secrets, live guard, links,
emergency, receipts, CLI. Every destructive guard is shown REFUSING or PRESERVING,
not only the happy path."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import awstorage
import pytest
from awstorage import cli
from awstorage._fs import is_link, remove_tree
from awstorage._selftest import fake_secret, make_dir_link
from awstorage.catalog import Catalog
from awstorage.policy import ApplyRefused, list_quarantine, move_no_follow, revert

# `awstorage.sweep` the ATTRIBUTE is the sweep() function (the API the brick
# exports); the module is reached through sys.modules for monkeypatching.
sw = sys.modules["awstorage.sweep"]
PKG_ROOT = Path(__file__).resolve().parents[1]


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


def _run(root: Path, tmp: Path, **kw) -> dict:
    kw.setdefault("policy", _pol(root))
    kw.setdefault("harvest_to", tmp / "shelf")
    kw.setdefault("seal", False)
    return awstorage.sweep(**kw)


# -- rules -------------------------------------------------------------------------

@pytest.mark.parametrize("v,s", [("12h", 43200), ("3d", 259200), ("90m", 5400), (45, 45),
                                 ("1w", 604800), ("0.5h", 1800)])
def test_parse_duration(v, s):
    assert sw.parse_duration(v) == s


@pytest.mark.parametrize("bad", ["", "12x", "-3h", "h"])
def test_parse_duration_rejects(bad):
    with pytest.raises(sw.SweepConfigError):
        sw.parse_duration(bad)


def test_expand_path_both_var_styles_and_unset_is_an_error():
    env = {"LOCALAPPDATA": "C:\\Users\\u\\AppData\\Local", "HOMEX": "/h"}
    assert sw.expand_path("%LOCALAPPDATA%\\Temp\\claude\\*\\*", env) == \
        "C:/Users/u/AppData/Local/Temp/claude/*/*"
    assert sw.expand_path("$HOMEX/a/${HOMEX}", env) == "/h/a//h"
    with pytest.raises(sw.SweepConfigError, match="NOPE"):
        sw.expand_path("%NOPE%/x", env)
    # TMPDIR unset is the platform temp dir, not an error and not ''.
    assert sw.expand_path("$TMPDIR/claude", {}).endswith("/claude")
    assert sw.expand_path("$TMPDIR/claude", {}) != "/claude"


def test_static_base_and_glob_regex():
    assert sw.static_base("C:/a/Temp/claude/*/*") == "C:/a/Temp/claude"
    assert sw.static_base("/tmp/*") == "/tmp"
    assert sw.static_base("C:/*") == "C:/"
    md = sw.glob_to_regex("**/*.md")
    assert md.match("a.md") and md.match("x/y/B.MD") and not md.match("a.mdx")
    ev = sw.glob_to_regex("**/*eval*/**")
    assert ev.match("runs/my_eval_3/out.txt") and not ev.match("runs/out.txt")
    res = sw.glob_to_regex("**/results/**")
    assert res.match("results/a.csv") and res.match("x/results/y/z") and not res.match("x/r/y")
    star = sw.glob_to_regex("*.json")
    assert star.match("a.json") and not star.match("d/a.json")


def test_presets_are_opt_in_by_name():
    assert awstorage.default_policy()["retention"] == []
    with pytest.raises(sw.SweepConfigError, match="no retention rule named"):
        sw.resolve_rules([], awstorage.default_policy())
    names = {r["name"] for r in sw.resolve_rules(["agent-scratch", "temp-toplevel"])}
    assert names == {"agent-scratch", "temp-toplevel"}
    p = sw.presets()
    assert p["agent-scratch"]["max_idle"] == "12h" and p["temp-toplevel"]["max_idle"] == "3d"
    assert p["agent-scratch"]["paths"][0].endswith("/claude/*/*")
    assert any(x.endswith("/claude") for x in p["temp-toplevel"]["exclude"])
    if os.name == "nt":
        assert p["agent-scratch"]["paths"][0].startswith("%LOCALAPPDATA%")
    else:
        assert p["agent-scratch"]["paths"][0].startswith("$TMPDIR")


def test_policy_rule_overrides_preset_and_declared_rules_run_unnamed(tmp_path: Path):
    pol = {"retention": [_rule(tmp_path, name="agent-scratch", max_idle="1d")]}
    [r] = sw.resolve_rules(["agent-scratch"], pol)
    assert r["max_idle"] == 86400 and r["paths"] == [tmp_path.as_posix() + "/*"]
    assert [x["name"] for x in sw.resolve_rules(None, pol)] == ["agent-scratch"]


@pytest.mark.parametrize("over,msg", [
    ({"class": "service-state"}, "never auto"),
    ({"class": "dataset"}, "never auto"),
    ({"class": "nonsense"}, "not one of"),
    ({"action": "compress"}, "action"),
    ({"paths": []}, "paths"),
    ({"name": "a/b"}, "name"),
    ({"harvest": "yes"}, "harvest"),
])
def test_validate_rule_refuses(tmp_path: Path, over, msg):
    with pytest.raises(sw.SweepConfigError, match=msg):
        sw.validate_rule(_rule(tmp_path, **over))
    r = _rule(tmp_path)
    del r["max_idle"]
    with pytest.raises(sw.SweepConfigError, match="max_idle"):
        sw.validate_rule(r)


# -- measure / age ------------------------------------------------------------------

def test_age_is_newest_file_inside_never_the_top_entry(tmp_path: Path):
    root = tmp_path / "r"
    # Top entry old, a deep file fresh -> NOT idle.
    deep = root / "busy"
    _mk(deep / "a" / "b" / "c" / "new.txt", b"n", 3)
    _mk(deep / "old.txt", b"o", 50)
    _age_dir(deep, 50)
    # Top entry fresh (just touched), every file old -> idle.
    stale = root / "stale"
    _mk(stale / "sub" / "old.txt", b"o", 50)
    rec = _run(root, tmp_path, policy=_pol(root, live_guard=None), dry_run=True)
    by = {Path(i["path"]).name: i for i in rec["items"]}
    assert "busy" not in by and rec["kept_fresh"] == 1
    assert by["stale"]["outcome"] == "dry-run"
    m = sw.measure(str(stale))
    assert m["files"] == 1 and m["bytes"] == 1 and m["top_subdirs"][0]["path"] == "sub"


def test_measure_stops_at_the_first_too_new_file(tmp_path: Path):
    it = tmp_path / "big"
    for i in range(50):
        _mk(it / f"d{i:02d}" / "f.bin", b"z" * 10, 50)
    _mk(it / "d00" / "new.txt", b"n", 0)
    full = sw.measure(str(it))
    assert full["files"] == 51 and "early" not in full
    cut = sw.measure(str(it), stop_newer_than=time.time() - 3600)
    assert cut["early"] == "fresh" and cut["files"] < 51


def test_time_budget_truncates_cleanly_with_a_receipt(tmp_path: Path, capsys, monkeypatch):
    import types
    root = tmp_path / "r"
    for i in range(3):
        _mk(root / f"s{i}" / "a.md", b"a", 30)
    # A clock that advances 10 s per read: deterministic, unlike a 1e-9 budget
    # against Windows' 15 ms monotonic tick.
    ticks = iter(range(0, 10**6, 10))
    fake = types.SimpleNamespace(**{k: getattr(time, k) for k in
                                    ("time", "strftime", "gmtime", "localtime")},
                                 monotonic=lambda: float(next(ticks)))
    monkeypatch.setattr(sw, "time", fake)
    rec = _run(root, tmp_path, dry_run=False, time_budget_s=5,
               receipt=tmp_path / "r.json")
    got = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert rec["truncated"] is True and got["truncated"] is True and got["exit_code"] == 0
    assert all((root / f"s{i}").exists() for i in range(3))
    assert any("time budget" in n for n in rec["notes"])
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(_pol(root)), encoding="utf-8")
    rc = cli.main(["sweep", "--policy", str(pol), "--no-catalog", "--no-audit",
                   "--harvest-to", str(tmp_path / "shelf"), "--time-budget", "5"])
    assert rc == 0 and "TRUNCATED" in capsys.readouterr().out


def test_budget_cut_item_goes_first_next_pass(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    for n in ("a", "b", "z-giant"):
        _mk(root / n / "f.md", b"x", 30)
    rc = tmp_path / "rc.json"
    order: list[str] = []
    real = sw.measure

    def spy(path, *a, **k):
        order.append(Path(path).name)
        if Path(path).name == "z-giant" and len(order) < 4:
            return {**real(path, *a, **k), "early": "budget"}
        return real(path, *a, **k)
    monkeypatch.setattr(sw, "measure", spy)
    rec = _run(root, tmp_path, dry_run=True, receipt=rc)
    assert rec["truncated"] and [Path(x).name for x in rec["resume_first"]] == ["z-giant"]
    order.clear()
    _run(root, tmp_path, dry_run=True, receipt=rc)
    assert order[0] == "z-giant"


# -- harvest -----------------------------------------------------------------------

def test_harvest_copies_verifies_and_writes_manifest_before_delete(tmp_path: Path):
    root = tmp_path / "r"
    it = root / "sess"
    _mk(it / "REPORT.md", b"# report", 30)
    _mk(it / "deep" / "evalrun_eval" / "score.txt", b"0.9", 30)
    _mk(it / "x" / "results" / "r.csv", b"a,b", 30)
    _mk(it / "notes.txt", b"not included", 30)
    _mk(it / "blob.json", b"{\x00}", 30)
    _mk(it / "huge.md", b"h" * (600 * 1024), 30)
    rec = _run(root, tmp_path, dry_run=False, receipt=tmp_path / "r.json")
    assert rec["exit_code"] == 0 and not it.exists()
    day = time.strftime("%Y-%m-%d")
    d = tmp_path / "shelf" / "t" / day / "sess"
    man = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    got = {h["path"]: h for h in man["harvested"]}
    assert set(got) == {"REPORT.md", "deep/evalrun_eval/score.txt", "x/results/r.csv"}
    assert (d / "deep" / "evalrun_eval" / "score.txt").read_bytes() == b"0.9"
    import hashlib
    assert got["REPORT.md"]["sha256"] == hashlib.sha256(b"# report").hexdigest()
    reasons = {s["path"]: s["reason"] for s in man["skipped"]}
    assert reasons == {"blob.json": "binary", "huge.md": "too-large"}
    assert man["item"] == it.as_posix() and man["file_count"] == 6
    assert man["total_bytes"] == sum(len(x) for x in (b"# report", b"0.9", b"a,b",
                                                         b"not included", b"{\x00}")) + 600 * 1024
    assert rec["bytes_harvested"] == 8 + 3 + 3 and rec["files_harvested"] == 3


def test_harvest_total_budget(tmp_path: Path):
    root = tmp_path / "r"
    for i in range(5):
        _mk(root / "s" / f"f{i}.md", b"m" * 300 * 1024, 30)
    rec = _run(root, tmp_path, dry_run=False,
               policy=_pol(root, harvest={"max_total_mb": 1}))
    assert rec["files_harvested"] == 3
    man = next((tmp_path / "shelf").rglob("manifest.json"))
    skipped = json.loads(man.read_text(encoding="utf-8"))["skipped"]
    assert [s["reason"] for s in skipped] == ["budget", "budget"]


@pytest.mark.parametrize("secret", [
    lambda: fake_secret(),
    lambda: "gh" + "p_" + "A" * 36,
    lambda: "gh" + "s_" + "B" * 36,
    lambda: "AK" + "IA" + "ABCDEFGHIJKLMNOP",
    lambda: "xo" + "xb-" + "1234567890-abcdef",
    lambda: "xo" + "xp-" + "1234567890-abcdef",
    lambda: "pk" + "_live_" + "abcdefghijkl",
    lambda: "sk" + "_live_" + "abcdefghijkl",
    lambda: "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    lambda: "pass" + "word=" + "hunter2hunter2",
])
def test_secret_patterns_are_withheld_and_never_written(tmp_path: Path, secret):
    root = tmp_path / "r"
    s = secret()
    _mk(root / "sess" / "leak.md", f"notes\n{s}\n".encode(), 30)
    _mk(root / "sess" / "ok.md", b"clean", 30)
    rec = _run(root, tmp_path, dry_run=False, receipt=tmp_path / "rc.json")
    assert rec["withheld_secret"] == 1 and rec["exit_code"] == 0
    shelf = tmp_path / "shelf"
    assert next(shelf.rglob("leak.md"), None) is None
    assert next(shelf.rglob("ok.md"), None) is not None
    for f in list(shelf.rglob("*")) + [tmp_path / "rc.json"]:
        if f.is_file():
            assert s not in f.read_text(encoding="utf-8", errors="replace")
    man = json.loads(next(shelf.rglob("manifest.json")).read_text(encoding="utf-8"))
    assert {"path": "leak.md", "reason": "withheld: secret-pattern"} in man["skipped"]


def test_password_without_a_value_is_not_a_secret(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "doc.md", b"set the password= in the vault\n", 30)
    rec = _run(root, tmp_path, dry_run=False)
    assert rec["withheld_secret"] == 0 and rec["files_harvested"] == 1


def test_harvest_verify_failure_keeps_the_item(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"abc", 30)
    monkeypatch.setattr(sw, "_sha256_file", lambda p: (3, "0" * 64))
    rec = _run(root, tmp_path, dry_run=False, receipt=tmp_path / "r.json")
    assert rec["exit_code"] == 1 and (root / "s" / "a.md").exists()
    assert "verify failed" in rec["errors"][0]
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["exit_code"] == 1


def test_harvest_offdrive_refuses_a_same_drive_shelf(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"abc", 30)
    rec = _run(root, tmp_path, dry_run=False, harvest_offdrive=True)
    assert rec["exit_code"] == 1 and (root / "s").exists()
    assert "same drive" in rec["errors"][0]


def test_reserved_shelf_names_are_not_overwritten(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "manifest.json", b'{"mine": 1}', 30)
    _mk(root / "s" / "a.md", b"a", 30)
    _run(root, tmp_path, dry_run=False)
    man = json.loads(next((tmp_path / "shelf").rglob("manifest.json")).read_text(
        encoding="utf-8"))
    assert man["item"].endswith("/s")
    assert any(s["path"] == "manifest.json" and "reserved" in s["reason"]
               for s in man["skipped"])


def test_item_with_nothing_to_harvest_gets_no_shelf_dir(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "junk.tmp", b"y" * 100, 30)
    rec = _run(root, tmp_path, dry_run=False)
    assert rec["items_removed"] == 1 and not (tmp_path / "shelf").exists()


# -- live guard --------------------------------------------------------------------

def test_live_guard_window_env_and_file(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    _mk(root / "fresh" / "a.md", b"a", 0.5)
    _mk(root / "env-id" / "a.md", b"a", 30)
    _mk(root / "file-id" / "a.md", b"a", 30)
    _mk(root / "gone" / "a.md", b"a", 30)
    ids = tmp_path / "live.txt"
    ids.write_text("# running sessions\nFILE-ID  # case-insensitive\n", encoding="utf-8")
    monkeypatch.setenv(sw.LIVE_IDS_ENV, "other, env-id;x")
    rec = _run(root, tmp_path, dry_run=False, live_ids_file=str(ids))
    live = sorted(Path(p).name for p in rec["skipped_live"])
    assert live == ["env-id", "file-id", "fresh"]
    assert all((root / n).exists() for n in live) and not (root / "gone").exists()


def test_unreadable_live_ids_file_is_could_not_judge(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)
    rec = _run(root, tmp_path, dry_run=False, live_ids_file=str(tmp_path / "missing.txt"),
               receipt=tmp_path / "r.json")
    assert rec["exit_code"] == 2 and (root / "s").exists()


# -- links -------------------------------------------------------------------------

@pytest.fixture
def linked(tmp_path: Path):
    """An old item holding a directory link to a precious tree outside it."""
    root = tmp_path / "r"
    outside = tmp_path / "precious"
    _mk(outside / "keep.txt", b"keep")
    _mk(outside / "report.md", b"outside report")
    item = root / "s"
    _mk(item / "a.md", b"a", 30)
    kind = make_dir_link(item / "lnk", outside)
    if kind is None:
        pytest.skip("this host can make neither a junction nor a symlink")
    return root, item, outside, kind


def test_link_detection_and_remove_tree_never_follow(linked):
    _root, item, outside, kind = linked
    assert is_link(item / "lnk") and not is_link(item)
    removed, errs = remove_tree(item)
    assert errs == [] and not item.exists()
    assert (outside / "keep.txt").read_bytes() == b"keep", kind


@pytest.mark.skipif(os.name != "nt", reason="junctions are Windows-only")
def test_real_junction_via_mklink(tmp_path: Path):
    target = tmp_path / "t"
    _mk(target / "f.txt", b"f")
    j = tmp_path / "j"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(j), str(target)],
                       capture_output=True, check=False)
    assert r.returncode == 0, r.stderr
    # os.path.islink() is False for a junction; is_link() must still say True.
    assert is_link(j) and not os.path.islink(j)
    assert awstorage.sweep.__module__ == "awstorage.sweep"
    remove_tree(j)
    assert not os.path.lexists(j) and (target / "f.txt").exists()


def test_sweep_delete_unlinks_link_and_harvest_skips_it(linked, tmp_path: Path):
    root, item, outside, _kind = linked
    rec = _run(root, tmp_path, dry_run=False)
    assert rec["exit_code"] == 0 and not item.exists()
    assert (outside / "keep.txt").exists() and (outside / "report.md").exists()
    # The link was never walked for harvest either.
    assert next((tmp_path / "shelf").rglob("report.md"), None) is None


def test_sweep_quarantine_moves_link_as_link_and_revert_restores(linked, tmp_path: Path):
    root, item, outside, _kind = linked
    rec = _run(root, tmp_path, dry_run=False, policy=_pol(root, action="quarantine"))
    assert rec["items_removed"] == 1 and not item.exists()
    [q] = list_quarantine([root])
    assert Path(q["entry"]).name.startswith("sweep-t-")
    assert (outside / "keep.txt").exists()
    revert(Path(q["entry"]))
    assert (item / "a.md").exists() and is_link(item / "lnk")


def test_purge_and_rmtree_do_not_follow_links(linked, tmp_path: Path):
    root, item, outside, _kind = linked
    from awstorage.policy import _rmtree, purge_quarantine
    _run(root, tmp_path, dry_run=False, policy=_pol(root, action="quarantine"))
    res = purge_quarantine([root], older_than_days=0, dry_run=False)
    assert res and res[0]["outcome"] == "purged"
    assert (outside / "keep.txt").exists()
    other = tmp_path / "o"
    _mk(other / "x", b"x")
    make_dir_link(other / "l", outside)
    _rmtree(other)
    assert not other.exists() and (outside / "keep.txt").exists()


def test_scan_does_not_count_link_targets(linked):
    root, _item, _outside, _kind = linked
    snap = awstorage.scan(root, max_depth=2, node="t")
    by = {t["path"]: t for t in snap["trees"]}
    assert by[root.as_posix()]["bytes"] == 1  # a.md only, not the link target's files


def test_cross_device_fallback_refuses_a_tree_with_links(linked, tmp_path: Path, monkeypatch):
    import errno as _errno
    _root, item, outside, _kind = linked

    def xdev(*_a, **_k):
        raise OSError(_errno.EXDEV, "cross-device")
    monkeypatch.setattr(os, "replace", xdev)
    with pytest.raises(ApplyRefused, match="cross-device"):
        move_no_follow(item, tmp_path / "elsewhere")
    assert (item / "a.md").exists() and (outside / "keep.txt").exists()


def test_a_busy_rename_never_falls_back_to_copy_and_delete(tmp_path: Path, monkeypatch):
    src = tmp_path / "s"
    _mk(src / "f", b"f")

    def busy(*_a, **_k):
        raise PermissionError(13, "in use")
    monkeypatch.setattr(os, "replace", busy)
    with pytest.raises(PermissionError):
        move_no_follow(src, tmp_path / "d")
    assert (src / "f").exists() and not (tmp_path / "d").exists()


def test_busy_item_is_skipped_not_failed(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)

    def busy(*_a, **_k):
        raise PermissionError(13, "in use")
    monkeypatch.setattr(sw, "move_no_follow", busy)
    rec = _run(root, tmp_path, dry_run=False, policy=_pol(root, action="quarantine"))
    assert rec["exit_code"] == 0 and rec["skipped_busy"] and (root / "s").exists()
    assert list_quarantine([root]) == []  # the half-made entry was cleaned up


# -- emergency ---------------------------------------------------------------------

def test_emergency_halves_max_idle_only_under_the_floor(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 6)
    calm = _run(root, tmp_path, dry_run=True, emergency_free_gb=40,
                disk_free=lambda _p: 100 * 2**30)
    assert calm["items_eligible"] == 0 and calm["emergency"] == []
    hot = _run(root, tmp_path, dry_run=True, emergency_free_gb=40,
               disk_free=lambda _p: 1 * 2**30)
    assert hot["items_eligible"] == 1
    [e] = hot["emergency"]
    assert e["rule"] == "t" and "EMERGENCY" in e["message"] and "10h -> 5h" in e["message"]


def test_emergency_is_printed_by_the_cli(tmp_path: Path, capsys):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 6)
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(_pol(root)), encoding="utf-8")
    rc = cli.main(["sweep", "--policy", str(pol), "--harvest-to", str(tmp_path / "shelf"),
                   "--no-catalog", "--no-audit", "--emergency-free-gb", "1e12"])
    out = capsys.readouterr().out
    assert rc == 0 and "EMERGENCY:" in out and "dry-run" in out


# -- the pass: dry run, quarantine, purge, delete, ledger, receipt -----------------

RECEIPT_KEYS = {"exit_code", "started", "finished", "items_seen", "items_removed",
                "bytes_freed", "bytes_harvested", "skipped_live", "errors", "free_before",
                "free_after"}


def test_dry_run_is_the_default_and_prints_the_full_plan(tmp_path: Path, capsys):
    root = tmp_path / "r"
    _mk(root / "s1" / "a.md", b"a", 30)
    _mk(root / "s2" / "b.bin", b"b" * 10, 30)
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(_pol(root)), encoding="utf-8")
    rc = cli.main(["sweep", "--policy", str(pol), "--harvest-to", str(tmp_path / "shelf"),
                   "--no-catalog", "--no-audit", "--receipt", str(tmp_path / "r.json")])
    out = capsys.readouterr().out
    assert rc == 0 and "DRY RUN" in out and "s1" in out and "s2" in out
    assert "Re-run with --yes" in out
    assert (root / "s1").exists() and (root / "s2").exists()
    assert not (tmp_path / "shelf").exists()
    rec = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert RECEIPT_KEYS <= set(rec) and rec["dry_run"] is True


def test_quarantine_then_purge_after_frees_bytes(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.bin", b"z" * 1000, 30)
    rec = _run(root, tmp_path, dry_run=False,
               policy=_pol(root, action="quarantine", purge_after="1d"))
    assert rec["items_removed"] == 1 and rec["bytes_quarantined"] == 1000
    assert rec["bytes_freed"] == 0  # a quarantine frees nothing yet; honest
    [q] = list_quarantine([root])
    old = time.time() - 2 * 86400
    os.utime(q["entry"], (old, old))
    rec2 = _run(root, tmp_path, dry_run=False,
                policy=_pol(root, action="quarantine", purge_after="1d"))
    # The payload plus the entry's own ORIGIN record: every byte purge removed.
    assert rec2["purged"][0]["outcome"] == "purged" and rec2["bytes_freed"] >= 1000
    assert list_quarantine([root]) == []


def test_delete_ledger_and_receipt(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.bin", b"z" * 500, 30)
    _mk(root / "fresh" / "a.bin", b"z", 5)
    cat_path = tmp_path / "cat.db"
    rec = _run(root, tmp_path, dry_run=False, catalog=cat_path,
               receipt=tmp_path / "rc.json", policy=_pol(root, live_guard=None))
    assert rec["exit_code"] == 0 and rec["bytes_freed"] == 500 and rec["items_removed"] == 1
    assert rec["kept_fresh"] == 1 and rec["items_seen"] == 2
    on_disk = json.loads((tmp_path / "rc.json").read_text(encoding="utf-8"))
    assert RECEIPT_KEYS <= set(on_disk) and on_disk["bytes_freed"] == 500
    assert on_disk["free_before"] and on_disk["free_after"]
    cat = Catalog(cat_path)
    rows = cat.list_ledger()
    cat.close()
    assert [(r["action"], r["outcome"], r["bytes"]) for r in rows] == \
        [("sweep:t:delete", "applied", 500)]


def test_quarantine_dir_shelf_and_receipt_are_never_items(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)
    shelf = root / "shelf-inside"
    _mk(shelf / "old.md", b"o", 30)
    _mk(root / "old-q" / "a.md", b"a", 30)
    _run(root, tmp_path, dry_run=False, harvest_to=shelf,
         policy=_pol(root, action="quarantine"))
    assert (root / ".awstorage-quarantine").is_dir()
    rec = _run(root, tmp_path, dry_run=False, harvest_to=shelf,
               receipt=root / "receipt-dir" / "r.json",
               policy=_pol(root, action="quarantine"))
    assert shelf.exists()
    paths = {Path(i["path"]).name: i for i in rec["items"]}
    assert paths["shelf-inside"]["outcome"] == "skipped"
    assert ".awstorage-quarantine" not in paths


def test_an_item_matched_by_two_rules_is_processed_once(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)
    pol = {"retention": [_rule(root, name="one"), _rule(root, name="two")]}
    rec = _run(root, tmp_path, dry_run=True, policy=pol)
    assert rec["items_seen"] == 1 and rec["items"][0]["rule"] == "one"


def test_missing_base_is_a_note_not_an_error(tmp_path: Path):
    rec = _run(tmp_path / "nope", tmp_path, dry_run=False)
    assert rec["exit_code"] == 0 and "does not exist" in rec["notes"][0]


def test_unreadable_root_is_could_not_judge(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)
    real = os.scandir

    def deny(p=".", *a, **k):
        if Path(p) == root:
            raise PermissionError(13, "denied")
        return real(p, *a, **k)
    monkeypatch.setattr(sw.os, "scandir", deny)
    ok_root = tmp_path / "ok"
    _mk(ok_root / "first" / "a.md", b"a", 30)
    # The readable rule runs FIRST; the unreadable one must stop the pass before it acts.
    pol = {"retention": [_rule(ok_root, name="first"), _rule(root, name="second")]}
    rec = _run(root, tmp_path, dry_run=False, receipt=tmp_path / "r.json", policy=pol)
    assert rec["exit_code"] == 2 and "cannot read" in rec["could_not_judge"][0]
    assert (root / "s").exists() and (ok_root / "first").exists()


def test_internal_error_still_writes_a_receipt(tmp_path: Path, monkeypatch):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)

    def boom(*_a, **_k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(sw, "measure", boom)
    rec = _run(root, tmp_path, dry_run=False, receipt=tmp_path / "r.json")
    got = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert rec["exit_code"] == 2 and got["exit_code"] == 2 and "kaboom" in got["could_not_judge"][0]


def test_cli_bad_policy_file_exits_2_with_receipt(tmp_path: Path):
    bad = tmp_path / "p.json"
    bad.write_text("{not json", encoding="utf-8")
    rc = cli.main(["sweep", "--rules", "agent-scratch", "--policy", str(bad), "--no-catalog",
                   "--no-audit", "--receipt", str(tmp_path / "r.json")])
    assert rc == 2
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["exit_code"] == 2


def test_cli_yes_json_and_exit_1_on_failure(tmp_path: Path, capsys):
    root = tmp_path / "r"
    _mk(root / "s" / "a.md", b"a", 30)
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps(_pol(root)), encoding="utf-8")
    base = ["sweep", "--policy", str(pol), "--harvest-to", str(tmp_path / "shelf"),
            "--catalog", str(tmp_path / "c.db"), "--no-audit", "--no-seal", "--json"]
    rc = cli.main(base + ["--yes", "--harvest-offdrive"])
    rec = json.loads(capsys.readouterr().out)
    assert rc == 1 and rec["exit_code"] == 1 and (root / "s").exists()
    rc = cli.main(base + ["--yes"])
    rec = json.loads(capsys.readouterr().out)
    assert rc == 0 and rec["items_removed"] == 1 and not (root / "s").exists()


def test_preset_agent_scratch_end_to_end_via_env(tmp_path: Path):
    la = tmp_path / "LA"
    tmp = la / "Temp" if os.name == "nt" else la
    old = tmp / "claude" / "proj" / "dead-session"
    _mk(old / "tasks" / "x.output", b"o" * 100, 48)
    _mk(old / "REVIEW_REPORT.md", b"# review", 48)
    _mk(tmp / "claude" / "proj" / "live-session" / "f.md", b"f", 0.2)
    env = {"LOCALAPPDATA": str(la), "TMPDIR": str(la)}
    rec = awstorage.sweep(["agent-scratch"], dry_run=False, env=env, seal=False,
                          harvest_to=tmp_path / "shelf")
    assert rec["exit_code"] == 0 and rec["items_removed"] == 1
    assert not old.exists() and (tmp / "claude" / "proj" / "live-session").exists()
    assert next((tmp_path / "shelf" / "agent-scratch").rglob("REVIEW_REPORT.md"))


def test_python_dash_m_and_version():
    assert awstorage.__version__ == "0.5.0"
    r = subprocess.run([sys.executable, "-m", "awstorage", "--version"], cwd=PKG_ROOT,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=60, check=False)
    assert r.returncode == 0 and "0.5.0" in r.stdout
    toml = (PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.5.0"' in toml


def test_sweep_imports_no_sibling_at_module_load():
    code = ("import sys, awstorage, awstorage.sweep, awstorage.integrations, awstorage.cli;"
            "bad=[m for m in ('awdit','awseal','awshare','awm','awrecover','adk','lib',"
            "'services') if m in sys.modules]; print(bad); sys.exit(1 if bad else 0)")
    r = subprocess.run([sys.executable, "-c", code], cwd=PKG_ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=60, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
