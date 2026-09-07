"""awstorage contract tests. Every claim in the package docstring has a test that
can fail, and the destructive path is proven REVERSIBLE, not just refused."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import awstorage
import pytest
from awstorage import cli
from awstorage._fs import exclusive_bytes
from awstorage.classify import LLMClassifier, classify_tree
from awstorage.graph import to_graph
from awstorage.policy import NEVER_AUTO, ApplyRefused


def _mk(root: Path, rel: str, size: int, age_days: float = 0.0) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * size)
    if age_days:
        t = time.time() - age_days * 86400
        os.utime(p, (t, t))
    return p


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "vol"
    _mk(root, "build/out.o", 4096, age_days=10)
    _mk(root, "build/sub/deep/x.bin", 2048, age_days=10)
    _mk(root, "node_modules/pkg/index.js", 1024, age_days=30)
    _mk(root, "postgres-data/base/1", 8192)
    _mk(root, "models/big.gguf", 16384, age_days=5)
    _mk(root, "readme.txt", 10)
    return root


def _policy_min1():
    pol = awstorage.default_policy()
    for r in pol["rules"]:
        r["min_bytes"] = 1
    return pol


def test_scan_aggregates_and_depth(tree: Path):
    snap = awstorage.scan(tree, max_depth=2, node="t")
    by = {t["path"]: t for t in snap["trees"]}
    root = by[snap["root"]]
    assert root["depth"] == 0
    assert root["files"] == 6
    assert root["bytes"] == 4096 + 2048 + 1024 + 8192 + 16384 + 10
    build = by[snap["root"] + "/build"]
    assert build["bytes"] == 4096 + 2048  # aggregate includes the depth-3 file
    assert build["depth"] == 1
    assert (snap["root"] + "/build/sub") in by
    assert (snap["root"] + "/build/sub/deep") not in by  # beyond max_depth
    assert snap["schema"] == awstorage.SCHEMA_VERSION
    assert snap["truncated"] is False
    assert snap["top_files"][0]["bytes"] == 16384
    excl = exclusive_bytes(snap)
    assert excl[snap["root"] + "/build"] == 4096  # sub's 2048 belongs to sub
    assert excl[snap["root"]] == 10


def test_scan_time_budget_marks_truncated(tree: Path):
    snap = awstorage.scan(tree, max_depth=5, time_budget_s=0.0, node="t")
    assert snap["truncated"] is True


def test_scan_bad_root_raises(tmp_path: Path):
    with pytest.raises(awstorage.ScanError):
        awstorage.scan(tmp_path / "nope")


def test_heuristic_classes_and_refetchable():
    assert classify_tree("E:/Caches/pip")["cls"] == "package-cache"
    assert classify_tree("C:/x/node_modules")["refetchable"] is True
    v = classify_tree("/var/lib/containers/storage/overlay")
    assert v["cls"] == "container-store"
    assert classify_tree("D:/postgres-data")["refetchable"] is False
    weights = classify_tree("D:/stuff", ["D:/stuff/a.gguf", "D:/stuff/b.safetensors"])
    assert weights["cls"] == "model-weights" and weights["source"] == "heuristic"
    assert classify_tree("D:/whatever")["cls"] == "unknown"
    for v2 in (weights, classify_tree("D:/whatever")):
        assert set(v2) >= {"cls", "refetchable", "confidence", "reason", "source"}


def test_llm_classifier_falls_back_and_records_source(tree: Path):
    snap = awstorage.scan(tree, max_depth=1, node="t")
    paths = [t["path"] for t in snap["trees"]]

    def complete(prompt: str) -> str:
        # Answer for ONE path with a valid class, one with an INVALID class, skip the rest.
        return json.dumps([
            {"path": paths[1], "cls": "dataset", "refetchable": False, "confidence": 0.7,
             "reason": "looks like data"},
            {"path": paths[2], "cls": "not-a-class", "refetchable": True, "confidence": 0.9},
        ])

    clf = LLMClassifier(complete, batch=100)
    awstorage.classify_snapshot(snap, clf)
    by = {t["path"]: t for t in snap["trees"]}
    assert by[paths[1]]["cls"] == "dataset" and by[paths[1]]["source"] == "llm"
    assert "heuristic_cls" in by[paths[1]]
    assert by[paths[2]]["source"] == "heuristic"  # invalid class -> floor kept
    assert clf.fallbacks == len(paths) - 1
    assert snap["classifier"]["kind"] == "llm"

    def broken(prompt: str) -> str:
        raise RuntimeError("router down")

    snap2 = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=1, node="t"),
                                        LLMClassifier(broken))
    assert all(t["source"] == "heuristic" for t in snap2["trees"])
    assert all("llm_error" not in t for t in snap2["trees"])  # error is not smuggled into trees


def test_catalog_roundtrip_and_totals(tree: Path, tmp_path: Path):
    snap = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=2, node="t"))
    cat = awstorage.Catalog(tmp_path / "c.db")
    sid = cat.put_snapshot(snap)
    back = cat.get_snapshot(sid)
    assert back["root"] == snap["root"] and len(back["trees"]) == len(snap["trees"])
    assert {t["path"]: t["bytes"] for t in back["trees"]} == \
        {t["path"]: t["bytes"] for t in snap["trees"]}
    assert back["trees"][0]["refetchable"] in (True, False, None)
    tot = cat.totals()
    assert tot["nodes"] == ["t"] and tot["total_bytes"] == snap["trees"][0]["bytes"]
    assert cat.get_snapshot(999) is None
    cat.close()


def test_diff_sees_growth_added_removed(tree: Path):
    a = awstorage.scan(tree, max_depth=2, node="t")
    _mk(tree, "models/second.gguf", 4096)
    _mk(tree, "newdir/f", 512)
    import shutil
    shutil.rmtree(tree / "node_modules")
    b = awstorage.scan(tree, max_depth=2, node="t")
    d = awstorage.diff_snapshots(a, b, min_delta_bytes=1)
    grown = {g["path"]: g["delta"] for g in d["grown"]}
    assert grown[b["root"] + "/models"] == 4096
    assert any(r["path"].endswith("/newdir") for r in d["added"])
    assert any(r["path"].endswith("/node_modules") for r in d["removed"])
    assert d["summary"]["root_delta"] == 4096 + 512 - 1024
    with pytest.raises(ValueError):
        awstorage.diff_snapshots(a, {**b, "root": "other"})


def test_propose_collapses_nested_and_never_autos_state(tree: Path):
    snap = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=3, node="t"))
    props = awstorage.propose(snap, _policy_min1())
    paths = [p.path for p in props]
    assert any(p.endswith("/build") for p in paths)
    assert not any(p.endswith("/build/sub") for p in paths)  # collapsed onto parent
    by = {p.path.rsplit("/", 1)[-1]: p for p in props}
    assert by["build"].auto is True and by["build"].action == "delete"
    assert by["node_modules"].auto is True
    assert by["models"].auto is False and by["models"].action == "review"
    assert "postgres-data" not in by  # no rule targets service-state at all
    assert all(p.cls not in NEVER_AUTO or not p.auto for p in props)
    with pytest.raises(ValueError):
        awstorage.propose(awstorage.scan(tree, max_depth=1, node="t"))  # unclassified


def test_apply_refuses_outside_roots_stale_and_unapproved(tree: Path, tmp_path: Path):
    snap = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=2, node="t"))
    props = awstorage.propose(snap, _policy_min1())
    build = next(p for p in props if p.path.endswith("/build"))
    with pytest.raises(ApplyRefused, match="outside the declared roots"):
        awstorage.apply(build, roots=[tmp_path / "elsewhere"], dry_run=False)
    # Dry run is the default and touches nothing.
    r = awstorage.apply(build, roots=[tree])
    assert r["outcome"] == "dry-run" and (tree / "build").exists()
    # A write after the scan makes the proposal stale.
    _mk(tree, "build/new.o", 100)
    with pytest.raises(ApplyRefused, match="changed since the scan"):
        awstorage.apply(build, roots=[tree], dry_run=False)
    # A non-auto proposal needs approval.
    models = next(p for p in props if p.path.endswith("/models"))
    models.action = "delete"
    with pytest.raises(ApplyRefused, match="approved"):
        awstorage.apply(models, roots=[tree], dry_run=False, verify_fingerprint=False)


def test_apply_quarantines_and_revert_restores(tree: Path):
    snap = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=2, node="t"))
    build = next(p for p in awstorage.propose(snap, _policy_min1()) if p.path.endswith("/build"))
    build.id = 7
    r = awstorage.apply(build, roots=[tree], dry_run=False)
    assert r["outcome"] == "applied" and r["bytes"] == 4096 + 2048
    assert not (tree / "build").exists()
    q = awstorage.list_quarantine([tree])
    assert len(q) == 1 and q[0]["origin"].endswith("build") and q[0]["bytes"] == 6144
    # Purge respects age; nothing this fresh is purged, even with --yes.
    assert awstorage.purge_quarantine([tree], older_than_days=1, dry_run=False) == []
    dest = awstorage.revert(Path(q[0]["entry"]))
    assert dest.endswith("/build") and (tree / "build" / "out.o").read_bytes() == b"x" * 4096
    assert awstorage.list_quarantine([tree]) == []
    with pytest.raises(ApplyRefused):
        awstorage.revert(tree / "models")  # not a quarantine entry


def test_backup_hook_runs_before_quarantine(tree: Path):
    snap = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=2, node="t"))
    models = next(p for p in awstorage.propose(snap, _policy_min1()) if p.path.endswith("/models"))
    models.action = "backup-then-delete"
    calls = []

    def hook(p: Path) -> str:
        calls.append(p)
        return "label-1"

    with pytest.raises(ApplyRefused, match="backup hook"):
        awstorage.apply(models, roots=[tree], dry_run=False, approved=True)
    r = awstorage.apply(models, roots=[tree], dry_run=False, approved=True, backup_hook=hook)
    assert calls and r["outcome"] == "applied" and "label-1" in r["detail"]


def test_graph_has_contains_and_duplicates(tree: Path):
    # Two trees with the SAME name and size under different parents -> duplicate_of.
    _mk(tree, "copyA/weights/model.bin", 5000)
    _mk(tree, "copyB/weights/model.bin", 5000)
    snap = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=2, node="t"))
    g = to_graph(snap)
    kinds = {e["kind"] for e in g["edges"]}
    assert {"hosts", "contains", "duplicate_of"} <= kinds
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["src"] in ids and e["dst"] in ids for e in g["edges"])
    tree_nodes = [n for n in g["nodes"] if n["kind"] == "tree"]
    assert all("exclusive_bytes" in n and "cls" in n for n in tree_nodes)


def test_cli_end_to_end(tree: Path, tmp_path: Path, capsys):
    db = str(tmp_path / "inv.db")
    assert cli.main(["scan", str(tree), "--depth", "2", "--catalog", db, "--node", "t",
                     "--quiet"]) == 0
    assert cli.main(["inventory", "--catalog", db]) == 0
    out = capsys.readouterr().out
    assert "1 root(s) on 1 node(s)" in out
    pol = tmp_path / "pol.json"
    pol.write_text(json.dumps(_policy_min1()), encoding="utf-8")
    assert cli.main(["propose", "--catalog", db, "--snapshot", "1", "--policy", str(pol)]) == 0
    out = capsys.readouterr().out
    assert "AUTO" in out and "ASK" in out
    # Apply the build proposal: dry-run first, then for real, then revert.
    cat = awstorage.Catalog(db)
    build = next(p for p in cat.list_proposals() if p["path"].endswith("/build"))
    cat.close()
    assert cli.main(["apply", "--catalog", db, "--proposal", str(build["id"]),
                     "--root", str(tree)]) == 0
    assert (tree / "build").exists()
    assert cli.main(["apply", "--catalog", db, "--proposal", str(build["id"]),
                     "--root", str(tree), "--yes"]) == 0
    assert not (tree / "build").exists()
    cat = awstorage.Catalog(db)
    led = cat.list_ledger()
    assert led[0]["outcome"] == "applied" and led[1]["outcome"] == "dry-run"
    assert cat.get_proposal(build["id"])["status"] == "applied"
    cat.close()
    assert cli.main(["quarantine", "--root", str(tree)]) == 0
    entry = awstorage.list_quarantine([tree])[0]["entry"]
    assert cli.main(["revert", entry]) == 0
    assert (tree / "build" / "out.o").exists()
    # Refusal is exit 1 and ledgered.
    models = next(p for p in awstorage.Catalog(db).list_proposals()
                  if p["path"].endswith("/models"))
    assert cli.main(["apply", "--catalog", db, "--proposal", str(models["id"]),
                     "--root", str(tmp_path / "other"), "--yes"]) == 1
    assert cli.main(["scan", str(tree), "--depth", "2", "--catalog", db, "--node", "t",
                     "--quiet"]) == 0
    assert cli.main(["diff", "--catalog", db, "--root", str(tree), "--node", "t"]) == 0
    assert cli.main(["graph", "--catalog", db, "--snapshot", "1"]) == 0
    assert cli.main(["inventory", "--catalog", db, "--snapshot", "404"]) == 2


def test_build_output_inside_a_git_repo_is_never_auto(tmp_path: Path):
    """Tenant repos `git add -f` their dist/; a build-temp rule must not auto-delete it."""
    root = tmp_path / "vol"
    _mk(root, "repos/acme/.git/HEAD", 10)
    _mk(root, "repos/acme/dist/bundle.js", 8192, age_days=30)
    _mk(root, "scratch/dist/out.o", 8192, age_days=30)
    snap = awstorage.classify_snapshot(awstorage.scan(root, max_depth=3, node="t"))
    by = {t["path"]: t for t in snap["trees"]}
    assert by[snap["root"] + "/repos/acme"]["git"] is True
    assert by[snap["root"] + "/scratch"]["git"] is False
    props = {p.path.rsplit("/", 2)[-2] + "/" + p.path.rsplit("/", 1)[-1]: p
             for p in awstorage.propose(snap, _policy_min1())}
    assert props["acme/dist"].auto is False
    assert "git working tree" in props["acme/dist"].note
    assert props["scratch/dist"].auto is True
    # The flag survives the catalog round trip, so proposing from a stored snapshot
    # reaches the same verdict as proposing from a live one.
    cat = awstorage.Catalog(tmp_path / "c.db")
    back = cat.get_snapshot(cat.put_snapshot(snap))
    again = {p.path: p.auto for p in awstorage.propose(back, _policy_min1())}
    assert again[snap["root"] + "/repos/acme/dist"] is False
    assert again[snap["root"] + "/scratch/dist"] is True
    cat.close()


def test_apply_defers_while_a_build_is_in_progress(tree: Path):
    """Design N11: reclaim is DEFERRED while a container build runs on the node — a
    build's temp dirs and intermediate layers look exactly like reclaimable trees."""
    snap = awstorage.classify_snapshot(awstorage.scan(tree, max_depth=2, node="t"))
    build = next(p for p in awstorage.propose(snap, _policy_min1()) if p.path.endswith("/build"))
    with pytest.raises(ApplyRefused, match="deferred: a container build"):
        awstorage.apply(build, roots=[tree], dry_run=False, build_in_progress=lambda: True)
    assert (tree / "build").exists()  # nothing moved
    # A dry run never consults the probe (a deferral must not mask a dry-run answer).
    r = awstorage.apply(build, roots=[tree], dry_run=True,
                        build_in_progress=lambda: (_ for _ in ()).throw(AssertionError("probed")))
    assert r["outcome"] == "dry-run"
    # No build -> proceeds (quarantine), and the default probe is a callable.
    r2 = awstorage.apply(build, roots=[tree], dry_run=False, build_in_progress=lambda: False)
    assert r2["outcome"] == "applied" and not (tree / "build").exists()
    from awstorage.policy import _build_in_progress
    assert isinstance(_build_in_progress(), bool)


def test_apply_refuses_inside_a_git_working_tree_even_for_a_stale_auto_proposal(tmp_path: Path):
    """2026-09-02: proposals written before the scanner recorded `.git` quarantined four
    tenant repos' tracked dist/ trees. The guard must live at APPLY time, on the disk."""
    root = tmp_path / "vol"
    _mk(root, "repos/acme/dist/bundle.js", 8192, age_days=30)
    snap = awstorage.classify_snapshot(awstorage.scan(root, max_depth=3, node="t"))
    dist = next(p for p in awstorage.propose(snap, _policy_min1()) if p.path.endswith("/dist"))
    assert dist.auto is True  # no .git yet -> the policy pre-approves it
    # The repo appears AFTER the proposal was written (or the scan predates the flag).
    _mk(root, "repos/acme/.git/HEAD", 10)
    with pytest.raises(ApplyRefused, match="git working tree"):
        awstorage.apply(dist, roots=[root], dry_run=False, verify_fingerprint=False)
    assert (root / "repos" / "acme" / "dist" / "bundle.js").exists()
    # A human's explicit approval still goes through (and is what the card answers).
    r = awstorage.apply(dist, roots=[root], dry_run=False, verify_fingerprint=False, approved=True)
    assert r["outcome"] == "applied"
    # The declared root itself being a repo does not make everything under it a repo
    # (the scan-time repo guard still downgrades those; the APPLY guard must not double up).
    from awstorage.policy import _git_ancestor
    root2 = tmp_path / "vol2"
    _mk(root2, ".git/HEAD", 10)
    _mk(root2, "scratch/dist/out.o", 8192, age_days=30)
    assert _git_ancestor(root2 / "scratch" / "dist", [root2]) is None
    assert _git_ancestor(root / "repos" / "acme" / "dist", [root]) is not None


def test_self_test_passes():
    assert cli.self_test() == 0
