"""0.4.0: agents suggest deletions, trust, watch, place, shelf safety, agent-worktrees."""

from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

import awstorage
from awstorage import manage, space
from awstorage.catalog import Catalog
from awstorage.cli import main
from awstorage.gitcheck import git_state, nested_repos
from awstorage.policy import list_quarantine, revert

sg = importlib.import_module("awstorage.suggest")
sw = importlib.import_module("awstorage.sweep")
HAS_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAS_GIT, reason="git not on PATH")
GB = 2**30


# -- helpers -------------------------------------------------------------------------

def _mk(p: Path, data: bytes = b"x", age_h: float = 30.0) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    _age(p, age_h)
    return p


def _age(p: Path, hours: float) -> None:
    t = time.time() - hours * 3600
    os.utime(p, (t, t))


def _age_tree(root: Path, hours: float) -> None:
    t = time.time() - hours * 3600
    for d, dirs, files in os.walk(root):
        for n in files + dirs:
            try:
                os.utime(os.path.join(d, n), (t, t), follow_symlinks=False)
            except (OSError, NotImplementedError):
                os.utime(os.path.join(d, n), (t, t))
    os.utime(root, (t, t))


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    gc = tmp_path / "gitconfig"
    gc.write_text("", encoding="utf-8")
    for k, v in {"GIT_CONFIG_GLOBAL": str(gc), "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                 "AWSTORAGE_NODE": "testnode"}.items():
        monkeypatch.setenv(k, v)
    for k in ("AWSTORAGE_LIVE_IDS", "AWSTORAGE_FLOORS", "AWSTORAGE_TRUST_THRESHOLD",
              "AWSTORAGE_ALERT_CMD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "default-cat.db"))
    sg.set_card_hook(None)
    sg.set_archive_hook(None)
    yield
    sg.set_card_hook(None)
    sg.set_archive_hook(None)


@pytest.fixture
def cat(tmp_path: Path):
    c = Catalog(tmp_path / "cat.db")
    yield c
    c.close()


def git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args],
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stderr
    return r.stdout


def make_pushed_repo(tmp: Path, name: str = "work") -> Path:
    bare = tmp / f"{name}-remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True,
                   capture_output=True)
    work = tmp / name
    work.mkdir()
    git(work, "init", "-q")
    git(work, "checkout", "-q", "-b", "main")
    (work / "README.md").write_text("hi\n", encoding="utf-8")
    (work / ".gitignore").write_text("build/\n", encoding="utf-8")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "init")
    git(work, "remote", "add", "origin", str(bare))
    git(work, "push", "-q", "-u", "origin", "main")
    return work


def seed_trust(cat: Catalog, agent: str, applied: int = 5, rejected: int = 0,
               reverted: int = 0) -> None:
    for i in range(applied + rejected):
        sid = cat.put_suggestion({"node": "n", "path": f"/seed/{agent}/{i}",
                                  "path_key": f"/seed/{agent}/{i}", "action": "quarantine",
                                  "reason": "seed", "suggested_by": agent,
                                  "status": "pending-card"})
        if i < applied:
            extra = {"reverted_at": "2026-01-02T00:00:00"} if i < reverted else {}
            cat.update_suggestion(sid, status="reverted" if extra else "applied",
                                  applied_at="2026-01-01T00:00:00", **extra)
        else:
            cat.update_suggestion(sid, status="rejected")


def old_build(root: Path, n: int = 128) -> Path:
    item = root / "build"
    _mk(item / "a.o", b"1" * n, 30)
    _mk(item / "NOTES.md", b"# notes\n", 30)
    _age_tree(item, 30)
    return item


def attested_card(cid: str, pid: int, answer: str = "approve") -> dict:
    return {"id": cid, "status": "answered", "answered_via": "desk", "answered_by": "owner",
            "answer": answer, "facts": [f"proposal_id: {pid}"]}


# -- git check -----------------------------------------------------------------------

@needs_git
def test_git_state_clean_dirty_unpushed_and_worktree(tmp_path: Path):
    work = make_pushed_repo(tmp_path)
    st = git_state(work)
    assert st["judged"] and st["clean"], st
    (work / "new.txt").write_text("x", encoding="utf-8")
    st = git_state(work / "README.md")
    assert st["judged"] and not st["clean"] and st["dirty"] == 1
    (work / "new.txt").unlink()
    (work / "README.md").write_text("changed\n", encoding="utf-8")
    git(work, "commit", "-qam", "local only")
    st = git_state(work)
    assert st["judged"] and not st["clean"] and st["unpushed"] == 1
    git(work, "push", "-q")
    assert git_state(work)["clean"]
    # A linked worktree (.git is a FILE): detached / new branch, HEAD on a remote.
    git(work, "worktree", "add", "-q", str(tmp_path / "wt1"), "-b", "feat")
    st = git_state(tmp_path / "wt1")
    assert st["kind"] == "file" and st["clean"], st
    (tmp_path / "wt1" / "f.txt").write_text("x", encoding="utf-8")
    git(tmp_path / "wt1", "add", "f.txt")
    git(tmp_path / "wt1", "commit", "-qm", "unpushed on feat")
    st = git_state(tmp_path / "wt1")
    assert not st["clean"] and st["unpushed"] == 1


@needs_git
def test_git_state_no_remote_and_empty_repo_refuse(tmp_path: Path):
    r = tmp_path / "local"
    r.mkdir()
    git(r, "init", "-q")
    st = git_state(r)
    assert not st["judged"] and not st["clean"] and "could not judge" in st["why"]
    (r / "a").write_text("a", encoding="utf-8")
    git(r, "add", "a")
    git(r, "commit", "-qm", "a")
    st = git_state(r)
    assert st["judged"] and not st["clean"] and st["unpushed"] >= 1


def test_git_state_outside_repo_and_missing_git(tmp_path: Path, monkeypatch):
    d = tmp_path / "plain"
    d.mkdir()
    assert git_state(d)["repo"] is None and git_state(d)["clean"]
    (d / ".git").mkdir()
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    st = git_state(d)
    assert st["repo"] and not st["judged"] and not st["clean"]


def test_nested_repos_found_and_bounded(tmp_path: Path):
    (tmp_path / "top" / "a" / ".git").mkdir(parents=True)
    (tmp_path / "top" / "b" / "c").mkdir(parents=True)
    (tmp_path / "top" / "b" / "c" / ".git").write_text("gitdir: x", encoding="utf-8")
    r = nested_repos(tmp_path / "top")
    kinds = sorted(k for _p, k in r["repos"])
    assert r["complete"] and kinds == ["dir", "file"]
    assert not nested_repos(tmp_path / "top", max_dirs=1)["complete"]


# -- suggest: validation -------------------------------------------------------------

def test_suggest_arguments_are_validated(tmp_path: Path, cat):
    with pytest.raises(ValueError, match="action"):
        sg.suggest(str(tmp_path), reason="r", suggested_by="a", action="rm", catalog=cat)
    with pytest.raises(ValueError, match="reason"):
        sg.suggest(str(tmp_path), reason=" ", suggested_by="a", catalog=cat)
    with pytest.raises(ValueError, match="suggested_by"):
        sg.suggest(str(tmp_path), reason="r", suggested_by="", catalog=cat)
    with pytest.raises(ValueError, match="ttl_days"):
        sg.suggest(str(tmp_path), reason="r", suggested_by="a", ttl_days=0, catalog=cat)


def test_suggest_result_shape_and_card_lane_for_new_agent(tmp_path: Path, cat):
    item = old_build(tmp_path / "proj")
    r = sg.suggest(str(item), reason="stale build", suggested_by="newbie",
                   evidence={"bytes": 136, "idle_hours": 24}, catalog=cat)
    assert set(r) >= {"id", "status", "why", "class", "size", "checks"}
    assert isinstance(r["id"], int) and r["id"] > 0
    assert r["status"] == "pending-card" and "trust 0.50 < 0.60" in r["why"]
    assert r["class"] == "build-temp" and r["size"] == 136
    names = [c.split(":")[0] for c in r["checks"]]
    for n in ("dedupe", "exists", "not-link", "guards", "live-ids", "classify", "git",
              "measure", "live-window", "evidence", "trust"):
        assert n in names, (n, r["checks"])
    # The id is a proposals row whose action policy.apply refuses.
    prop = cat.get_proposal(r["id"])
    assert prop["action"] == "suggest:quarantine" and prop["status"] == "proposed"
    with pytest.raises(awstorage.ApplyRefused, match="unknown action"):
        awstorage.apply(prop, roots=[tmp_path], dry_run=False)


@pytest.mark.parametrize("case", ["missing", "guard", "live-id", "fresh", "root"])
def test_suggest_refusals(tmp_path: Path, cat, monkeypatch, case):
    if case == "missing":
        path = tmp_path / "nope"
    elif case == "guard":
        path = tmp_path / "secrets" / "build"
        _mk(path / "a", b"1")
    elif case == "live-id":
        path = old_build(tmp_path / "sess-7")
        monkeypatch.setenv("AWSTORAGE_LIVE_IDS", "sess-7")
    elif case == "fresh":
        path = tmp_path / "build"
        _mk(path / "old", b"1", 30)
        _mk(path / "deep" / "new", b"2", 0.1)
    else:
        path = Path(os.path.abspath(os.sep))
    r = sg.suggest(str(path), reason="r", suggested_by="a", catalog=cat)
    assert r["status"] == "refused", r
    assert any("REFUSED" in c for c in r["checks"])
    if case == "fresh":
        assert "live window" in r["why"]


def test_suggest_refuses_a_link(tmp_path: Path, cat):
    from awstorage._selftest import make_dir_link

    target = old_build(tmp_path / "t")
    link = tmp_path / "link"
    if make_dir_link(link, target) is None:
        pytest.skip("cannot create a directory link here")
    r = sg.suggest(str(link), reason="r", suggested_by="a", catalog=cat)
    assert r["status"] == "refused" and "link" in r["why"]
    assert target.exists()


@needs_git
def test_suggest_refuses_dirty_and_unpushed_work_trees(tmp_path: Path, cat):
    work = make_pushed_repo(tmp_path)
    b = old_build(work)  # build/ is ignored: the tree is clean
    r = sg.suggest(str(b), reason="r", suggested_by="a", catalog=cat)
    assert r["status"] == "pending-card", r
    assert any(c.startswith("git: ") and "clean and pushed" in c for c in r["checks"])
    sg.resolve_suggestion(r["id"], "reject", catalog=cat)
    (work / "wip.txt").write_text("uncommitted", encoding="utf-8")
    r = sg.suggest(str(b), reason="r", suggested_by="a", catalog=cat)
    assert r["status"] == "refused" and "uncommitted" in r["why"]
    (work / "wip.txt").unlink()
    (work / "README.md").write_text("new\n", encoding="utf-8")
    git(work, "commit", "-qam", "local")
    r = sg.suggest(str(b), reason="r", suggested_by="a", catalog=cat)
    assert r["status"] == "refused" and "no remote holds" in r["why"]


def test_suggest_dedupes_open_suggestions(tmp_path: Path, cat):
    item = old_build(tmp_path)
    r1 = sg.suggest(str(item), reason="r", suggested_by="a", catalog=cat)
    r2 = sg.suggest(str(item) + os.sep, reason="r2", suggested_by="b", catalog=cat)
    assert r2["status"] == "duplicate" and r2["id"] == r1["id"]
    assert len(cat.list_suggestions()) == 1
    sg.resolve_suggestion(r1["id"], "reject", catalog=cat)
    r3 = sg.suggest(str(item), reason="r3", suggested_by="b", catalog=cat)
    assert r3["status"] == "pending-card" and r3["id"] != r1["id"]


# -- lanes + trust -------------------------------------------------------------------

def test_trust_math():
    assert sg.trust_score(0, 0, 0) == 0.5
    assert sg.trust_score(1, 0, 0) == pytest.approx(2 / 3)
    assert sg.trust_score(0, 1, 0) == pytest.approx(1 / 3)
    assert sg.trust_score(1, 0, 1) == pytest.approx(-1 / 3)
    assert sg.trust_score(10, 2, 1) == pytest.approx((10 - 3 + 1) / 14)
    assert sg.trust_score(0, 0, 0) < sg.TRUST_THRESHOLD


def test_trust_threshold_cannot_admit_a_new_agent(monkeypatch):
    monkeypatch.setenv("AWSTORAGE_TRUST_THRESHOLD", "0.1")
    assert sg.trust_threshold() == sg.MIN_TRUST_THRESHOLD > sg.trust_score(0, 0, 0)
    monkeypatch.setenv("AWSTORAGE_TRUST_THRESHOLD", "0.9")
    assert sg.trust_threshold() == 0.9


def test_trust_table_counts(cat):
    seed_trust(cat, "good", applied=4, rejected=1)
    seed_trust(cat, "bad", applied=2, reverted=1)
    rows = {r["agent"]: r for r in sg.trust(catalog=cat)}
    g, b = rows["good"], rows["bad"]
    assert (g["made"], g["applied"], g["rejected"], g["reverted"]) == (5, 4, 1, 0)
    assert g["trust"] == pytest.approx(5 / 7, abs=1e-4) and g["auto_eligible"]
    assert b["reverted"] == 1 and b["trust"] == pytest.approx(0.0) and not b["auto_eligible"]
    [n] = sg.trust("nobody", catalog=cat)
    assert n["made"] == 0 and n["trust"] == 0.5


def test_auto_lane_requires_every_condition(tmp_path: Path, cat):
    seed_trust(cat, "trusted", applied=5)
    ok = old_build(tmp_path / "p1")
    r = sg.suggest(str(ok), reason="dead", suggested_by="trusted",
                   evidence={"bytes": 136}, catalog=cat)
    assert r["status"] == "auto-approved", r
    # delete / archive: never auto.
    for i, act in enumerate(("delete", "archive")):
        it = old_build(tmp_path / f"a{i}")
        r = sg.suggest(str(it), reason="dead", suggested_by="trusted", action=act,
                       evidence={"bytes": 136}, catalog=cat)
        assert r["status"] == "pending-card" and f"action {act}" in r["why"]
    # no evidence -> card
    it = old_build(tmp_path / "p2")
    r = sg.suggest(str(it), reason="dead", suggested_by="trusted", catalog=cat)
    assert r["status"] == "pending-card" and "evidence none" in r["why"]
    # non-regenerable class -> card
    ds = tmp_path / "p3" / "datasets"
    _mk(ds / "d.csv", b"1,2", 30)
    _age_tree(ds, 30)
    r = sg.suggest(str(ds), reason="dead", suggested_by="trusted",
                   evidence={"bytes": 3}, catalog=cat)
    assert r["status"] == "pending-card" and "not regenerable" in r["why"]
    # untrusted agent -> card
    it = old_build(tmp_path / "p4")
    r = sg.suggest(str(it), reason="dead", suggested_by="stranger",
                   evidence={"bytes": 136}, catalog=cat)
    assert r["status"] == "pending-card" and "trust" in r["why"]
    # nested dirty repo blocks auto
    it = old_build(tmp_path / "p5")
    (it / "clone" / ".git").mkdir(parents=True)
    _age_tree(it, 30)
    r = sg.suggest(str(it), reason="dead", suggested_by="trusted",
                   evidence={"bytes": 136}, catalog=cat)
    assert r["status"] == "pending-card" and "nested work tree" in r["why"]


def test_evidence_mismatch_is_refused(tmp_path: Path, cat):
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="r", suggested_by="a",
                   evidence={"bytes": 50 * GB}, catalog=cat)
    assert r["status"] == "refused" and "evidence does not match" in r["why"]
    it2 = old_build(tmp_path / "b")
    r = sg.suggest(str(it2), reason="r", suggested_by="a",
                   evidence={"idle_hours": 1000}, catalog=cat)
    assert r["status"] == "refused"
    counts = {x["agent"]: x for x in sg.trust(catalog=cat)}
    assert counts["a"]["refused"] == 2 and counts["a"]["trust"] == 0.5


def test_card_hook_receives_proposal_id_fact(tmp_path: Path, cat):
    seen: list = []
    sg.set_card_hook(lambda spec: seen.append(spec) or "card-9")
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="dead session", suggested_by="a", catalog=cat)
    assert r["status"] == "pending-card" and r["card_id"] == "card-9"
    assert f"proposal_id: {r['id']}" in seen[0]["facts"]
    assert cat.get_suggestion(r["id"])["card_raised"] == "card-9"
    sg.set_card_hook(lambda spec: 1 / 0)
    it2 = old_build(tmp_path / "x")
    r2 = sg.suggest(str(it2), reason="r", suggested_by="a", catalog=cat)
    assert r2["status"] == "pending-card" and r2["card_id"] is None
    assert "card hook failed" in cat.get_suggestion(r2["id"])["why"]


# -- resolve -------------------------------------------------------------------------

def test_card_approval_refused_while_store_does_not_attest(tmp_path: Path, cat, monkeypatch):
    assert manage.STORE_ATTESTS_ANSWERER is False
    monkeypatch.setenv(manage.OWNERS_ENV, "owner")
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="r", suggested_by="a", action="delete", catalog=cat)
    out = sg.resolve_suggestion(r["id"], "approve", card=attested_card("c1", r["id"]),
                                catalog=cat)
    assert not out["ok"] and "does not attest" in out["why"]
    assert cat.get_suggestion(r["id"])["status"] == "pending-card"
    out = sg.resolve_suggestion(r["id"], "approve", catalog=cat)
    assert not out["ok"] and "CARD-ONLY" in out["why"]


def test_card_approval_uses_the_manage_checks(tmp_path: Path, cat, monkeypatch):
    monkeypatch.setattr(manage, "STORE_ATTESTS_ANSWERER", True)
    monkeypatch.setenv(manage.OWNERS_ENV, "owner")
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="r", suggested_by="a", action="delete", catalog=cat)
    wrong = sg.resolve_suggestion(r["id"], "approve",
                                  card=attested_card("c1", r["id"] + 1000), catalog=cat)
    assert not wrong["ok"] and "proposal_id" in wrong["why"]
    via_api = dict(attested_card("c1", r["id"]), answered_via="api")
    assert not sg.resolve_suggestion(r["id"], "approve", card=via_api, catalog=cat)["ok"]
    ok = sg.resolve_suggestion(r["id"], "approve", card=attested_card("c1", r["id"]),
                               catalog=cat)
    assert ok["ok"] and ok["status"] == "approved"
    s = cat.get_suggestion(r["id"])
    assert s["card_id"] == "c1" and s["approved_at"]


def test_reject_needs_no_card_and_counts_against_trust(tmp_path: Path, cat):
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="r", suggested_by="a", catalog=cat)
    out = sg.resolve_suggestion(r["id"], "reject", catalog=cat)
    assert out["ok"] and out["status"] == "rejected"
    assert sg.trust("a", catalog=cat)[0]["trust"] == pytest.approx(1 / 3, abs=1e-4)
    again = sg.resolve_suggestion(r["id"], "reject", catalog=cat)
    assert not again["ok"]
    assert sg.resolve_suggestion(99999, "approve", catalog=cat)["status"] == "missing"


def test_expired_suggestions(tmp_path: Path, cat):
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="r", suggested_by="a", ttl_days=0.00001, catalog=cat)
    time.sleep(1.1)
    rows = sg.suggestions(catalog=cat)
    assert rows[0]["status"] == "expired"
    assert sg.suggestions("expired", catalog=cat)[0]["id"] == r["id"]
    assert not sg.resolve_suggestion(r["id"], "reject", catalog=cat)["ok"]


# -- apply ---------------------------------------------------------------------------

def _auto(tmp_path: Path, cat, name: str = "p") -> tuple[dict, Path]:
    seed_trust(cat, "trusted", applied=5)
    it = old_build(tmp_path / name)
    r = sg.suggest(str(it), reason="dead", suggested_by="trusted",
                   evidence={"bytes": 136}, catalog=cat)
    assert r["status"] == "auto-approved", r
    return r, it


def test_apply_dry_run_changes_nothing(tmp_path: Path, cat):
    r, it = _auto(tmp_path, cat)
    rec = sg.apply_suggestions(dry_run=True, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["exit_code"] == 0 and rec["items"][0]["outcome"] == "dry-run"
    assert it.exists() and not (tmp_path / "shelf").exists()
    assert cat.get_suggestion(r["id"])["status"] == "auto-approved"


def test_apply_quarantines_harvests_ledgers_and_revert_costs_trust(tmp_path: Path, cat):
    r, it = _auto(tmp_path, cat)
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["exit_code"] == 0 and rec["applied"] == 1, rec
    assert not it.exists() and rec["bytes_freed"] == 0 and rec["bytes_quarantined"] == 136
    assert next((tmp_path / "shelf").rglob("NOTES.md")).read_bytes() == b"# notes\n"
    s = cat.get_suggestion(r["id"])
    assert s["status"] == "applied" and s["quarantine"] and s["outcome"] == "applied"
    assert any(x["proposal_id"] == r["id"] and x["outcome"] == "applied"
               for x in cat.list_ledger())
    before = sg.trust("trusted", catalog=cat)[0]["trust"]
    out = sg.revert_suggestion(r["id"], catalog=cat)
    assert out["ok"] and (it / "a.o").exists()
    after = sg.trust("trusted", catalog=cat)[0]
    assert after["reverted"] == 1 and after["trust"] < before - 0.3


def test_revert_by_the_generic_path_is_detected(tmp_path: Path, cat):
    r, it = _auto(tmp_path, cat)
    sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    [q] = [x for x in list_quarantine([it.parent]) if "suggest-" in x["entry"]]
    revert(q["entry"])
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["reverts_detected"] == 1
    assert cat.get_suggestion(r["id"])["status"] == "reverted"


def test_apply_refuses_size_drift(tmp_path: Path, cat):
    r, it = _auto(tmp_path, cat)
    _mk(it / "a.o", b"1" * 999, 30)
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["drifted"] == 1 and it.exists()
    s = cat.get_suggestion(r["id"])
    assert s["status"] == "drifted" and "size" in s["why"]


def test_apply_refuses_mtime_drift_and_live_writes(tmp_path: Path, cat):
    r, it = _auto(tmp_path, cat)
    _age(it / "a.o", 10)  # newer than recorded, still outside the live window
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["drifted"] == 1 and it.exists()
    assert "mtime" in cat.get_suggestion(r["id"])["why"]
    r2, it2 = _auto(tmp_path, cat, "q")
    _mk(it2 / "live.tmp", b"z", 0.01)
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert it2.exists() and cat.get_suggestion(r2["id"])["status"] == "drifted"
    assert "live window" in cat.get_suggestion(r2["id"])["why"]


@needs_git
def test_apply_revalidates_git(tmp_path: Path, cat):
    seed_trust(cat, "trusted", applied=5)
    work = make_pushed_repo(tmp_path)
    b = old_build(work)
    r = sg.suggest(str(b), reason="dead", suggested_by="trusted",
                   evidence={"bytes": 136}, catalog=cat)
    assert r["status"] == "auto-approved"
    (work / "wip.txt").write_text("x", encoding="utf-8")
    sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert b.exists() and cat.get_suggestion(r["id"])["status"] == "drifted"


def test_auto_approval_is_withdrawn_when_trust_falls(tmp_path: Path, cat):
    r, it = _auto(tmp_path, cat)
    seed_trust(cat, "trusted", applied=0, rejected=10)
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["demoted"] == 1 and it.exists()
    assert cat.get_suggestion(r["id"])["status"] == "pending-card"


def test_card_approved_delete_harvests_then_deletes(tmp_path: Path, cat, monkeypatch):
    monkeypatch.setattr(manage, "STORE_ATTESTS_ANSWERER", True)
    monkeypatch.setenv(manage.OWNERS_ENV, "owner")
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="dead", suggested_by="a", action="delete", catalog=cat)
    assert sg.resolve_suggestion(r["id"], "approve", card=attested_card("c", r["id"]),
                                 catalog=cat)["ok"]
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["applied"] == 1 and rec["bytes_freed"] == 136 and not it.exists()
    assert next((tmp_path / "shelf").rglob("NOTES.md")).exists()
    assert sg.trust("a", catalog=cat)[0]["applied"] == 1


def test_archive_waits_for_a_hook_then_applies(tmp_path: Path, cat, monkeypatch):
    monkeypatch.setattr(manage, "STORE_ATTESTS_ANSWERER", True)
    monkeypatch.setenv(manage.OWNERS_ENV, "owner")
    it = old_build(tmp_path)
    r = sg.suggest(str(it), reason="cold", suggested_by="a", action="archive", catalog=cat)
    sg.resolve_suggestion(r["id"], "approve", card=attested_card("c", r["id"]), catalog=cat)
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["items"][0]["outcome"] == "waiting" and it.exists()
    got: list = []
    sg.set_archive_hook(lambda p, s: got.append(p) or {"ok": True, "detail": "strata:x"})
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["applied"] == 1 and got and not it.exists()
    assert cat.get_suggestion(r["id"])["quarantine"]


def test_apply_purges_old_suggestion_quarantine(tmp_path: Path, cat, monkeypatch):
    r, it = _auto(tmp_path, cat)
    sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    monkeypatch.setattr(sg, "PURGE_AFTER_S", 0.0)
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["purged"] and rec["purged"][0]["outcome"] == "purged"
    assert rec["bytes_freed"] >= 136  # the payload + the entry's ORIGIN file
    assert cat.get_suggestion(r["id"])["purged_at"]
    assert not sg.revert_suggestion(r["id"], catalog=cat)["ok"]


def test_apply_keeps_item_when_shelf_drive_is_under_its_floor(tmp_path, cat, monkeypatch):
    r, it = _auto(tmp_path, cat)
    monkeypatch.setenv("AWSTORAGE_FLOORS", f"{tmp_path}=999999999")
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["harvest_skipped"] and it.exists() and rec["exit_code"] == 0
    assert "shelf drive low" in rec["items"][0]["reason"]
    assert cat.get_suggestion(r["id"])["status"] == "auto-approved"


# -- sweep: shelf floor + agent-worktrees --------------------------------------------

def _rule(root: Path, **over) -> dict:
    r = {"name": "t", "paths": [root.as_posix() + "/*"], "class": "build-temp",
         "max_idle": "10h", "action": "quarantine", "live_guard": {"window": "2h"}}
    r.update(over)
    return r


def test_sweep_keeps_item_when_shelf_drive_low(tmp_path: Path):
    root = tmp_path / "scratch"
    _mk(root / "s1" / "REPORT.md", b"# r\n", 30)
    rec = sw.sweep(policy={"retention": [_rule(root)]}, dry_run=False,
                   harvest_to=tmp_path / "shelf", seal=False, floors={str(tmp_path): 40},
                   disk_free=lambda _p: 0)
    assert rec["exit_code"] == 0 and rec["items_removed"] == 0
    assert (root / "s1" / "REPORT.md").exists() and not (tmp_path / "shelf").exists()
    assert rec["harvest_skipped"][0]["why"].startswith("shelf drive low")
    assert rec["items"][0]["outcome"] == "harvest-skipped"


def test_sweep_delete_on_the_shelf_drive_still_harvests(tmp_path: Path):
    root = tmp_path / "scratch"
    _mk(root / "s1" / "REPORT.md", b"# r\n", 30)
    rec = sw.sweep(policy={"retention": [_rule(root, action="delete")]}, dry_run=False,
                   harvest_to=tmp_path / "shelf", seal=False, floors={str(tmp_path): 40},
                   disk_free=lambda _p: 0)
    assert rec["items_removed"] == 1 and next((tmp_path / "shelf").rglob("REPORT.md"))


def test_sweep_bad_floors_is_could_not_judge(tmp_path: Path):
    rec = sw.sweep(policy={"retention": [_rule(tmp_path)]}, floors="C:40")
    assert rec["exit_code"] == 2 and "DRIVE=GB" in rec["could_not_judge"][0]


def test_agent_worktrees_preset_needs_policy_paths(tmp_path: Path):
    with pytest.raises(sw.SweepConfigError, match="come from --policy"):
        sw.resolve_rules(["agent-worktrees"])
    [r] = sw.resolve_rules(["agent-worktrees"],
                           {"retention": [{"name": "agent-worktrees",
                                           "paths": ["C:/wt/*"]}]})
    assert r["require_git_clean"] and r["max_idle"] == 7 * 86400
    assert r["action"] == "quarantine" and r["paths"] == ["C:/wt/*"]
    with pytest.raises(sw.SweepConfigError, match="quarantine only"):
        sw.validate_rule({**_rule(tmp_path), "require_git_clean": True, "action": "delete"})


@needs_git
def test_agent_worktrees_sweeps_only_clean_pushed_worktree_roots(tmp_path: Path):
    main_repo = make_pushed_repo(tmp_path, "main")
    wts = tmp_path / "wts"
    git(main_repo, "worktree", "add", "-q", str(wts / "clean"), "-b", "c1")
    git(main_repo, "worktree", "add", "-q", str(wts / "dirty"), "-b", "d1")
    (wts / "dirty" / "local.txt").write_text("only here", encoding="utf-8")
    git(main_repo, "worktree", "add", "-q", str(wts / "ahead"), "-b", "a1")
    (wts / "ahead" / "x.txt").write_text("x", encoding="utf-8")
    git(wts / "ahead", "add", "x.txt")
    git(wts / "ahead", "commit", "-qm", "unpushed")
    (wts / "plain").mkdir()
    _mk(wts / "plain" / "f.txt", b"f", 300)
    _age_tree(wts, 10 * 24)
    pol = {"retention": [{"name": "agent-worktrees", "paths": [wts.as_posix() + "/*"]}]}
    rec = sw.sweep(["agent-worktrees"], policy=pol, dry_run=False,
                   harvest_to=tmp_path / "shelf", seal=False)
    out = {Path(i["path"]).name: i["outcome"] for i in rec["items"]}
    assert out == {"clean": "applied", "dirty": "skipped-git", "ahead": "skipped-git",
                   "plain": "skipped-git"}, rec["items"]
    assert not (wts / "clean").exists() and (wts / "dirty" / "local.txt").exists()
    assert (wts / "ahead").exists() and (wts / "plain").exists()
    assert len(rec["skipped_git"]) == 3


# -- space: floors, place, watch, shelf prune ----------------------------------------

def test_parse_floors_and_size():
    f = space.parse_floors("C:=40, D:=60;E=30")
    assert set(f) == ({"C:", "D:", "E:"} if os.name == "nt" else {"C:/", "D:/", "E:/"})
    assert list(f.values()) == [40.0, 60.0, 30.0]
    for bad in ("C:40", "C:=x", "C:=-1", "=5"):
        with pytest.raises(space.FloorsError):
            space.parse_floors(bad)
    assert space.parse_size("90GB") == 90 * GB and space.parse_size("1.5T") == int(1.5 * 2**40)
    assert space.parse_size("500M") == 500 * 2**20 and space.parse_size(4096) == 4096
    with pytest.raises(space.FloorsError):
        space.parse_size("lots")


def test_place_ranks_and_refuses_below_floor(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    free = {str(a): 200 * GB, str(b): 120 * GB}
    rows = space.place("90GB", {str(a): 40, str(b): 40}, drives=[str(a), str(b)],
                       disk_free=lambda p: free[str(Path(p))])
    # a and b share a real volume, so each floor lookup hits the first floor key --
    # the free space is what the fake says per path.
    assert rows[0]["ok"] and rows[0]["free_after"] == 110 * GB
    assert not rows[1]["ok"] and "REFUSED" in rows[1]["why"]
    rows = space.place(10 * GB, {str(a): 40}, source=str(a / "data"), drives=[str(a)],
                       disk_free=lambda p: 200 * GB)
    assert not rows[0]["ok"] and "source drive" in rows[0]["why"]


def test_watch_fast_path_walks_nothing(tmp_path: Path, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("watch walked a tree on the fast path")

    monkeypatch.setattr(sw, "measure", boom)
    monkeypatch.setattr(sw, "walk_no_follow", boom)
    called: list = []
    t0 = time.monotonic()
    rec = space.watch_once({str(tmp_path): 1.0}, sweep_fn=lambda *a, **k: called.append(1),
                           alerts_path=tmp_path / "alerts.jsonl",
                           receipt=tmp_path / "w.json")
    assert time.monotonic() - t0 < 2.0
    assert rec["exit_code"] == 0 and not called and not rec["under"]
    assert not (tmp_path / "alerts.jsonl").exists()
    saved = json.loads((tmp_path / "w.json").read_text(encoding="utf-8"))
    d = saved["drives"][str(tmp_path)]
    assert d["free_before"] > 0 and d["under_before"] is False


def test_watch_under_floor_runs_real_emergency_sweep_and_alerts(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    _mk(scratch / "dead" / "big.bin", b"\x00" * 4096, 30)
    marker = tmp_path / "alert-cmd.txt"
    script = tmp_path / "alert.py"
    script.write_text("import sys, pathlib\n"
                      f"pathlib.Path({str(marker)!r}).write_text(sys.argv[-1])\n",
                      encoding="utf-8")
    monkeypatch.setenv("AWSTORAGE_ALERT_CMD", json.dumps([sys.executable, str(script)]))
    freed = {"n": 0}

    def disk_free(_p):
        return 0 if freed["n"] == 0 else 100 * GB

    pol = {"retention": [_rule(scratch, name="scr", emergency_delete=True)]}
    real_sweep = sw.sweep

    def sweep_and_mark(*a, **k):
        r = real_sweep(*a, **k)
        freed["n"] = r["bytes_freed"]
        return r

    rec = space.watch_once({str(tmp_path): 40.0}, yes=True, rules=("scr",), policy=pol,
                           harvest_to=tmp_path / "shelf", disk_free=disk_free,
                           sweep_fn=sweep_and_mark, alerts_path=tmp_path / "al.jsonl",
                           receipt=tmp_path / "w.json")
    d = rec["drives"][str(tmp_path)]
    assert d["under_before"] and not d["under_after"] and rec["exit_code"] == 0, rec
    assert d["sweep"]["emergency_deleted"] == 1 and not (scratch / "dead").exists()
    alert = json.loads((tmp_path / "al.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert alert["kind"] == "awstorage.floor" and alert["acted"] is True
    assert json.loads(marker.read_text(encoding="utf-8"))["drive"] == str(tmp_path)


def test_watch_plan_only_without_yes_and_bad_floors(tmp_path: Path):
    scratch = tmp_path / "scratch"
    _mk(scratch / "dead" / "big.bin", b"\x00" * 4096, 30)
    pol = {"retention": [_rule(scratch, name="scr", emergency_delete=True)]}
    rec = space.watch_once({str(tmp_path): 40.0}, rules=("scr",), policy=pol,
                           harvest_to=tmp_path / "shelf", disk_free=lambda _p: 0,
                           alerts_path=tmp_path / "al.jsonl")
    assert rec["exit_code"] == 1 and (scratch / "dead").exists()
    assert rec["drives"][str(tmp_path)]["sweep"]["items_eligible"] == 1
    assert space.watch_once("C:40")["exit_code"] == 2
    assert space.watch_once("")["exit_code"] == 2


def test_prune_shelf(tmp_path: Path):
    shelf = tmp_path / "shelf"
    old = shelf / "agent-scratch" / "2020-01-01" / "item"
    new_day = time.strftime("%Y-%m-%d")
    new = shelf / "agent-scratch" / new_day / "item"
    other = shelf / "agent-scratch" / "notes"
    for d in (old, new, other):
        _mk(d / "f.md", b"x" * 10, 0)
    r = space.prune_shelf(shelf, older_than_s=30 * 86400, dry_run=True)
    assert len(r["removed"]) == 1 and old.exists()
    r = space.prune_shelf(shelf, older_than_s=30 * 86400, dry_run=False)
    assert r["bytes_freed"] == 10 and not old.exists() and new.exists() and other.exists()


# -- CLI -----------------------------------------------------------------------------

def test_cli_suggest_list_resolve_apply_trust(tmp_path: Path, capsys):
    db = str(tmp_path / "c.db")
    it = old_build(tmp_path / "p")
    assert main(["suggest", str(it), "--reason", "dead", "--by", "cli-agent",
                 "--evidence", '{"bytes": 136}', "--catalog", db, "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["status"] == "pending-card"
    assert main(["suggest", str(tmp_path / "nope"), "--reason", "x", "--by", "a",
                 "--catalog", db]) == 1
    assert main(["suggest", str(it), "--reason", "x", "--by", "a", "--evidence", "{bad",
                 "--catalog", db]) == 2
    capsys.readouterr()
    assert main(["suggestions", "--catalog", db, "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 2
    assert main(["suggestion", "approve", str(r["id"]), "--catalog", db]) == 1
    assert main(["suggestion", "reject", str(r["id"]), "--catalog", db]) == 0
    assert main(["apply-suggestions", "--catalog", db, "--json",
                 "--receipt", str(tmp_path / "r.json")]) == 0
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["dry_run"] is True
    capsys.readouterr()
    assert main(["trust", "--catalog", db]) == 0
    assert "cli-agent" in capsys.readouterr().out


def test_cli_place_watch_shelf(tmp_path: Path, capsys):
    assert main(["place", "--size", "1PB", "--floors", f"{tmp_path}=1",
                 "--to", str(tmp_path)]) == 1
    assert main(["place", "--size", "1KB", "--floors", f"{tmp_path}=0",
                 "--to", str(tmp_path)]) == 0
    assert main(["watch", "--floors", f"{tmp_path}=0", "--once", "--no-catalog",
                 "--alerts", str(tmp_path / "a.jsonl")]) == 0
    assert main(["watch", "--floors", "C:40", "--once"]) == 2
    (tmp_path / "shelf" / "r" / "2020-01-01").mkdir(parents=True)
    assert main(["shelf", "prune", "--older-than", "30d", "--shelf",
                 str(tmp_path / "shelf"), "--yes"]) == 0
    assert not (tmp_path / "shelf" / "r" / "2020-01-01").exists()


def test_public_api_is_exported():
    for n in ("suggest", "suggestions", "resolve_suggestion", "apply_suggestions", "trust",
              "watch_once", "place", "prune_shelf", "revert_suggestion"):
        assert hasattr(awstorage, n) and n in awstorage.__all__
    # The suggestions API arrived in 0.4.0; the exact release pin lives in test_sweep.py, so a
    # later release (0.5.0 added relocate) does not fail this feature test.
    assert tuple(int(x) for x in awstorage.__version__.split(".")[:3]) >= (0, 4, 0)
