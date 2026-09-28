"""awstorage.manage contract tests: every manage/share action is dry-run by default,
refuses without a HUMAN card approving THIS proposal, re-verifies sha256 before it
acts, is revertible byte-for-byte, and writes a ledger row -- including refusals."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from awstorage import manage
from awstorage.catalog import Catalog
from awstorage.policy import ApplyRefused, list_quarantine


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _card(pid: int, **over) -> dict:
    card = {"id": "d-1", "title": f"awstorage #{pid}: dedup?", "status": "answered",
            "answer": "approve", "answered_via": "popup",
            "facts": manage.card_facts(pid)}
    card.update(over)
    return card


@pytest.fixture
def env(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    cat = Catalog(tmp_path / "cat.db")
    yield root, cat
    cat.close()


def _dupes(root: Path, data: bytes = b"same-bytes" * 100, n: int = 3) -> tuple[list[Path], dict]:
    paths = []
    for i in range(n):
        p = root / ("a" * (i + 1)) / "f.bin"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        paths.append(p)
    group = {"sha256": _sha(data), "size": len(data),
             "paths": [{"node": "n1", "path": str(p)} for p in paths]}
    return paths, group


def _submit(cat: Catalog, props: list) -> list[int]:
    with manage.ManageStore(cat) as st:
        return st.submit(props)


def _ledger(cat: Catalog, pid: int) -> list[dict]:
    return [r for r in cat.list_ledger() if r["proposal_id"] == pid]


# -- propose --------------------------------------------------------------------------

def test_propose_dedup_picks_deterministic_keeper_and_skips_other_nodes(env):
    root, _ = env
    paths, group = _dupes(root)
    group["paths"].append({"node": "other", "path": "/elsewhere/f.bin"})
    [p] = manage.propose_dedup([group], node="n1")
    assert p.params["keeper"] == str(paths[0])
    assert p.params["copies"] == [str(paths[1]), str(paths[2])]
    assert p.bytes == group["size"] * 2
    assert manage.propose_dedup([group], node="nobody") == []


def test_propose_share_requires_owner():
    with pytest.raises(ValueError):
        manage.propose_share("n1", "/x", owner="")


# -- card-only ------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    None,
    {"status": "open", "answer": None},
    {"answer": "snooze"},
    {"answered_via": "agent"},
    {"answered_via": "deadline"},
    {"facts": ["proposal_id: 999"], "title": "awstorage #999: other"},
])
def test_refuses_without_a_human_approve_of_this_proposal(env, bad):
    root, cat = env
    _, group = _dupes(root)
    [pid] = _submit(cat, manage.propose_dedup([group], node="n1"))
    card = None if bad is None else _card(pid, **bad)
    with pytest.raises(ApplyRefused):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=card, dry_run=False)
    rows = _ledger(cat, pid)
    assert rows and rows[0]["outcome"] == "refused"
    # nothing moved
    assert not (root / ".awstorage-quarantine").exists()


def test_title_prefix_does_not_match_a_longer_id(env):
    with pytest.raises(ApplyRefused):
        manage.verify_card(_card(1, facts=[], title="awstorage #12: x"), 1)


def test_self_service_only_covers_own_share(env, tmp_path):
    root, cat = env
    f = root / "doc.txt"
    f.write_text("hello")
    _, group = _dupes(root)
    [dpid] = _submit(cat, manage.propose_dedup([group], node="n1"))
    with pytest.raises(ApplyRefused, match="share.awshare only"):
        manage.apply_manage(dpid, catalog=cat, roots=[root], self_service_owner="t:u",
                            dry_run=False)
    [spid] = _submit(cat, [manage.propose_share("workspace", str(f), owner="t:alice")])
    with pytest.raises(ApplyRefused, match="does not own"):
        manage.apply_manage(spid, catalog=cat, roots=[root], self_service_owner="t:mallory",
                            dry_run=False, share_hook=lambda *a, **k: {"x": 1})


# -- dedup ----------------------------------------------------------------------------

def test_dedup_dry_run_is_default_and_changes_nothing(env):
    root, cat = env
    paths, group = _dupes(root)
    [pid] = _submit(cat, manage.propose_dedup([group], node="n1"))
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid))
    assert out["outcome"] == "dry-run"
    assert all(p.is_file() for p in paths)
    assert not (root / ".awstorage-quarantine").exists()
    assert _ledger(cat, pid)[0]["outcome"] == "dry-run"
    assert cat.get_proposal(pid)["status"] == "proposed"


def test_quarantine_copies_then_revert_byte_for_byte(env):
    root, cat = env
    paths, group = _dupes(root)
    [pid] = _submit(cat, manage.propose_dedup([group], node="n1"))
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert out["outcome"] == "applied"
    assert paths[0].is_file() and not paths[1].exists() and not paths[2].exists()
    assert len(list_quarantine([root])) == 2
    assert cat.get_proposal(pid)["status"] == "applied"
    # second apply is refused (idempotent)
    with pytest.raises(ApplyRefused, match="already applied"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    rv = manage.revert_proposal(pid, catalog=cat)
    assert rv["outcome"] == "reverted"
    for p in paths:
        assert _sha(p.read_bytes()) == group["sha256"]
    assert list_quarantine([root]) == []
    assert [r["outcome"] for r in _ledger(cat, pid)][0] == "reverted"


def test_hardlink_reverifies_sha_and_skips_drifted_copy(env):
    root, cat = env
    paths, group = _dupes(root)
    [pid] = _submit(cat, manage.propose_dedup([group], node="n1", action="dedup.hardlink"))
    paths[2].write_bytes(b"changed after the scan")
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    by = {r["path"]: r["result"] for r in out["results"]}
    assert by[str(paths[1])] == "hardlinked"
    assert by[str(paths[2])] == "drifted"
    assert os.path.samefile(paths[0], paths[1])
    assert paths[2].read_bytes() == b"changed after the scan"
    manage.revert_proposal(pid, catalog=cat)
    assert not os.path.samefile(paths[0], paths[1])
    assert _sha(paths[1].read_bytes()) == group["sha256"]


def test_keeper_drift_refuses_whole_proposal(env):
    root, cat = env
    paths, group = _dupes(root)
    [pid] = _submit(cat, manage.propose_dedup([group], node="n1", action="dedup.hardlink"))
    paths[0].write_bytes(b"keeper edited")
    with pytest.raises(ApplyRefused, match="keeper"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert paths[1].is_file() and paths[2].is_file()
    assert _ledger(cat, pid)[0]["outcome"] == "refused"


def test_paths_outside_roots_refused(env, tmp_path):
    root, cat = env
    other = tmp_path / "other"
    other.mkdir()
    paths, group = _dupes(other)
    [pid] = _submit(cat, manage.propose_dedup([group], node="n1"))
    with pytest.raises(ApplyRefused, match="outside the declared roots"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert all(p.is_file() for p in paths)


# -- archive --------------------------------------------------------------------------

def test_archive_needs_verified_remote_sha_then_quarantines_and_reverts(env):
    root, cat = env
    f = root / "big.iso"
    f.write_bytes(b"iso" * 1000)
    sha = _sha(f.read_bytes())
    [pid] = _submit(cat, [manage.propose_archive("n1", str(f), strata_path="aither://cold/x",
                                                 sha256=sha)])
    calls = []

    def liar(path, **kw):
        calls.append(kw)
        return {"sha256": "0" * 64}

    with pytest.raises(ApplyRefused, match="did not confirm"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                            strata_hook=liar)
    assert f.is_file()
    # dry-run never calls the hook
    manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), strata_hook=liar)
    assert len(calls) == 1

    def honest(path, **kw):
        assert kw["sha256"] == sha and kw["tier"] == "cold"
        return {"sha256": sha}

    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                              strata_hook=honest)
    assert out["outcome"] == "applied" and not f.exists()
    manage.revert_proposal(pid, catalog=cat)
    assert _sha(f.read_bytes()) == sha


def test_archive_refuses_a_file_changed_since_proposal(env):
    root, cat = env
    f = root / "a.bin"
    f.write_bytes(b"v1")
    [pid] = _submit(cat, [manage.propose_archive("n1", str(f), strata_path="aither://cold/a",
                                                 sha256=_sha(b"v0"))])
    with pytest.raises(ApplyRefused, match="changed since"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                            strata_hook=lambda p, **k: {"sha256": _sha(b"v1")})


# -- share ----------------------------------------------------------------------------

def test_share_local_awshare_publish_list_and_revert(env, tmp_path):
    pytest.importorskip("awshare")
    root, cat = env
    d = root / "proj"
    d.mkdir()
    (d / "a.txt").write_text("alpha")
    share, unshare = manage.local_awshare_hook(tmp_path / "shares")
    [pid] = _submit(cat, [manage.propose_share("workspace", str(d), owner="t1:alice")])
    out = manage.apply_manage(pid, catalog=cat, roots=[root], self_service_owner="t1:alice",
                              dry_run=False, share_hook=share)
    h = out["handle"]
    assert Path(h["manifest"]).is_file() and h["files"] == 1
    # the source is never modified by publish
    assert sorted(x.name for x in d.iterdir()) == ["a.txt"]
    with manage.ManageStore(cat) as st:
        assert [s["proposal_id"] for s in st.list_shares("t1:alice")] == [pid]
        assert st.list_shares("t1:bob") == []
    manage.revert_proposal(pid, catalog=cat, unshare_hook=unshare)
    assert not Path(h["out_dir"]).exists()
    with manage.ManageStore(cat) as st:
        assert st.list_shares("t1:alice") == []


def test_share_platform_disk_needs_card(env):
    root, cat = env
    f = root / "x.txt"
    f.write_text("x")
    [pid] = _submit(cat, [manage.propose_share("n1", str(f), owner="platform:op")])
    hook_calls = []
    with pytest.raises(ApplyRefused, match="CARD-ONLY"):
        manage.apply_manage(pid, catalog=cat, roots=[root], dry_run=False,
                            share_hook=lambda *a, **k: hook_calls.append(1) or {"h": 1})
    assert hook_calls == []
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                              share_hook=lambda *a, **k: {"h": 1})
    assert out["outcome"] == "applied"


def test_cli_apply_dry_run_default(env, tmp_path, capsys):
    import json

    root, cat = env
    _, group = _dupes(root)
    [pid] = _submit(cat, manage.propose_dedup([group], node="n1"))
    cf = tmp_path / "card.json"
    cf.write_text(json.dumps(_card(pid)))
    rc = manage.main(["--db", str(cat.path), "apply", str(pid), "--root", str(root),
                      "--card", str(cf)])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "dry-run"
