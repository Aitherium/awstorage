"""awstorage.manage contract tests (contract A6/A7, review round 1).

Every card action is dry-run by default, refuses without an OWNER card carrying the
fact `proposal_id: <id>` and a SIGNED answer receipt (awstorage.attest), is platform-nodes-only, re-verifies every member (size,
mtime, sha256 -- keeper AND victim for a hardlink), refuses the guards and any git
tree up to the filesystem root whatever the card says, quarantines with ONE
same-volume os.replace (no copy fallback), is revertible byte-for-byte, and writes
one ledger row per member plus a proposal row.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from awstorage import manage, policy
from awstorage.catalog import Catalog
from awstorage.policy import ApplyRefused

from tests.attest_util import pubkey_env, sign_card


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


OWNER = "owner@test"
#: The catalog of the running test (set by the `env` fixture), so `_card` can raise
#: the REAL card facts -- including `content_sha256` -- for a submitted proposal.
_ENV_CAT: list = []


def _facts(pid: int) -> list[str]:
    if _ENV_CAT:
        try:
            with manage.ManageStore(_ENV_CAT[0]) as st:
                return manage.card_spec(st.load(pid))["facts"]
        except Exception:  # noqa: BLE001 -- not a submitted proposal: the bare id fact
            pass
    return manage.card_facts(pid)


def _card(pid: int, _r: dict | None = None, _sign: bool = True, **over) -> dict:
    """An owner's answered card, SIGNED as it stands; ``over`` then tampers with the
    card (after signing) and ``_r`` changes what was signed."""
    card = {"id": f"d-{pid}", "title": f"awstorage #{pid}: dedup?", "status": "answered",
            "answer": "approve", "answered_via": "desk", "answered_by": OWNER,
            "facts": _facts(pid)}
    if _sign:
        sign_card(card, **(_r or {}))
    card.update(over)
    return card


@pytest.fixture(autouse=True)
def attested_store(monkeypatch, tmp_path):
    """One owner, the test signing key provisioned, and a throwaway default catalog
    (the nonce store for calls that pass none)."""
    monkeypatch.setenv(manage.OWNERS_ENV, OWNER)
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "default-catalog.db"))
    pubkey_env(monkeypatch)


@pytest.fixture
def env(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    cat = Catalog(tmp_path / "cat.db")
    _ENV_CAT[:] = [cat]
    yield root, cat
    _ENV_CAT.clear()
    cat.close()


def _row(p: Path, node: str = "n1") -> dict:
    st = os.stat(p)
    return {"node": node, "path": str(p), "bytes": st.st_size, "mtime_ns": st.st_mtime_ns,
            "sha256": _sha(p.read_bytes()), "dev": st.st_dev, "ino": st.st_ino,
            "nlink": st.st_nlink}


def _dupes(root: Path, data: bytes = b"same-bytes" * 100, n: int = 3) -> tuple[list[Path], dict]:
    paths = []
    for i in range(n):
        p = root / ("a" * (i + 1)) / "f.bin"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        paths.append(p)
    group = {"sha256": _sha(data), "bytes": len(data), "paths": [_row(p) for p in paths]}
    return paths, group


def _submit(cat: Catalog, props: list, approve: bool = True) -> list[int]:
    """Submit, and (by default) approve each with card `d-<id>` the way the card
    consumer does -- apply only ever runs on an approved proposal."""
    with manage.ManageStore(cat) as st:
        ids = st.submit(props)
        if approve:
            for pid in ids:
                assert st.mark_approved(pid, f"d-{pid}")
        return ids


def _ledger(cat: Catalog, pid: int) -> list[dict]:
    return [r for r in cat.list_ledger(limit=1000) if r["proposal_id"] == pid]


def _one(cat: Catalog, group: dict, action: str = "quarantine-copy",
         approve: bool = True) -> int:
    [pid] = _submit(cat, manage.propose_dupes([group], node="n1", action=action),
                    approve=approve)
    return pid


# -- vocabulary ------------------------------------------------------------------------

def test_one_closed_vocabulary():
    assert set(policy.CARD_ACTIONS) == {"hardlink", "quarantine-copy", "archive", "share"}
    assert set(policy.CARD_ACTIONS) <= set(policy.ACTIONS)
    assert not hasattr(manage, "MANAGE_ACTIONS")


@pytest.mark.parametrize("action", policy.CARD_ACTIONS)
def test_policy_apply_refuses_card_actions(tmp_path, action):
    f = tmp_path / "x"
    f.write_text("x")
    with pytest.raises(ApplyRefused, match="card-only"):
        policy.apply({"node": "n1", "path": str(f), "action": action, "bytes": 1,
                      "cls": "dedup", "status": "approved"}, roots=[tmp_path], dry_run=False)
    assert f.exists()


def test_legacy_dotted_rows_load_as_the_closed_vocabulary(env):
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group)
    with cat._db:
        cat._db.execute("UPDATE proposals SET action = 'dedup.quarantine_copies' WHERE id = ?",
                        (pid,))
    with manage.ManageStore(cat) as st:
        assert st.load(pid).action == "quarantine-copy"


# -- propose ---------------------------------------------------------------------------

def test_propose_dupes_deterministic_keeper_actionable_members_only(env):
    root, cat = env
    paths, group = _dupes(root, n=5)
    group["paths"][3]["git_root"] = str(root)  # inside a repo: not actionable
    group["paths"][4]["nlink"] = 2              # already linked: not actionable
    group["paths"].append({**group["paths"][1]})  # the same (dev, ino) twice = one file
    group["paths"].append({"node": "n2", "path": "/elsewhere/f.bin"})
    [p] = manage.propose_dupes([group], node="n1")
    assert p.params["keep"]["path"] == str(paths[0])
    assert [m["path"] for m in p.members] == [str(paths[1]), str(paths[2])]
    assert p.bytes == 2 * len(b"same-bytes" * 100)
    assert p.action == "quarantine-copy" and p.tenant == "platform"
    assert {"path", "bytes", "mtime_ns", "sha256", "dev", "ino"} <= set(p.members[0])


def test_propose_dupes_drops_sensitive_never_and_other_volumes(env):
    root, cat = env
    paths, group = _dupes(root, n=3)
    group["paths"][1]["path"] = str(root / ".ssh" / "f.bin")
    group["paths"][2]["dev"] = 999999
    assert manage.propose_dupes([group], node="n1") == []
    with pytest.raises(ValueError):
        manage.propose_dupes([group], node="n1", action="delete")


def test_proposal_shape_round_trips(env):
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group)
    with manage.ManageStore(cat) as st:
        p = st.load(pid)
    assert p.members and p.expires_at and p.tenant == "platform" and p.node == "n1"
    assert manage.ManageProposal.from_order(p.to_dict()).members == p.members


# -- cards -----------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    None,
    {"status": "open", "answer": None},
    {"answer": "snooze"},
    {"answer": "reject"},
    {"answered_via": "agent"},
    {"answered_via": "deadline"},
    {"answer_receipt": None},       # no signed receipt: the store's word is not proof
    {"answer_attested": True, "answer_receipt": None},   # a hand-edited boolean
    {"_r": {"answered_by": "atlas"}},        # SIGNED answerer is not an owner
    {"_r": {"auth_method": "device_code"}},  # the agent session-bearer's sign-in
    {"_r": {"auth_method": "password"}},
    {"_r": {"auth_method": ""}},             # PAT / API key / OIDC access token
    {"_r": {"choice": "reject"}},            # the owner said reject; the card says approve
    {"id": "d-other"},              # not the card that approved this proposal
    {"facts": ["proposal_id: 999"]},
    {"facts": []},  # the title alone names the id: not enough (A7 needs the fact)
])
def test_refuses_without_a_human_approve_of_this_proposal(env, bad):
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group)
    card = None if bad is None else _card(pid, **bad)
    with pytest.raises(ApplyRefused):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=card, dry_run=False)
    rows = _ledger(cat, pid)
    assert rows and rows[0]["outcome"] == "refused"
    assert not (root / ".awstorage-quarantine").exists()


def test_master_switch_off_refuses_a_signed_card(env, monkeypatch):
    """STORE_ATTESTS_ANSWERER is the master switch: False refuses even a perfectly
    signed owner card."""
    monkeypatch.setattr(manage, "STORE_ATTESTS_ANSWERER", False)
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group)
    with pytest.raises(ApplyRefused, match="switched off"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert not (root / ".awstorage-quarantine").exists()


def test_via_is_a_label_not_a_gate(env):
    """0.4.1: the surface allowlist is gone -- an `api`-labelled card with a valid
    signed receipt approves; the same card unsigned does not."""
    assert manage.verify_card(_card(1, answered_via="api"), 1) == "d-1"
    with pytest.raises(ApplyRefused, match="no signed answer receipt"):
        manage.verify_card(_card(2, _sign=False, answered_via="popup"), 2)


def test_no_owner_principals_configured_refuses(monkeypatch):
    monkeypatch.delenv(manage.OWNERS_ENV, raising=False)
    with pytest.raises(ApplyRefused, match="owner principal"):
        manage.verify_card(_card(1), 1)


def test_unapproved_proposal_with_a_valid_card_is_refused(env):
    """A `proposed` proposal plus a perfect-looking card dict never executes: apply
    runs only on what the card consumer approved, with the card it recorded."""
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group, approve=False)
    with pytest.raises(ApplyRefused, match="not approved"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert not (root / ".awstorage-quarantine").exists()
    assert cat.get_proposal(pid)["status"] == "proposed"


def test_order_card_must_be_the_orders_card(env):
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group)
    with manage.ManageStore(cat) as st:
        order = st.load(pid).to_dict()
    order["card_id"] = "d-someone-else"
    with pytest.raises(ApplyRefused, match="not the card that approved"):
        manage.apply_manage(manage.ManageProposal.from_order(order), catalog=cat,
                            roots=[root], card=_card(pid), dry_run=False)
    order["card_id"] = None
    with pytest.raises(ApplyRefused, match="no approving card"):
        manage.apply_manage(manage.ManageProposal.from_order(order), catalog=cat,
                            roots=[root], card=_card(pid), dry_run=False)


def test_fact_for_a_longer_id_does_not_match():
    with pytest.raises(ApplyRefused):
        manage.verify_card(_card(1, facts=["proposal_id: 12"]), 1)


@pytest.mark.parametrize("action,must", [
    ("hardlink", "hardlink"), ("quarantine-copy", "quarantine"),
    ("archive", "PLAINTEXT"), ("share", "excluded"),
])
def test_card_text_comes_from_each_action_class(env, action, must):
    root, cat = env
    paths, group = _dupes(root)
    if action in ("hardlink", "quarantine-copy"):
        [p] = manage.propose_dupes([group], node="n1", action=action)
    elif action == "archive":
        p = manage.propose_archive("n1", _row(paths[0]))
    else:
        p = manage.propose_share("n1", str(paths[0]), owner="platform:op")
    _submit(cat, [p])
    spec = manage.card_spec(p)
    assert spec["title"].startswith(f"awstorage #{p.id}:")
    assert f"proposal_id: {p.id}" in spec["facts"]
    assert must in (spec["summary"] + " ".join(spec["facts"]))
    assert spec["reversibility"] and spec["options"][0].startswith("approve|")
    assert any(o.startswith("reject|") for o in spec["options"])


def test_tenant_and_workspace_proposals_refused_even_with_a_card(env):
    """Platform nodes only until card recipients land (A7): a genuine human approve
    of THIS proposal still cannot act on a tenant node or the workspace pseudo-node."""
    root, cat = env
    f = root / "doc.txt"
    f.write_text("hello")
    calls = []

    def hook(*a, **k):
        calls.append(1)
        return {"h": 1}

    [tpid] = _submit(cat, [manage.propose_share("t-a--laptop", str(f), owner="t-a:alice",
                                                tenant="t-a")])
    [wpid] = _submit(cat, [manage.propose_share("workspace", str(f), owner="t-a:alice")])
    for pid in (tpid, wpid):
        with pytest.raises(ApplyRefused, match="platform-nodes-only"):
            manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid),
                                dry_run=False, share_hook=hook)
        assert _ledger(cat, pid)[0]["outcome"] == "refused"
    assert calls == []


def test_expired_proposal_is_refused(env):
    root, cat = env
    _, group = _dupes(root)
    [p] = manage.propose_dupes([group], node="n1")
    p.expires_at = "2000-01-01T00:00:00+00:00"
    [pid] = _submit(cat, [p])
    with pytest.raises(ApplyRefused, match="expired"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)


# -- apply-time safety (no approval overrides) -----------------------------------------

@pytest.mark.parametrize("sub", ["pg_wal", "secrets", ".git/objects/ab"])
def test_card_approved_dedup_in_live_state_is_refused(env, sub):
    root, cat = env
    d = root / sub
    d.mkdir(parents=True)
    data = b"live-state" * 50
    paths = [d / "a.bin", d / "bb.bin"]
    for p in paths:
        p.write_bytes(data)
    group = {"sha256": _sha(data), "bytes": len(data), "paths": [_row(p) for p in paths]}
    # propose_dupes already drops never paths; forge the proposal to prove apply refuses
    p = manage.ManageProposal(node="n1", action="quarantine-copy", path=str(paths[1]),
                              params={"sha256": _sha(data), "keep": group["paths"][0]},
                              members=[group["paths"][1]])
    [pid] = _submit(cat, [p])
    with pytest.raises(ApplyRefused, match="no approval overrides"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert all(x.exists() for x in paths)


@pytest.mark.parametrize("shape", ["dir", "file", "bare", "above-root"])
def test_git_refusal_walks_to_the_filesystem_root(tmp_path, shape):
    repo = tmp_path / "repo"
    repo.mkdir()
    if shape == "dir":
        (repo / ".git").mkdir()
    elif shape == "file":
        (repo / ".git").write_text("gitdir: /elsewhere/.git/worktrees/x")
    elif shape == "bare":
        (repo / "HEAD").write_text("ref: refs/heads/main")
        (repo / "objects").mkdir()
        (repo / "refs").mkdir()
    else:
        (tmp_path / ".git").mkdir()  # the repo CONTAINS the declared root
    root = repo / "root"
    (root / "d").mkdir(parents=True)
    data = b"tracked" * 50
    paths = [root / "d" / "a.bin", root / "d" / "bb.bin"]
    for p in paths:
        p.write_bytes(data)
    cat = Catalog(tmp_path / "cat.db")
    _ENV_CAT[:] = [cat]
    try:
        rows = [_row(p) for p in paths]
        p = manage.ManageProposal(node="n1", action="hardlink", path=str(paths[1]),
                                  params={"sha256": _sha(data), "keep": rows[0]},
                                  members=[rows[1]])
        [pid] = _submit(cat, [p])
        with pytest.raises(ApplyRefused, match="git tree"):
            manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid),
                                dry_run=False)
    finally:
        _ENV_CAT.clear()
        cat.close()
    assert all(x.read_bytes() == data for x in paths)


# -- dedup -----------------------------------------------------------------------------

def test_dedup_dry_run_is_default_and_changes_nothing(env):
    root, cat = env
    paths, group = _dupes(root)
    pid = _one(cat, group)
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid))
    assert out["outcome"] == "dry-run"
    assert [r["result"] for r in out["results"]] == ["would-quarantine"] * 2
    assert all(p.exists() for p in paths)
    assert not (root / ".awstorage-quarantine").exists()


def test_quarantine_copies_ledger_per_member_then_revert_byte_for_byte(env):
    root, cat = env
    paths, group = _dupes(root)
    pid = _one(cat, group)
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert out["outcome"] == "applied"
    assert paths[0].exists() and not paths[1].exists() and not paths[2].exists()
    rows = _ledger(cat, pid)
    member_rows = [r for r in rows if r["outcome"] == "quarantined"]
    assert sorted(json.loads(r["detail"])["member"] for r in member_rows) == [0, 1]
    assert any(r["outcome"] == "applied" and r["path"] == str(paths[1]) for r in rows)
    assert cat.get_proposal(pid)["status"] == "applied"
    manage.revert_proposal(pid, catalog=cat)
    assert all(p.read_bytes() == b"same-bytes" * 100 for p in paths)


def test_hardlink_verifies_keeper_and_victim(env):
    root, cat = env
    paths, group = _dupes(root)
    pid = _one(cat, group, action="hardlink")
    paths[2].write_bytes(b"x" * 1000)  # the victim drifted (same size, new bytes)
    os.utime(paths[2], ns=(group["paths"][2]["mtime_ns"], group["paths"][2]["mtime_ns"]))
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    res = {r["path"]: r["result"] for r in out["results"]}
    assert res[str(paths[1])] == "hardlinked" and res[str(paths[2])] == "drifted"
    assert os.path.samefile(paths[0], paths[1])
    manage.revert_proposal(pid, catalog=cat)
    assert not os.path.samefile(paths[0], paths[1])


def test_keeper_drift_marks_the_proposal_drifted_and_touches_nothing(env):
    root, cat = env
    paths, group = _dupes(root)
    pid = _one(cat, group, action="hardlink")
    paths[0].write_bytes(b"changed")
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert out["outcome"] == "drifted"
    assert cat.get_proposal(pid)["status"] == "drifted"
    assert all(p.exists() for p in paths[1:])


def test_mtime_drift_is_drift(env):
    root, cat = env
    paths, group = _dupes(root)
    pid = _one(cat, group)
    st = os.stat(paths[1])
    os.utime(paths[1], ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert {r["path"]: r["result"] for r in out["results"]}[str(paths[1])] == "drifted"
    assert paths[1].exists()


@pytest.mark.parametrize("exc,reason", [
    (OSError(errno.EXDEV, "cross-device link"), "refused-cross-volume"),
    (PermissionError(13, "sharing violation"), "refused-locked"),
])
def test_quarantine_is_one_replace_and_never_copies(env, monkeypatch, exc, reason):
    root, cat = env
    paths, group = _dupes(root)
    pid = _one(cat, group)

    def boom(*_a, **_k):
        raise exc

    def no_copy(*_a, **_k):
        raise AssertionError("manage must never fall back to a copy")

    monkeypatch.setattr(manage.os, "replace", boom)
    monkeypatch.setattr(shutil, "move", no_copy)
    monkeypatch.setattr(shutil, "copy2", no_copy)
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert [r["result"] for r in out["results"]] == [reason, reason]
    assert out["outcome"] == "noop"
    assert all(p.read_bytes() == b"same-bytes" * 100 for p in paths)
    qroot = root / ".awstorage-quarantine"
    assert not qroot.exists() or not any(qroot.iterdir())


def test_paths_outside_roots_refused(env, tmp_path):
    root, cat = env
    other = tmp_path / "other"
    other.mkdir()
    paths, group = _dupes(other)
    pid = _one(cat, group)
    with pytest.raises(ApplyRefused, match="outside the declared roots"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False)
    assert all(p.exists() for p in paths)


# -- archive ---------------------------------------------------------------------------

def _archive_env(root: Path, cat: Catalog):
    f = root / "big.iso"
    f.write_bytes(b"iso-bytes" * 1000)
    p = manage.propose_archive("n1", _row(f))
    [pid] = _submit(cat, [p])
    return f, pid, p.params["strata_path"]


def test_archive_streams_reads_back_then_quarantines_and_reverts(env):
    root, cat = env
    f, pid, spath = _archive_env(root, cat)
    assert spath.startswith("aither://cold/disk-archive/n1/")
    stored: dict = {}

    def write(path, *, strata_path, sha256, size, tier):
        stored[strata_path] = Path(path).read_bytes()
        return {"sha256": sha256}

    def readback(strata_path):
        b = stored[strata_path]
        return {"sha256": _sha(b), "size": len(b)}

    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                              strata_hook=write, readback_hook=readback)
    assert out["outcome"] == "applied" and not f.exists()
    manage.revert_proposal(pid, catalog=cat)
    assert f.read_bytes() == b"iso-bytes" * 1000


def test_archive_readback_mismatch_keeps_local(env):
    root, cat = env
    f, pid, _ = _archive_env(root, cat)
    with pytest.raises(ApplyRefused, match="read-back"):
        manage.apply_manage(
            pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
            strata_hook=lambda p, **k: {"sha256": k["sha256"]},
            readback_hook=lambda s: {"sha256": "0" * 64, "size": 9000})
    assert f.exists()


def test_archive_refuses_a_file_changed_since_proposal(env):
    root, cat = env
    f, pid, _ = _archive_env(root, cat)
    f.write_bytes(b"different")
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                              strata_hook=lambda *a, **k: pytest.fail("uploaded"),
                              readback_hook=lambda s: {})
    assert out["outcome"] == "drifted" and f.exists()


def test_purge_archived_needs_ttl_and_a_second_stat(env):
    root, cat = env
    f, pid, spath = _archive_env(root, cat)
    sha = _sha(f.read_bytes())
    size = f.stat().st_size
    ok = {"sha256": sha, "size": size}
    manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                        strata_hook=lambda p, **k: {"sha256": k["sha256"]},
                        readback_hook=lambda s: ok)
    import time as _t

    young = manage.purge_archived(catalog=cat, stat_hook=lambda s: ok, ttl_days=14,
                                  dry_run=False)
    assert [r["outcome"] for r in young] == ["kept-ttl"]
    later = _t.time() + 15 * 86400
    bad = manage.purge_archived(catalog=cat, stat_hook=lambda s: {"sha256": sha, "size": 1},
                                ttl_days=14, dry_run=False, now=later)
    assert [r["outcome"] for r in bad] == ["kept-stat-mismatch"]
    good = manage.purge_archived(catalog=cat, stat_hook=lambda s: ok, ttl_days=14,
                                 dry_run=False, now=later)
    assert [r["outcome"] for r in good] == ["purged"]
    assert not (root / ".awstorage-quarantine").exists() or not any(
        (root / ".awstorage-quarantine").iterdir())


# -- share -----------------------------------------------------------------------------

def test_share_enumeration_excludes_git_env_sensitive_and_links(tmp_path):
    d = tmp_path / "proj"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("alpha")
    (d / "sub" / "b.txt").write_text("beta")
    (d / ".env.local").write_text("TOKEN=x")
    (d / "id_rsa").write_text("key")
    (d / ".git").mkdir()
    (d / "node_modules" / "x").mkdir(parents=True)
    (d / "node_modules" / "x" / "i.js").write_text("js")
    files, excluded = manage.enumerate_share(d)
    assert sorted(f.name for f in files) == ["a.txt", "b.txt"]
    names = " ".join(excluded)
    assert ".env.local" in names and "id_rsa" in names and ".git" in names
    assert "node_modules" in names


def test_share_local_awshare_publish_list_and_revert(env, tmp_path):
    pytest.importorskip("awshare")
    root, cat = env
    d = root / "proj"
    d.mkdir()
    (d / "a.txt").write_text("alpha")
    (d / ".env").write_text("NOPE=1")
    share, unshare = manage.local_awshare_hook(tmp_path / "shares")
    [pid] = _submit(cat, [manage.propose_share("n1", str(d), owner="platform:op")])
    out = manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid),
                              dry_run=False, share_hook=share)
    h = out["handle"]
    assert Path(h["manifest"]).is_file() and h["files"] == 1
    assert any(".env" in x for x in h["excluded"])
    assert sorted(x.name for x in d.iterdir()) == [".env", "a.txt"]  # source untouched
    with manage.ManageStore(cat) as st:
        assert [s["proposal_id"] for s in st.list_shares("platform:op")] == [pid]
    manage.revert_proposal(pid, catalog=cat, unshare_hook=unshare)
    assert not Path(h["out_dir"]).exists()


def test_share_inside_a_git_tree_is_refused(env):
    root, cat = env
    (root / "repo" / ".git").mkdir(parents=True)
    (root / "repo" / "a.txt").write_text("x")
    [pid] = _submit(cat, [manage.propose_share("n1", str(root / "repo"), owner="p:op")])
    with pytest.raises(ApplyRefused, match="git tree"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=_card(pid), dry_run=False,
                            share_hook=lambda *a, **k: pytest.fail("shared"))


def test_share_needs_card(env):
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


# -- card links + approval bookkeeping -------------------------------------------------

def test_mark_approved_is_idempotent_and_only_from_proposed(env):
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group, approve=False)
    with manage.ManageStore(cat) as st:
        st.link_card("d-x", pid)
        assert st.mark_approved(pid, "d-x") is True
        assert st.mark_approved(pid, "d-x") is False
        assert st.mark_rejected(pid, "d-x") is False
        assert st.load(pid).card_id == "d-x" and st.load(pid).approved_at
    assert cat.get_proposal(pid)["status"] == "approved"


def test_cli_has_no_apply(env, tmp_path):
    """A card from a FILE is a caller-supplied dict, not a decision record: the local
    CLI cannot apply at all."""
    root, cat = env
    _, group = _dupes(root)
    pid = _one(cat, group)
    cf = tmp_path / "card.json"
    cf.write_text(json.dumps(_card(pid)))
    with pytest.raises(SystemExit):
        manage.main(["--db", str(cat.path), "apply", str(pid), "--root", str(root),
                     "--card", str(cf), "--yes"])
    assert not (root / ".awstorage-quarantine").exists()

