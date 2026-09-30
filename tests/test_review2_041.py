"""0.4.1, second security review: nothing is deleted on a status read off catalog.db.

c1  an ``approved`` / ``auto-approved`` status flipped in SQLite must not act: apply
    re-verifies the recorded card (signature, owner, receipt digest, content) and
    re-judges every auto-lane condition (identity via the verifier, not the row).
c2  the card binds WHAT was approved (``content_sha256`` over path/members/params);
    a row edited after the answer no longer matches.
c4  a receipt older than 7 days (env-tunable, clamped) is refused by the REAL clock.
c5  a verifier-key file under ~/.aither or in a world-writable dir is refused.
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import stat
import time
from pathlib import Path

import pytest

from awstorage import attest, manage
from awstorage.catalog import Catalog
from awstorage.policy import ApplyRefused

from tests.attest_util import OWNER, pubkey_env, sign_card

sg = importlib.import_module("awstorage.suggest")


def _mk(p: Path, data: bytes, age_h: float = 30.0) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    t = time.time() - age_h * 3600
    os.utime(p, (t, t))
    return p


def _tree(root: Path, age_h: float = 30.0) -> Path:
    _mk(root / "a.o", b"1" * 128, age_h)
    _mk(root / "NOTES.md", b"# notes\n", age_h)
    t = time.time() - age_h * 3600
    os.utime(root, (t, t))
    return root


@pytest.fixture(autouse=True)
def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for k in ("AWSTORAGE_LIVE_IDS", "AWSTORAGE_FLOORS", "AWSTORAGE_TRUST_THRESHOLD",
              attest.PUBKEY_FILE_ENV, attest.MAX_RECEIPT_AGE_ENV, attest.MAX_AUTH_AGE_ENV,
              sg.TRUST_INPROCESS_ENV):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWSTORAGE_NODE", "testnode")
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "default.db"))
    monkeypatch.setenv(manage.OWNERS_ENV, OWNER)
    pubkey_env(monkeypatch)
    for hook in (sg.set_card_hook, sg.set_archive_hook, sg.set_identity_verifier,
                 sg.set_card_reader):
        hook(None)
    yield
    for hook in (sg.set_card_hook, sg.set_archive_hook, sg.set_identity_verifier,
                 sg.set_card_reader):
        hook(None)


@pytest.fixture
def cat(tmp_path: Path):
    c = Catalog(tmp_path / "cat.db")
    yield c
    c.close()


def _approved_card(cat: Catalog, sid: int, cid: str = "c1", **receipt_over) -> dict:
    card = {"id": cid, "status": "answered", "answered_via": "desk", "answered_by": OWNER,
            "answer": "approve", "facts": sg.card_spec(cat.get_suggestion(sid))["facts"]}
    return sign_card(card, **receipt_over)


def _sql(cat: Catalog, q: str, *args) -> None:
    db = sqlite3.connect(str(cat.path))
    with db:
        db.execute(q, args)
    db.close()


# -- c1: a flipped status acts on nothing ------------------------------------------------

def test_status_flipped_to_approved_in_sqlite_deletes_nothing(tmp_path: Path, cat):
    victim = _tree(tmp_path / "work" / "notes")
    r = sg.suggest(str(victim), reason="cleanup", suggested_by="agent:x", action="delete",
                   catalog=cat)
    assert r["status"] == "pending-card"
    _sql(cat, "UPDATE suggestions SET status='approved', approved_at=datetime('now')"
              " WHERE id=?", r["id"])
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert victim.exists() and (victim / "a.o").exists()
    assert rec["applied"] == 0 and rec["refused"] == 1 and rec["exit_code"] == 1
    assert rec["items"][0]["outcome"] == "refused"
    assert "no approving card" in rec["items"][0]["reason"]
    assert cat.get_suggestion(r["id"])["status"] == "refused"


def test_flipped_status_with_forged_card_columns_is_refused(tmp_path: Path, cat):
    victim = _tree(tmp_path / "work" / "notes")
    r = sg.suggest(str(victim), reason="r", suggested_by="agent:x", action="delete",
                   catalog=cat)
    forged = {"id": "c9", "status": "answered", "answer": "approve", "answered_by": OWNER,
              "answer_attested": True, "facts": [f"proposal_id: {r['id']}"]}
    _sql(cat, "UPDATE suggestions SET status='approved', card_id='c9', receipt_digest=?,"
              " card_snapshot=? WHERE id=?", "0" * 64, json.dumps(forged), r["id"])
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert victim.exists() and rec["refused"] == 1
    assert "no signed answer receipt" in rec["items"][0]["reason"]


def test_genuine_approval_then_path_swapped_in_sqlite_is_refused(tmp_path: Path, cat):
    build = _tree(tmp_path / "scratch" / "build")
    victim = _tree(tmp_path / "work" / "thesis")
    r = sg.suggest(str(build), reason="dead", suggested_by="a", action="delete", catalog=cat)
    ok = sg.resolve_suggestion(r["id"], "approve", card=_approved_card(cat, r["id"]),
                               catalog=cat)
    assert ok["ok"]
    vp = str(victim).replace("\\", "/")
    _sql(cat, "UPDATE suggestions SET path=?, path_key=? WHERE id=?",
         vp, os.path.normcase(vp).replace("\\", "/"), r["id"])
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert victim.exists() and build.exists()
    assert rec["refused"] == 1 and "changed after the owner answered" in \
        rec["items"][0]["reason"]


def test_genuine_approval_with_edited_receipt_digest_is_refused(tmp_path: Path, cat):
    build = _tree(tmp_path / "scratch" / "build")
    r = sg.suggest(str(build), reason="dead", suggested_by="a", action="delete", catalog=cat)
    assert sg.resolve_suggestion(r["id"], "approve", card=_approved_card(cat, r["id"]),
                                 catalog=cat)["ok"]
    row = cat.get_suggestion(r["id"])
    assert row["card_snapshot"]["id"] == "c1" and len(row["receipt_digest"]) == 64
    _sql(cat, "UPDATE suggestions SET receipt_digest=? WHERE id=?", "f" * 64, r["id"])
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert build.exists() and rec["refused"] == 1
    assert "different receipt" in rec["items"][0]["reason"]


def test_genuine_approval_applies_and_a_card_reader_is_used(tmp_path: Path, cat):
    build = _tree(tmp_path / "scratch" / "build")
    r = sg.suggest(str(build), reason="dead", suggested_by="a", action="delete", catalog=cat)
    card = _approved_card(cat, r["id"])
    assert sg.resolve_suggestion(r["id"], "approve", card=card, catalog=cat)["ok"]
    reads: list = []
    sg.set_card_reader(lambda cid: reads.append(cid) or dict(card, answer="reject"))
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert reads == ["c1"] and build.exists() and rec["refused"] == 1  # live card says no
    _sql(cat, "UPDATE suggestions SET status='approved' WHERE id=?", r["id"])
    sg.set_card_reader(lambda cid: card)
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert rec["applied"] == 1 and not build.exists()


def test_status_flipped_to_auto_approved_with_identity_verified_is_withdrawn(
        tmp_path: Path, cat):
    build = _tree(tmp_path / "scratch" / "build")
    r = sg.suggest(str(build), reason="dead", suggested_by="a", catalog=cat,
                   evidence={"bytes": 136})
    assert r["status"] == "pending-card"
    for _ in range(6):  # forged trust history
        _sql(cat, "INSERT INTO suggestions(created_at, updated_at, node, path, path_key,"
                  " action, reason, suggested_by, status) VALUES"
                  " ('x','x','n','/p','/p','quarantine','r','a','applied')")
    _sql(cat, "UPDATE suggestions SET status='auto-approved', identity='verified',"
              " cls='build-temp' WHERE id=?", r["id"])
    rec = sg.apply_suggestions(dry_run=False, harvest_to=tmp_path / "shelf", catalog=cat)
    assert build.exists() and rec["applied"] == 0 and rec["demoted"] == 1
    assert "identity" in rec["items"][0]["reason"]


def test_athena_repro_flip_refuses(tmp_path: Path, monkeypatch):
    """scratchpad/ath2/repro/flip.py, inlined: SQLite status flip -> apply -> victim."""
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "catalog.db"))
    victim = tmp_path / "work" / "notes"
    victim.mkdir(parents=True)
    (victim / "important.txt").write_text("owner data " * 100)
    old = time.time() - 3 * 86400
    for q in (victim / "important.txt", victim):
        os.utime(q, (old, old))
    r = sg.suggest(str(victim), reason="cleanup", suggested_by="agent:x", action="delete")
    db = sqlite3.connect(str(tmp_path / "catalog.db"))
    db.execute("UPDATE suggestions SET status='approved', approved_at=datetime('now')"
               " WHERE id=?", (r["id"],))
    db.commit()
    db.close()
    out = sg.apply_suggestions(dry_run=False, harvest_to=str(tmp_path / "shelf"))
    assert victim.exists() and out["items"][0]["outcome"] == "refused"


# -- c2: manage content binding -----------------------------------------------------------

def _dupe_proposal(root: Path, cat: Catalog) -> tuple[int, list[Path]]:
    import hashlib

    data = b"same" * 256
    paths = []
    for rel in ("k/f.bin", "copy/f.bin"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        paths.append(p)
    sha = hashlib.sha256(data).hexdigest()
    rows = [{"node": "n1", "path": str(p), "bytes": p.stat().st_size,
             "mtime_ns": p.stat().st_mtime_ns, "sha256": sha, "dev": p.stat().st_dev,
             "ino": p.stat().st_ino, "nlink": 1} for p in paths]
    [prop] = manage.propose_dupes([{"sha256": sha, "bytes": len(data), "paths": rows}],
                                  node="n1")
    with manage.ManageStore(cat) as st:
        [pid] = st.submit([prop])
        assert st.mark_approved(pid, f"d-{pid}")
    return pid, paths


def _manage_card(cat: Catalog, pid: int, facts: list | None = None) -> dict:
    with manage.ManageStore(cat) as st:
        spec = manage.card_spec(st.load(pid))
    card = {"id": f"d-{pid}", "status": "answered", "answer": "approve",
            "answered_via": "desk", "answered_by": OWNER,
            "facts": spec["facts"] if facts is None else facts}
    return sign_card(card)


def test_manage_card_binds_members_and_a_later_edit_is_refused(tmp_path: Path, cat):
    root = tmp_path / "root"
    pid, paths = _dupe_proposal(root, cat)
    card = _manage_card(cat, pid)
    assert any(f.startswith("content_sha256: ") for f in card["facts"])
    other = root / "precious.bin"
    other.write_bytes(b"x")
    db = sqlite3.connect(str(cat.path))
    members = json.loads(db.execute("SELECT members_json FROM manage_params WHERE"
                                    " proposal_id=?", (pid,)).fetchone()[0])
    members[0]["path"] = str(other)
    with db:
        db.execute("UPDATE manage_params SET members_json=? WHERE proposal_id=?",
                   (json.dumps(members), pid))
    db.close()
    with pytest.raises(ApplyRefused, match="changed after the owner answered"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=card, dry_run=False)
    assert other.exists() and all(p.exists() for p in paths)


def test_manage_card_without_a_content_fact_is_refused(tmp_path: Path, cat):
    root = tmp_path / "root"
    pid, _paths = _dupe_proposal(root, cat)
    card = _manage_card(cat, pid, facts=manage.card_facts(pid))
    with pytest.raises(ApplyRefused, match="content_sha256"):
        manage.apply_manage(pid, catalog=cat, roots=[root], card=card, dry_run=False)


def test_manage_content_digest_survives_the_order_round_trip(tmp_path: Path, cat):
    pid, _paths = _dupe_proposal(tmp_path / "root", cat)
    with manage.ManageStore(cat) as st:
        p = st.load(pid)
    q = manage.ManageProposal.from_order(json.loads(json.dumps(p.to_dict())))
    assert manage.content_digest(p) == manage.content_digest(q)
    q.params = dict(q.params, sha256="0" * 64)
    assert manage.content_digest(p) != manage.content_digest(q)


# -- c4: receipt max age --------------------------------------------------------------------

def _card(pid: int = 1, **over) -> dict:
    return {"id": "d-1", "status": "answered", "answer": "approve", "answered_via": "desk",
            "answered_by": OWNER, "facts": manage.card_facts(pid), **over}


def test_receipt_older_than_seven_days_is_refused(cat):
    at = int(time.time()) - 8 * 86400
    card = sign_card(_card(), answered_at=at, auth_time=at - 60)
    with pytest.raises(ApplyRefused, match="receipt is .* h old"):
        attest.verify_receipt(card, owners=[OWNER], nonce_store=cat)


def test_receipt_age_is_env_tunable_clamped_and_uses_the_real_clock(cat, monkeypatch):
    at = int(time.time()) - 2 * 86400
    card = sign_card(_card(), answered_at=at, auth_time=at - 60)
    assert attest.verify_receipt(card, owners=[OWNER], nonce_store=cat, record=False)
    monkeypatch.setenv(attest.MAX_RECEIPT_AGE_ENV, "86400")
    with pytest.raises(ApplyRefused, match="h old"):
        attest.verify_receipt(card, owners=[OWNER], nonce_store=cat, record=False)
    # a caller-supplied clock is ignored: "now" in the past does not make it young
    with pytest.raises(ApplyRefused, match="h old"):
        attest.verify_receipt(card, owners=[OWNER], nonce_store=cat, record=False,
                              now=at + 10)
    monkeypatch.setenv(attest.MAX_RECEIPT_AGE_ENV, "1")
    assert attest.max_receipt_age() == 3600
    monkeypatch.setenv(attest.MAX_RECEIPT_AGE_ENV, str(10**9))
    assert attest.max_receipt_age() == 30 * 86400
    monkeypatch.setenv(attest.MAX_RECEIPT_AGE_ENV, "junk")
    assert attest.max_receipt_age() == 7 * 86400


def test_future_receipt_is_refused_whatever_now_says(cat):
    at = int(time.time()) + 3600
    card = sign_card(_card(), answered_at=at, auth_time=at - 60)
    with pytest.raises(ApplyRefused, match="in the future"):
        attest.verify_receipt(card, owners=[OWNER], nonce_store=cat, now=at + 3600)


# -- c5: where the verifier key may live ---------------------------------------------------

def _key_file(p: Path) -> Path:
    from tests.attest_util import PUB

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(PUB, encoding="utf-8")
    return p


def test_pubkey_file_under_home_aither_is_refused(tmp_path: Path, monkeypatch, cat):
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    f = _key_file(home / ".aither" / "attest.pub")
    monkeypatch.delenv(attest.PUBKEY_ENV, raising=False)
    monkeypatch.setenv(attest.PUBKEY_FILE_ENV, str(f))
    assert attest.configured_pubkey() is None
    assert "~/.aither" in attest.pubkey_file_refusal(f)
    with pytest.raises(ApplyRefused, match="refused: .*under"):
        attest.verify_receipt(sign_card(_card()), owners=[OWNER], nonce_store=cat)
    ok = _key_file(tmp_path / "etc" / "aither" / "attest.pub")
    monkeypatch.setenv(attest.PUBKEY_FILE_ENV, str(ok))
    assert attest.pubkey_file_refusal(ok) is None
    assert attest.configured_pubkey() is not None


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_pubkey_file_in_a_world_writable_dir_is_refused(tmp_path: Path):
    d = tmp_path / "ww"
    f = _key_file(d / "attest.pub")
    os.chmod(d, 0o777)
    assert "world-writable" in attest.pubkey_file_refusal(f)
    os.chmod(d, 0o755)
    os.chmod(f, 0o666)
    assert "world-writable" in attest.pubkey_file_refusal(f)
    os.chmod(f, 0o644)
    assert attest.pubkey_file_refusal(f) is None
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o644

