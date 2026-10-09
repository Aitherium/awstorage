"""Couplings: each sibling ABSENT (import blocked) answers "unavailable" honestly
and the sweep behaves as documented; each sibling PRESENT does the real thing.
A present-test skips with a reason when that package is not importable here."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import awstorage
import pytest
from awstorage import cli
from awstorage import integrations as ig


def _have(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def _block(monkeypatch, *mods: str) -> None:
    """Make `import <mod>` raise ImportError, as on a box without the package."""
    for m in mods:
        for k in [k for k in sys.modules if k == m or k.startswith(m + ".")]:
            monkeypatch.delitem(sys.modules, k, raising=False)
        monkeypatch.setitem(sys.modules, m, None)


def _mk(p: Path, data: bytes = b"x", age_h: float = 30.0) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    t = time.time() - age_h * 3600
    os.utime(p, (t, t))
    return p


def _pol(root: Path, **over) -> dict:
    r = {"name": "t", "paths": [root.as_posix() + "/*"], "class": "build-temp",
         "max_idle": "10h", "action": "delete"}
    r.update(over)
    return {"retention": [r]}


@pytest.fixture
def world(tmp_path: Path):
    root = tmp_path / "r"
    _mk(root / "sess" / "REPORT.md", b"# report")
    return root, tmp_path / "shelf"


@pytest.fixture
def seal_key(tmp_path: Path, monkeypatch):
    if not _have("awseal"):
        pytest.skip("awseal not installed")
    import awseal
    try:
        return awseal.keygen(tmp_path / "keys" / "signing.key")
    except Exception as exc:  # noqa: BLE001 -- e.g. cryptography missing
        pytest.skip(f"awseal cannot generate a key here: {exc}")


# -- awdit -------------------------------------------------------------------------

def test_awdit_absent_require_audit_refuses_to_remove(world, tmp_path, monkeypatch):
    root, shelf = world
    _block(monkeypatch, "awdit")
    assert ig.audit_available()["available"] is False
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          audit_log=tmp_path / "a.log", require_audit=True,
                          receipt=tmp_path / "rc.json")
    assert rec["exit_code"] == 2 and (root / "sess").exists()
    assert "awdit" in rec["could_not_judge"][0]
    assert json.loads((tmp_path / "rc.json").read_text(encoding="utf-8"))["exit_code"] == 2


def test_awdit_absent_without_require_warns_and_proceeds(world, tmp_path, monkeypatch):
    root, shelf = world
    _block(monkeypatch, "awdit")
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          audit_log=tmp_path / "a.log")
    assert rec["exit_code"] == 0 and not (root / "sess").exists()
    assert rec["audit"]["available"] is False and "audit unavailable" in rec["warnings"][0]
    assert ig.audit_verify(tmp_path / "a.log")["available"] is False
    assert cli.main(["audit", "verify", "--audit-log", str(tmp_path / "a.log")]) == 2


def test_require_audit_without_a_log_is_could_not_judge(world):
    root, shelf = world
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf,
                          require_audit=True)
    assert rec["exit_code"] == 2 and (root / "sess").exists()


@pytest.mark.skipif(not _have("awdit"), reason="awdit not installed")
def test_awdit_present_records_every_decision_and_detects_tampering(world, tmp_path):
    root, shelf = world
    _mk(root / "live" / "a.md", b"a", 0.1)
    log = tmp_path / "audit.log"
    rec = awstorage.sweep(policy=_pol(root, live_guard={"window": "2h"}), dry_run=False,
                          harvest_to=shelf, seal=False, audit_log=log, require_audit=True)
    assert rec["exit_code"] == 0 and rec["audit"]["available"] is True
    events = [json.loads(line)["event"] for line in log.read_text(encoding="utf-8").splitlines()]
    assert "awstorage.skipped-live" in events and "awstorage.harvested" in events
    assert events.index("awstorage.deleted-begin") < events.index("awstorage.deleted")
    assert ig.audit_verify(log)["ok"] is True
    assert cli.main(["audit", "verify", "--audit-log", str(log)]) == 0
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # truncate the tail
    assert ig.audit_verify(log)["ok"] is False
    assert cli.main(["audit", "verify", "--audit-log", str(log)]) == 1


@pytest.mark.skipif(not _have("awdit"), reason="awdit not installed")
def test_audit_append_is_linear_and_chains_with_a_concurrent_writer(tmp_path, monkeypatch):
    import awdit
    import awdit.log as awdit_log
    log = tmp_path / "a.log"
    # awdit.append re-reads the whole log per call (head() walks it): quadratic, 2000
    # appends took 19.6 s measured. Count the RECORDS read back instead of timing them
    # -- an fsync per append on a loaded Windows host costs more than the re-read, so a
    # wall-clock bound both flaked (6 runs in 8 over 12 s) and passed a quadratic path.
    # Counting at read() (which head() calls through the module global) catches any
    # walk of the log, not only one that goes through head().
    records_read = []
    real_read = awdit_log.read

    def counting_read(path, *a, **k):
        for rec in real_read(path, *a, **k):
            records_read.append(str(path))
            yield rec

    monkeypatch.setattr(awdit_log, "read", counting_read)
    monkeypatch.setattr(awdit, "read", counting_read)
    for i in range(300):
        assert ig.audit_append(log, "quarantined", path=f"/t/item-{i}", bytes=i)["ok"]
    # Linear allows at most one full walk (<= 300 records); per-append re-reads are ~45k.
    assert len(records_read) <= 300, (
        f"{len(records_read)} records re-read for 300 appends -- quadratic again?")
    monkeypatch.setattr(awdit_log, "read", real_read)
    monkeypatch.setattr(awdit, "read", real_read)
    awdit.append(str(log), "someone-else", by="peer")  # another writer moves the head
    assert ig.audit_append(log, "deleted", path="/t/after")["ok"]
    r = awdit.verify(str(log))
    assert r.ok and r.count == 302, r.problems


def test_failed_audit_append_under_require_audit_keeps_the_item(world, tmp_path, monkeypatch):
    root, shelf = world
    monkeypatch.setattr(ig, "audit_available", lambda: {"available": True, "ok": True})
    monkeypatch.setattr(ig, "audit_append",
                        lambda *a, **k: {"available": True, "ok": False, "reason": "disk"})
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          audit_log=tmp_path / "a.log", require_audit=True)
    assert rec["exit_code"] == 1 and (root / "sess").exists()


# -- awseal ------------------------------------------------------------------------

def test_awseal_absent_unsealed_is_reported_and_explicit_key_keeps_item(world, tmp_path,
                                                                        monkeypatch):
    root, shelf = world
    _block(monkeypatch, "awseal")
    assert ig.seal_dir(tmp_path, None)["available"] is False
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf)
    assert rec["exit_code"] == 0 and rec["items"][0]["harvest"]["seal"].startswith("unsealed")
    assert ig.verify_shelf(shelf)["available"] is False
    assert cli.main(["harvest", "verify", str(shelf)]) == 2
    _mk(root / "sess2" / "R.md", b"r")
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf,
                          seal_key=tmp_path / "k")
    assert rec["exit_code"] == 1 and (root / "sess2").exists()


def test_awseal_present_seals_and_verify_finds_tamper_and_missing(world, seal_key, tmp_path):
    root, shelf = world
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf,
                          seal_key=seal_key)
    assert rec["exit_code"] == 0
    item_dir = Path(rec["items"][0]["harvest"]["dir"])
    assert (item_dir / "awseal.json").is_file()
    r = ig.verify_shelf(shelf)
    assert r["ok"] and r["counts"] == {"sealed": 1, "tampered": 0, "missing": 0}
    assert cli.main(["harvest", "verify", str(shelf)]) == 0
    (item_dir / "REPORT.md").write_text("# rewritten", encoding="utf-8")
    assert ig.verify_shelf(shelf)["counts"]["tampered"] == 1
    assert cli.main(["harvest", "verify", str(shelf)]) == 1
    (item_dir / "awseal.json").unlink()
    assert ig.verify_shelf(shelf)["counts"]["missing"] == 1


# -- awshare -----------------------------------------------------------------------

def test_awshare_absent_publish_is_unavailable(world, tmp_path, monkeypatch):
    root, shelf = world
    _block(monkeypatch, "awshare")
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          publish_to=tmp_path / "pub")
    assert rec["exit_code"] == 0 and rec["publish"][0]["available"] is False
    assert any("publish unavailable" in w for w in rec["warnings"])
    day = next((shelf / "t").iterdir())
    assert cli.main(["harvest", "publish", str(day), "--to", str(tmp_path / "pub")]) == 2


@pytest.mark.skipif(not _have("awshare"), reason="awshare not installed")
def test_awshare_present_publishes_and_fetches_back_verified(world, tmp_path):
    root, shelf = world
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          publish_to=tmp_path / "pub")
    [p] = rec["publish"]
    assert p["ok"], p
    import awshare
    out = tmp_path / "fetched"
    awshare.fetch(Path(p["manifest"]), out)
    assert next(out.rglob("REPORT.md")).read_bytes() == b"# report"
    day = next((shelf / "t").iterdir())
    assert cli.main(["harvest", "publish", str(day), "--to", str(tmp_path / "pub2")]) == 0


# -- awm ---------------------------------------------------------------------------

def test_awm_absent_landing_is_a_warning(world, tmp_path, monkeypatch):
    root, shelf = world
    _block(monkeypatch, "awm")
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          land_to_awm="acme:me:proj", awm_db=tmp_path / "m.db")
    assert rec["exit_code"] == 0 and any("awm" in w for w in rec["warnings"])
    assert not (tmp_path / "m.db").exists()


@pytest.mark.skipif(not _have("awm"), reason="awm not installed")
def test_awm_present_lands_one_memory_via_remember(world, tmp_path):
    root, shelf = world
    _mk(root / "sess-b" / "x.md", b"x")
    db = tmp_path / "m.db"
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          land_to_awm="acme:me:proj", awm_db=db)
    assert rec["exit_code"] == 0 and not rec["warnings"]
    import awm
    st = awm.MemoryStore(db)
    mems = {m.key: m for m in st.recall(awm.Scope.parse("acme:me:proj"), limit=50)}
    st.close()
    assert set(mems) == {"storage.harvest.sess", "storage.harvest.sess-b"}
    assert "REPORT.md" in mems["storage.harvest.sess"].value


@pytest.mark.skipif(not _have("awm"), reason="awm not installed")
def test_awm_bad_scope_is_could_not_judge_and_old_schema_is_compat(world, tmp_path):
    root, shelf = world
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False,
                          land_to_awm="not-a-scope")
    assert rec["exit_code"] == 2 and (root / "sess").exists()
    import sqlite3
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE schema_meta (version INTEGER NOT NULL)")
    con.execute("INSERT INTO schema_meta(version) VALUES (0)")
    con.commit()
    con.close()
    r = ig.land_to_awm("acme:me:proj", {"item": "/x/s", "harvested": [{"path": "a"}]},
                       "/shelf", db=db)
    assert r["available"] and not r["ok"] and "compat" in r["reason"]
    con = sqlite3.connect(db)
    assert con.execute("SELECT version FROM schema_meta").fetchone()[0] == 0  # not migrated
    con.close()


# -- awrecover ---------------------------------------------------------------------

def test_awrecover_absent_snapshot_rule_keeps_the_item(world, tmp_path, monkeypatch):
    root, shelf = world
    _block(monkeypatch, "awrecover")
    rec = awstorage.sweep(policy=_pol(root, snapshot=True), dry_run=False, harvest_to=shelf,
                          seal=False, snapshot_store=tmp_path / "snaps")
    assert rec["exit_code"] == 1 and (root / "sess").exists()
    assert "snapshot required" in rec["errors"][0]


@pytest.mark.skipif(not (_have("awrecover") and _have("awshare")),
                    reason="awrecover (+awshare) not installed")
def test_awrecover_present_snapshots_before_removal(world, tmp_path):
    root, shelf = world
    store = tmp_path / "snaps"
    rec = awstorage.sweep(policy=_pol(root, snapshot=True), dry_run=False, harvest_to=shelf,
                          seal=False, snapshot_store=store)
    assert rec["exit_code"] == 0 and not (root / "sess").exists()
    import awrecover
    [snap] = awrecover.list_snapshots(store)
    assert snap.label == rec["items"][0]["snapshot"]
    out = tmp_path / "restored"
    awrecover.restore(store, snap.label, out)
    assert (out / "REPORT.md").read_bytes() == b"# report"


# -- awdk contract -----------------------------------------------------------------

def test_awdk_contract_sweep_returns_receipt_and_honours_live_ids(world, monkeypatch):
    root, shelf = world
    monkeypatch.setenv(awstorage.LIVE_IDS_ENV, "sess")
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to=shelf, seal=False)
    assert isinstance(rec, dict) and rec["exit_code"] == 0
    assert [Path(p).name for p in rec["skipped_live"]] == ["sess"] and (root / "sess").exists()
