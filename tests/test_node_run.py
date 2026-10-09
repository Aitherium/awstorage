"""node_run.py: apply orders, one full pass, and the loop's exit codes.

`GatewayClient` is faked with a plain duck-typed object here -- the wire
protocol itself is proven in test_remote_chunking.py against a real HTTP
server; these tests are about node_run's OWN logic (which orders get acted
on, what gets reported, when a pass refuses to call itself a success).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from awstorage.node_run import apply_orders, run_loop, run_once
from awstorage.remote import GatewayError


def _mk(root: Path, rel: str, size: int) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * size)
    return p


def _order(path: Path, *, action="delete", cls="build-temp", pid=1, status="approved",
           bytes_=4096) -> dict:
    return {"id": pid, "node": "test-node", "path": str(path).replace("\\", "/"),
            "action": action, "bytes": bytes_, "cls": cls, "policy_rule": "test-rule",
            "auto": False, "status": status, "fingerprint": None, "snapshot_id": None,
            "note": None}


class _FakeClient:
    """A duck-typed stand-in for GatewayClient: records every call, answers
    each tool the way the real Genesis router would for a healthy fleet."""

    def __init__(self, orders=None, ingest_entries=None):
        self.calls: list[tuple[str, dict]] = []
        self._orders = orders if orders is not None else []
        self._ingest_entries = ingest_entries  # None -> echo real tree count

    def call_tool(self, name: str, args: dict):
        self.calls.append((name, args))
        if name == "storage_requests":
            return {"node_id": args["node_id"], "orders": self._orders, "count": len(self._orders)}
        if name == "storage_report_apply":
            rows = json.loads(args["rows_json"])
            return {"written": len(rows)}
        if name == "storage_ingest_scan":
            if self._ingest_entries is not None:
                return {"entries_written": self._ingest_entries}
            snap = json.loads(args["snapshot_json"])
            n = len(snap.get("trees", []))
            return {"entries_written": n, "trees": n}
        return {"error": f"unknown tool {name!r}"}


class _FakeConnectingClient:
    """What `GatewayClient(...).connect()` returns when node_run.GatewayClient
    is monkeypatched -- `__init__` swallows the real constructor args."""

    def __init__(self, inner: _FakeClient | None = None, fail: bool = False):
        self._inner = inner
        self._fail = fail

    def connect(self):
        if self._fail:
            raise GatewayError("simulated: gateway unreachable")
        return self._inner


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "vol"
    _mk(root, "keep/data.bin", 4096)
    return root


# ------------------------------------------------------------------ apply_orders


def test_apply_orders_skips_unapproved(tree: Path):
    orders = [_order(tree / "keep", status="proposed")]
    rows = apply_orders(orders, roots=[tree])
    assert rows == []


def test_apply_orders_quarantines_an_approved_delete(tree: Path):
    target = tree / "keep"
    orders = [_order(target, action="delete", pid=7)]
    rows = apply_orders(orders, roots=[tree])
    assert len(rows) == 1
    assert rows[0]["proposal_id"] == 7
    assert rows[0]["outcome"] == "applied"
    assert not target.exists()  # quarantined, not deleted -- reversible


def test_apply_orders_review_action_is_review_only(tree: Path):
    orders = [_order(tree / "keep", action="review", cls="model-weights")]
    rows = apply_orders(orders, roots=[tree])
    assert rows[0]["outcome"] == "review-only"
    assert (tree / "keep").exists()  # review never touches the tree


def test_apply_orders_prune_engine_without_podman_is_refused(tree: Path, monkeypatch):
    monkeypatch.setattr("awstorage.node_run.podman_available", lambda: False)
    orders = [_order(tree, action="prune-engine", cls="container-store")]
    rows = apply_orders(orders, roots=[tree])
    assert rows[0]["outcome"] == "refused"
    assert "engine hook" in rows[0]["detail"]


def test_apply_orders_multiple_orders_each_get_a_ledger_row(tree: Path):
    a = tree / "keep"
    b = _mk(tree / "other", "x.bin", 10)
    orders = [_order(a, pid=1, action="delete"), _order(b, pid=2, action="review")]
    rows = apply_orders(orders, roots=[tree])
    assert {r["proposal_id"] for r in rows} == {1, 2}


# --------------------------------------------------------------------- run_once


def test_run_once_scans_and_pushes_with_no_orders(tree: Path):
    client = _FakeClient(orders=[])
    summary = run_once(client, node_id="test-node", roots=[tree])
    assert summary["entries_written"] > 0
    assert summary["applied"] == []
    assert summary["reported"] is None  # nothing to report -- no rows
    assert not summary["errors"]
    ingest_calls = [c for c in client.calls if c[0] == "storage_ingest_scan"]
    assert ingest_calls  # the scan of `tree` was pushed


def test_run_once_applies_and_reports_an_order(tree: Path):
    order = _order(tree / "keep", pid=3)
    client = _FakeClient(orders=[order])
    summary = run_once(client, node_id="test-node", roots=[tree])
    assert len(summary["applied"]) == 1
    assert summary["applied"][0]["proposal_id"] == 3
    assert summary["reported"] == {"written": 1}
    report_calls = [c for c in client.calls if c[0] == "storage_report_apply"]
    assert len(report_calls) == 1
    reported_rows = json.loads(report_calls[0][1]["rows_json"])
    assert reported_rows[0]["proposal_id"] == 3


def test_run_once_raises_when_the_whole_pass_writes_nothing(tree: Path):
    """The core contract: a pass that ran clean but recorded zero entries
    anywhere is a FAILURE, never a quiet success."""
    client = _FakeClient(orders=[], ingest_entries=0)
    with pytest.raises(GatewayError, match="wrote 0 entries"):
        run_once(client, node_id="test-node", roots=[tree])


def test_run_once_unknown_collector_is_recorded_not_raised(tree: Path):
    client = _FakeClient(orders=[])
    summary = run_once(client, node_id="test-node", roots=[tree], collectors=["nope"])
    assert any("nope" in e for e in summary["errors"])
    assert summary["entries_written"] > 0  # the root scan still succeeded


def test_run_once_missing_root_is_recorded_not_raised(tmp_path: Path):
    good = tmp_path / "good"
    _mk(good, "f.bin", 10)
    missing = tmp_path / "does-not-exist"
    client = _FakeClient(orders=[])
    summary = run_once(client, node_id="test-node", roots=[good, missing])
    assert any(str(missing).replace("\\", "/") in e or "does-not-exist" in e
               for e in summary["errors"])
    assert summary["entries_written"] > 0  # `good` still pushed


# --------------------------------------------------------------------- run_loop


def test_run_loop_once_success_returns_0(tree: Path, monkeypatch):
    inner = _FakeClient(orders=[])
    monkeypatch.setattr("awstorage.node_run.GatewayClient",
                        lambda *a, **k: _FakeConnectingClient(inner=inner))
    rc = run_loop(once=True, node_id="test-node", roots=[tree])
    assert rc == 0


def test_run_loop_once_zero_entries_returns_1(tree: Path, monkeypatch):
    inner = _FakeClient(orders=[], ingest_entries=0)
    monkeypatch.setattr("awstorage.node_run.GatewayClient",
                        lambda *a, **k: _FakeConnectingClient(inner=inner))
    rc = run_loop(once=True, node_id="test-node", roots=[tree])
    assert rc == 1


def test_run_loop_once_unreachable_gateway_returns_2(tree: Path, monkeypatch):
    monkeypatch.setattr("awstorage.node_run.GatewayClient",
                        lambda *a, **k: _FakeConnectingClient(fail=True))
    rc = run_loop(once=True, node_id="test-node", roots=[tree])
    assert rc == 2


def test_run_loop_not_once_stops_after_one_pass_when_told(tree: Path, monkeypatch):
    """`once=True` must never sleep -- a hung test here would mean the loop
    forgot to check `once` before its `time.sleep`."""
    inner = _FakeClient(orders=[])
    monkeypatch.setattr("awstorage.node_run.GatewayClient",
                        lambda *a, **k: _FakeConnectingClient(inner=inner))
    monkeypatch.setattr(time, "sleep", lambda _s: pytest.fail("run_loop slept with once=True"))
    rc = run_loop(once=True, node_id="test-node", roots=[tree], interval_s=9999)
    assert rc == 0


# ------------------------------------------------------------ card orders (A7)

def _manage_world(tmp_path: Path, *, card_over: dict | None = None, sign: bool = True):
    import hashlib
    import os

    from awstorage import manage
    from awstorage.catalog import Catalog

    root = tmp_path / "vol"
    data = b"dupe" * 300
    paths = []
    for rel in ("k/f.bin", "copy/f.bin"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        paths.append(p)
    sha = hashlib.sha256(data).hexdigest()
    rows = []
    for p in paths:
        st = os.stat(p)
        rows.append({"node": "test-node", "path": str(p), "bytes": st.st_size,
                     "mtime_ns": st.st_mtime_ns, "sha256": sha, "dev": st.st_dev,
                     "ino": st.st_ino, "nlink": 1})
    [prop] = manage.propose_dupes([{"sha256": sha, "bytes": len(data), "paths": rows}],
                                  node="test-node")
    prop.id, prop.status, prop.card_id = 41, "approved", "d-41"
    from tests.attest_util import sign_card

    card = {"id": "d-41", "status": "answered", "answer": "approve",
            "answered_via": "desk", "answered_by": "owner@test",
            "facts": manage.card_spec(prop)["facts"]}
    if sign:
        sign_card(card)
    card.update(card_over or {})
    order_row = {"id": 41, "node": "test-node", "path": prop.path, "action": "quarantine-copy",
                 "bytes": prop.bytes, "cls": "dedup", "status": "approved"}
    local = Catalog(tmp_path / "node-manage.db")
    return root, paths, prop, card, order_row, local


class _ManageClient(_FakeClient):
    def __init__(self, orders, order_body):
        super().__init__(orders=orders)
        self._order_body = order_body

    def call_tool(self, name, args):
        if name == "storage_manage_order":
            self.calls.append((name, args))
            return self._order_body
        if name == "storage_manage_report":
            self.calls.append((name, args))
            return {"updated": len(json.loads(args["rows_json"]))}
        return super().call_tool(name, args)


def test_dispatch_covers_the_one_vocabulary():
    from awstorage.node_run import DISPATCH, _card_order, _policy_order
    from awstorage.policy import ACTIONS, CARD_ACTIONS

    assert set(DISPATCH) == set(ACTIONS)
    assert all(DISPATCH[a] is _card_order for a in CARD_ACTIONS)
    assert all(DISPATCH[a] is _policy_order for a in set(ACTIONS) - set(CARD_ACTIONS))


@pytest.fixture
def attested(monkeypatch):
    """One owner (owner@test) and the test signing key provisioned."""
    from awstorage import manage

    from tests.attest_util import pubkey_env

    monkeypatch.setenv(manage.OWNERS_ENV, "owner@test")
    pubkey_env(monkeypatch)


def test_card_order_refused_without_a_signed_receipt(tmp_path: Path, attested):
    from awstorage.node_run import ManageContext

    root, paths, prop, card, order_row, local = _manage_world(tmp_path, sign=False)
    try:
        ctx = ManageContext(fetch_order=lambda pid: {"order": prop.to_dict(), "card": card},
                            catalog=local)
        [row] = apply_orders([order_row], roots=[root], manage=ctx)
        assert row["outcome"] == "refused" and "receipt" in row["detail"]
        assert all(p.exists() for p in paths)
    finally:
        local.close()


def test_card_order_routes_to_apply_manage_with_its_card_and_runs_once(tmp_path: Path,
                                                                       attested):
    from awstorage.node_run import ManageContext
    from awstorage.remote import fetch_manage_order

    root, paths, prop, card, order_row, local = _manage_world(tmp_path)
    client = _ManageClient([order_row], {"order": prop.to_dict(), "card": card})
    ctx = ManageContext(fetch_order=lambda pid: fetch_manage_order(client, "test-node", pid),
                        catalog=local)
    try:
        summary = run_once(client, node_id="test-node", roots=[root], manage=ctx)
        assert [r["outcome"] for r in summary["applied"]] == ["applied"]
        assert paths[0].exists() and not paths[1].exists()
        reported = json.loads([c for c in client.calls
                               if c[0] == "storage_report_apply"][0][1]["rows_json"])
        assert {r["outcome"] for r in reported} == {"applied", "quarantined"}
        assert any(c[0] == "storage_manage_report" for c in client.calls)
        # a second pass never re-executes the same order
        again = apply_orders([order_row], roots=[root], manage=ctx)
        assert again[0]["outcome"] == "already-executed"
        assert sum(1 for c in client.calls if c[0] == "storage_manage_order") == 1
    finally:
        local.close()


@pytest.mark.parametrize("over", [{"answered_via": "agent"}, {"answer_receipt": None},
                                  {"answer_attested": True, "answer_receipt": None},
                                  {"id": "d-other"},
                                  {"facts": ["proposal_id: 7"]}, {"answer": "reject"}])
def test_card_order_with_a_forged_card_is_refused(tmp_path: Path, over, attested):
    from awstorage.node_run import ManageContext

    root, paths, prop, card, order_row, local = _manage_world(tmp_path, card_over=over)
    try:
        ctx = ManageContext(fetch_order=lambda pid: {"order": prop.to_dict(), "card": card},
                            catalog=local)
        [row] = apply_orders([order_row], roots=[root], manage=ctx)
        assert row["outcome"] == "refused"
        assert all(p.exists() for p in paths)
    finally:
        local.close()


def test_card_order_without_manage_context_is_refused_never_policy_applied(tmp_path: Path):
    root, paths, prop, card, order_row, local = _manage_world(tmp_path)
    local.close()
    [row] = apply_orders([order_row], roots=[root])
    assert row["outcome"] == "refused" and "card-only" in row["detail"]
    assert all(p.exists() for p in paths)


def test_every_exception_is_a_ledger_row(tmp_path: Path):
    from awstorage.node_run import ManageContext

    root, paths, prop, card, order_row, local = _manage_world(tmp_path)

    def boom(pid):
        raise RuntimeError("genesis exploded")

    try:
        [row] = apply_orders([order_row], roots=[root],
                             manage=ManageContext(fetch_order=boom, catalog=local))
        assert row["outcome"] == "failed" and "genesis exploded" in row["detail"]
    finally:
        local.close()


def test_legacy_dotted_order_is_dispatched_as_card_only(tmp_path: Path):
    root, paths, prop, card, order_row, local = _manage_world(tmp_path)
    local.close()
    [row] = apply_orders([{**order_row, "action": "dedup.quarantine_copies"}], roots=[root])
    assert row["outcome"] == "refused" and row["action"] == "quarantine-copy"


# ------------------------------------------------------------------ --orders-only


class _FailingFetchClient(_FakeClient):
    def call_tool(self, name: str, args: dict):
        if name == "storage_requests":
            self.calls.append((name, args))
            return {"error": "simulated: Genesis down"}
        return super().call_tool(name, args)


def test_orders_only_applies_and_reports_but_never_scans(tree: Path):
    """`node-run --orders-only` (awstorage-scan.sh, after its own scans): orders are
    applied and reported; no root is walked and nothing is pushed a second time."""
    client = _FakeClient(orders=[_order(tree / "keep", pid=4)])
    summary = run_once(client, node_id="test-node", roots=[tree], orders_only=True)
    assert [r["proposal_id"] for r in summary["applied"]] == [4]
    names = [c[0] for c in client.calls]
    assert "storage_report_apply" in names and "storage_ingest_scan" not in names


def test_orders_only_with_no_orders_is_success_not_zero_entries(tree: Path, monkeypatch):
    inner = _FakeClient(orders=[], ingest_entries=0)
    monkeypatch.setattr("awstorage.node_run.GatewayClient",
                        lambda *a, **k: _FakeConnectingClient(inner=inner))
    assert run_loop(once=True, node_id="test-node", roots=[tree], orders_only=True) == 0
    assert [c[0] for c in inner.calls] == ["storage_requests"]


def test_orders_only_failed_fetch_exits_1(tree: Path, monkeypatch):
    inner = _FailingFetchClient(orders=[])
    monkeypatch.setattr("awstorage.node_run.GatewayClient",
                        lambda *a, **k: _FakeConnectingClient(inner=inner))
    assert run_loop(once=True, node_id="test-node", roots=[tree], orders_only=True) == 1


def test_cli_node_run_has_orders_only(capsys):
    from awstorage.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["node-run", "--help"])
    assert exc.value.code == 0 and "--orders-only" in capsys.readouterr().out


# ------------------------------------------------- archive card orders, wired by default


def _archive_world(tmp_path: Path):
    import hashlib
    import os

    from awstorage import manage
    from awstorage.catalog import Catalog

    from .attest_util import sign_card

    root = tmp_path / "vol"
    f = root / "logs" / "old.log"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"A" * 3000)
    st = os.stat(f)
    member = {"path": str(f), "bytes": st.st_size, "mtime_ns": st.st_mtime_ns,
              "sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "dev": st.st_dev,
              "ino": st.st_ino, "nlink": 1}
    prop = manage.propose_archive("test-node", member)
    prop.id, prop.status, prop.card_id = 51, "approved", "d-51"
    card = {"id": "d-51", "status": "answered", "answer": "approve",
            "answered_via": "desk", "answered_by": "owner@test",
            "facts": manage.card_spec(prop)["facts"]}
    sign_card(card)
    order_row = {"id": 51, "node": "test-node", "path": prop.path, "action": "archive",
                 "bytes": prop.bytes, "cls": "archive", "status": "approved"}
    return root, f, prop, card, order_row, Catalog(tmp_path / "node-manage.db")


def test_default_context_without_a_strata_credential_refuses_archive(tmp_path: Path,
                                                                     attested):
    from awstorage.node_run import default_manage_context

    root, f, prop, card, order_row, local = _archive_world(tmp_path)
    local.close()
    client = _ManageClient([order_row], {"order": prop.to_dict(), "card": card})
    ctx = default_manage_context(client, "test-node", db=tmp_path / "ctx.db", env={})
    try:
        assert ctx.strata_hook is None and ctx.readback_hook is None
        assert ctx.share_hook is None
        [row] = apply_orders([order_row], roots=[root], manage=ctx)
        assert row["outcome"] == "refused" and "read-back" in row["detail"]
        assert f.exists()
    finally:
        ctx.catalog.close()


def test_default_context_runs_an_archive_order_into_strata(tmp_path: Path, attested,
                                                          monkeypatch):
    from awstorage import strata
    from awstorage.node_run import default_manage_context

    from .strata_pool_stub import KEY, PoolStub

    pool = PoolStub()

    class _Http(strata.StrataTarget):  # the stub is plain http; the switch is explicit
        def __init__(self, tier, **kw):
            kw.pop("url", None)
            super().__init__(tier, url=pool.url, insecure_http_for_tests=True, **kw)

    monkeypatch.setattr(strata, "StrataTarget", _Http)
    root, f, prop, card, order_row, local = _archive_world(tmp_path)
    local.close()
    client = _ManageClient([order_row], {"order": prop.to_dict(), "card": card})
    ctx = default_manage_context(client, "test-node", db=tmp_path / "ctx.db",
                                 env={strata.KEY_ENV: KEY,
                                      "AWSTORAGE_SHARE_ROOT": str(tmp_path / "shares")})
    try:
        assert ctx.strata_hook and ctx.readback_hook and ctx.share_hook
        [row] = apply_orders([order_row], roots=[root], manage=ctx)
        assert row["outcome"] == "applied", row
        assert pool.objects[prop.params["strata_path"]] == b"A" * 3000
        assert not f.exists()  # quarantined only after the independent read-back
    finally:
        pool.close()
        ctx.catalog.close()
