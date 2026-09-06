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
