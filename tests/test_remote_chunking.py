"""remote.py: chunking, the wire protocol, and the zero-entries refusal.

A real (loopback, ephemeral-port) HTTP server stands in for the MCP gateway
so these tests prove the actual bytes-on-the-wire behaviour -- session
handshake, tools/call dispatch, and the 8 MB-per-part contract -- rather than
mocking `urllib` and trusting the mock matches the real shape.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from awstorage.remote import (
    GatewayClient,
    GatewayError,
    _chunk_trees,
    fetch_requests,
    push_snapshot,
    report_apply,
)


def _tree(i: int, size: int = 1024) -> dict:
    return {
        "path": f"E:/vol/tree-{i:05d}", "depth": 1, "bytes": size, "files": 10,
        "dirs": 2, "newest_mtime": 1756000000.0, "oldest_mtime": 1700000000.0,
        "fingerprint": f"sha1:{i:016x}", "cls": "build-temp", "refetchable": True,
        "confidence": 0.8, "reason": "test fixture", "source": "heuristic", "git": False,
    }


def _snapshot(n_trees: int) -> dict:
    return {
        "schema": 1, "node": "test-node", "root": "E:/vol", "taken_at": "2026-09-01T00:00:00+00:00",
        "max_depth": 1, "time_budget_s": 300.0, "truncated": False,
        "trees": [_tree(i) for i in range(n_trees)],
        "top_files": [{"path": "E:/vol/big.bin", "bytes": 999, "mtime": 1756000000.0}],
        "errors": [], "error_count": 0, "elapsed_s": 1.0,
    }


class _FakeGatewayHandler(BaseHTTPRequestHandler):
    """A minimal MCP-shaped JSON-RPC endpoint: initialize -> session id;
    tools/call -> counts trees in the pushed snapshot / echoes requests."""

    protocol_version = "HTTP/1.1"
    calls: list[dict] = []  # class-level, reset per test via server.calls_reset()
    force_zero_entries = False
    force_error = False
    force_detail_error = False  # a FastAPI HTTPException body: {"detail": "..."}, no "error" key

    def log_message(self, *_a):  # silence stdout during tests
        pass

    def do_POST(self):  # noqa: N802 -- stdlib handler name
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        method = body.get("method")
        if method == "initialize":
            payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                                  "result": {"protocolVersion": "2025-06-18"}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "sess-fake-1")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "tools/call":
            name = body["params"]["name"]
            args = body["params"]["arguments"]
            type(self).calls.append({"name": name, "args": args})
            result = self._tool_result(name, args)
            payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                                  "result": {"content": [{"type": "text",
                                                          "text": json.dumps(result)}]}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _tool_result(self, name: str, args: dict) -> dict:
        if type(self).force_detail_error:
            # what a rejected in-network HTTP call actually looks like once it
            # reaches `mcp_awstorage._get/_post` -- those wrap a NETWORK
            # exception as {"error": ...} but pass an HTTP error status's own
            # JSON body through untouched, and FastAPI's default body for a
            # raised HTTPException is {"detail": "..."}, never {"error": ...}.
            return {"detail": "Authentication required"}
        if type(self).force_error:
            return {"error": "forced test failure"}
        if name == "storage_ingest_scan":
            part_len = len(args["snapshot_json"].encode("utf-8"))
            assert part_len <= 8 * 1024 * 1024, f"part exceeded 8MB cap: {part_len}"
            if type(self).force_zero_entries:
                return {"snapshot_id": 1, "trees": 0}
            snap = json.loads(args["snapshot_json"])
            return {"snapshot_id": 1, "trees": len(snap.get("trees", [])),
                    "entries_written": len(snap.get("trees", []))}
        if name == "storage_report_apply":
            rows = json.loads(args["rows_json"])
            return {"written": len(rows)}
        if name == "storage_requests":
            return {"node_id": args["node_id"], "orders": [], "count": 0}
        return {"error": f"unknown tool {name!r}"}


@pytest.fixture
def gateway():
    _FakeGatewayHandler.calls = []
    _FakeGatewayHandler.force_zero_entries = False
    _FakeGatewayHandler.force_error = False
    _FakeGatewayHandler.force_detail_error = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeGatewayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/mcp"
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def bearer_file(tmp_path: Path) -> Path:
    p = tmp_path / "session-bearer"
    p.write_text("test-bearer-token\n", encoding="utf-8")
    return p


def _client(gateway: str, bearer_file: Path) -> GatewayClient:
    return GatewayClient(base_url=gateway, bearer_file=bearer_file).connect()


# --------------------------------------------------------------------- chunking


def test_chunk_trees_stays_under_cap():
    trees = [_tree(i, size=2048) for i in range(500)]
    big_trees = [json.dumps(t) for t in trees]
    avg_len = sum(len(s) for s in big_trees) // len(big_trees)
    max_bytes = avg_len * 10  # force multiple chunks
    chunks = _chunk_trees(trees, max_bytes)
    assert len(chunks) > 1
    for c in chunks:
        size = len(json.dumps(c, separators=(",", ":")).encode("utf-8"))
        assert size <= max_bytes
    # nothing lost or duplicated across chunks
    flat = [t["path"] for c in chunks for t in c]
    assert flat == [t["path"] for t in trees]


def test_chunk_trees_oversize_single_tree_gets_its_own_chunk():
    small = _tree(0, size=1)
    huge = dict(_tree(1), reason="x" * 5000)
    chunks = _chunk_trees([small, huge], max_bytes=1000)
    assert len(chunks) == 2
    assert chunks[1] == [huge]


def test_chunk_trees_empty_list_yields_one_empty_chunk():
    assert _chunk_trees([], max_bytes=1000) == [[]]


# ---------------------------------------------------------------------- push


def test_push_snapshot_30mb_splits_into_parts_under_8mb(gateway, bearer_file):
    client = _client(gateway, bearer_file)
    snap = _snapshot(n_trees=20000)  # each tree ~250B serialized -> ~5MB+ total
    result = push_snapshot(client, "test-node", snap, max_bytes=8 * 1024 * 1024)
    assert result["entries_written"] == 20000
    assert result["parts"] >= 1
    ingest_calls = [c for c in _FakeGatewayHandler.calls if c["name"] == "storage_ingest_scan"]
    assert len(ingest_calls) == result["parts"]
    for call in ingest_calls:
        assert len(call["args"]["snapshot_json"].encode("utf-8")) <= 8 * 1024 * 1024


def test_push_snapshot_small_is_one_part(gateway, bearer_file):
    client = _client(gateway, bearer_file)
    snap = _snapshot(n_trees=5)
    result = push_snapshot(client, "test-node", snap)
    assert result["parts"] == 1
    assert result["entries_written"] == 5


def test_push_snapshot_no_trees_refused(gateway, bearer_file):
    client = _client(gateway, bearer_file)
    snap = _snapshot(n_trees=0)
    with pytest.raises(GatewayError, match="no trees"):
        push_snapshot(client, "test-node", snap)


def test_push_snapshot_zero_entries_written_is_a_failure(gateway, bearer_file):
    """The core contract: a push that the fleet accepted but recorded NOTHING
    for is a FAILED push, never a silent no-op success."""
    _FakeGatewayHandler.force_zero_entries = True
    client = _client(gateway, bearer_file)
    snap = _snapshot(n_trees=3)
    with pytest.raises(GatewayError, match="wrote 0 entries"):
        push_snapshot(client, "test-node", snap)


def test_push_snapshot_tool_error_is_refused(gateway, bearer_file):
    _FakeGatewayHandler.force_error = True
    client = _client(gateway, bearer_file)
    snap = _snapshot(n_trees=3)
    with pytest.raises(GatewayError, match="refused"):
        push_snapshot(client, "test-node", snap)


def test_push_snapshot_part_and_parts_fields_sent(gateway, bearer_file):
    client = _client(gateway, bearer_file)
    snap = _snapshot(n_trees=20000)
    push_snapshot(client, "test-node", snap, max_bytes=1024 * 1024)
    ingest_calls = [c for c in _FakeGatewayHandler.calls if c["name"] == "storage_ingest_scan"]
    assert len(ingest_calls) > 1
    total_parts = ingest_calls[0]["args"]["parts"]
    for i, call in enumerate(ingest_calls, start=1):
        assert call["args"]["part"] == i
        assert call["args"]["parts"] == total_parts


# --------------------------------------------------------------- other calls


def test_fetch_requests_round_trip(gateway, bearer_file):
    client = _client(gateway, bearer_file)
    out = fetch_requests(client, "test-node")
    assert out["node_id"] == "test-node"
    assert out["orders"] == []


def test_report_apply_round_trip(gateway, bearer_file):
    client = _client(gateway, bearer_file)
    rows = [{"proposal_id": 1, "path": "E:/x", "action": "delete",
             "outcome": "applied", "bytes": 100, "detail": "quarantined"}]
    out = report_apply(client, "test-node", rows)
    assert out["written"] == 1


def test_report_apply_empty_rows_is_a_noop_not_a_call(gateway, bearer_file):
    client = _client(gateway, bearer_file)
    out = report_apply(client, "test-node", [])
    assert out["written"] == 0
    assert "skipped" in out  # distinguishes a no-op from a failed report
    assert not any(c["name"] == "storage_report_apply" for c in _FakeGatewayHandler.calls)


def test_fetch_requests_detail_shaped_error_is_refused_not_empty(gateway, bearer_file):
    """A 401/403 from the underlying genesis route reaches here as FastAPI's
    own {"detail": ...} body, not {"error": ...} -- and must not be read as
    'zero orders', or a human-approved order silently never applies again."""
    _FakeGatewayHandler.force_detail_error = True
    client = _client(gateway, bearer_file)
    with pytest.raises(GatewayError, match="Authentication required"):
        fetch_requests(client, "test-node")


def test_report_apply_detail_shaped_error_is_refused_not_silent(gateway, bearer_file):
    _FakeGatewayHandler.force_detail_error = True
    client = _client(gateway, bearer_file)
    rows = [{"proposal_id": 1, "path": "E:/x", "action": "delete",
             "outcome": "applied", "bytes": 100, "detail": "quarantined"}]
    with pytest.raises(GatewayError, match="Authentication required"):
        report_apply(client, "test-node", rows)


# ------------------------------------------------------------------- bearer


def test_missing_bearer_file_raises_gateway_error(gateway, tmp_path: Path):
    client = GatewayClient(base_url=gateway, bearer_file=tmp_path / "nope")
    with pytest.raises(GatewayError, match="cannot read bearer"):
        client.connect()


def test_empty_bearer_file_raises_gateway_error(gateway, tmp_path: Path):
    p = tmp_path / "empty-bearer"
    p.write_text("", encoding="utf-8")
    client = GatewayClient(base_url=gateway, bearer_file=p)
    with pytest.raises(GatewayError, match="is empty"):
        client.connect()


def test_unreachable_gateway_raises_gateway_error(bearer_file):
    client = GatewayClient(base_url="http://127.0.0.1:1/mcp", bearer_file=bearer_file,
                            timeout_s=2.0)
    with pytest.raises(GatewayError, match="unreachable"):
        client.connect()
