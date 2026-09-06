"""remote.py -- the gateway client a node runner uses to push what it found.

Genesis publishes NO host port (the LBs are retired, and Strata's own port is
not mirrored to the host either) -- so the one sanctioned path from a node's
disk to the fleet catalog is through the MCP gateway's `tools/call`, the same
wire protocol every other host-side client on this platform speaks (verified
against the live gateway 2026-08-25; see `awdelphi.gateway` for the sibling
implementation this one mirrors, stdlib-only where that one uses httpx):

    POST {base_url}  initialize             -> Mcp-Session-Id header
    POST {base_url}  notifications/initialized
    POST {base_url}  tools/call             -> JSON or text/event-stream

Two tools carry a node runner's whole job: `storage_ingest_scan` (a snapshot,
one chunk at a time) and `storage_report_apply` (ledger rows for what the
node just did). `storage_requests` reads back what a human approved for this
node. There is deliberately no tool this client can use to APPROVE anything
of its own -- see `policy.py`'s authorization pipeline; a node runner only
ever acts on an order it received, never one it invented.

**Never `verify=False`.** An https gateway is verified against a CA candidate
if this host has one installed (the fleet's internal root), or the platform
default trust store otherwise -- never with certificate checking disabled.
Auth is a bearer token read fresh from `~/.aither/session-bearer` (or
`--bearer-file`) on every connect, matching the fleet-wide credential
doctrine: a session picks up a rotated bearer without a restart.

**A push that writes nothing is a failure, not an empty success.** Genesis
caps a part at 8 MB and 50,000 trees and 413s past either; `push_snapshot`
chunks by SIZE (never assumes a tree count is safe) and refuses to report
success when the fleet wrote zero entries for what was pushed -- a silent
zero here is indistinguishable from "nothing changed on disk", and it is
usually "the push failed".
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from . import __version__

DEFAULT_GATEWAY_URL = os.environ.get("AWSTORAGE_GATEWAY", "http://127.0.0.1:8182/mcp")
DEFAULT_BEARER_FILE = Path.home() / ".aither" / "session-bearer"
PROTOCOL_VERSION = "2025-06-18"

# Genesis's own cap (routers/storage.py MAX_PART_BYTES); a safety margin is
# subtracted before chunking so our size ESTIMATE (per-tree json.dumps, no
# separators) never lands right on the server's real Content-Length check.
MAX_PART_BYTES = 8 * 1024 * 1024
_CHUNK_SAFETY_MARGIN = 512 * 1024

_CA_CANDIDATES = (
    Path(r"C:/AitherOS-Data/Library/Data/tls/ca-chain.pem"),
    Path("/app/AitherOS/Library/Data/tls/ca-chain.pem"),
    Path("/etc/aither/tls/ca-chain.pem"),
)


class GatewayError(RuntimeError):
    """The gateway refused, was unreachable, or returned something unusable."""


def resolve_ca() -> str | None:
    for cand in _CA_CANDIDATES:
        if cand.is_file():
            return str(cand)
    return None


def _ssl_context(url: str) -> ssl.SSLContext | None:
    """None for a plain-http base url (the local gateway); for https, a
    verifying context -- against a fleet CA if one is installed on this
    host, the platform trust store otherwise. Certificate checking is never
    disabled."""
    if not url.lower().startswith("https://"):
        return None
    ca = resolve_ca()
    return ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()


class GatewayClient:
    """A tiny MCP client: handshake once, call tools, re-handshake on a lost
    session. Mirrors `awdelphi.gateway.GatewayClient`'s verified wire
    behaviour with stdlib `urllib` instead of `httpx` -- this package speaks
    to nothing else, by design (see the package docstring)."""

    def __init__(self, base_url: str | None = None, bearer_file: Path | str | None = None,
                 timeout_s: float = 60.0) -> None:
        self.base_url = (base_url or DEFAULT_GATEWAY_URL).rstrip("/")
        self.bearer_file = Path(bearer_file) if bearer_file else DEFAULT_BEARER_FILE
        self.timeout_s = timeout_s
        self._session_id: str | None = None
        self._ctx = _ssl_context(self.base_url)

    # ------------------------------------------------------------------ auth

    def _bearer(self) -> str:
        try:
            token = self.bearer_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise GatewayError(
                f"cannot read bearer at {self.bearer_file} -- run "
                "`python AitherOS/dev/tools/mint_session_bearer.py` to mint one"
            ) from exc
        if not token:
            raise GatewayError(f"bearer file {self.bearer_file} is empty -- run "
                                "`python AitherOS/dev/tools/mint_session_bearer.py`")
        return token

    def _headers(self, with_session: bool = True) -> dict:
        headers = {
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self._bearer()}",
        }
        if with_session and self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    # ------------------------------------------------------------- transport

    def _raw_post(self, body: dict, headers: dict) -> tuple[int, Any, bytes]:
        """POST one JSON-RPC message. Returns (status, headers-object, body-bytes).
        `headers` supports case-insensitive `.get()` (an HTTPMessage), whether
        the call succeeded or the server answered with an error status."""
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base_url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s,  # noqa: S310
                                         context=self._ctx) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()
        except urllib.error.URLError as exc:
            raise GatewayError(f"gateway unreachable at {self.base_url}: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise GatewayError(f"gateway unreachable at {self.base_url}: {exc}") from exc

    # ---------------------------------------------------------------- wire

    def connect(self) -> "GatewayClient":
        """initialize + notifications/initialized; returns self."""
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "awstorage", "version": __version__},
            },
        }
        status, headers, _raw = self._raw_post(body, self._headers(with_session=False))
        if status in (401, 403):
            raise GatewayError(
                f"gateway refused ({status}) -- re-mint the session bearer: "
                "`python AitherOS/dev/tools/mint_session_bearer.py`")
        if status >= 400:
            raise GatewayError(f"gateway handshake failed: HTTP {status}")
        session = headers.get("Mcp-Session-Id") if headers is not None else None
        if not session:
            raise GatewayError("gateway did not return Mcp-Session-Id on initialize")
        self._session_id = session
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    expect_result=False)
        return self

    def _post(self, body: dict, expect_result: bool = True) -> Any:
        status, headers, raw = self._raw_post(body, self._headers())
        if status in (401, 403):
            raise GatewayError(
                f"gateway refused ({status}) -- re-mint the session bearer: "
                "`python AitherOS/dev/tools/mint_session_bearer.py`")
        if status == 404:
            raise GatewayError("session lost -- re-handshake required")
        if status >= 400:
            raise GatewayError(f"gateway call failed: HTTP {status}")
        # A notification (and HTTP 202) carries NO response body -- that is the
        # streamable-HTTP spec, not a broken gateway (see awdelphi.gateway).
        if status == 202 or not expect_result:
            return None
        if not raw.strip():
            raise GatewayError(f"gateway returned an EMPTY body for HTTP {status}")
        content_type = headers.get("Content-Type", "") if headers is not None else ""
        payload = _parse_response(raw, content_type)
        if payload.get("error"):
            raise GatewayError(f"gateway error: {payload['error']}")
        return payload.get("result")

    def call_tool(self, name: str, args: dict) -> Any:
        """Call one MCP tool; returns the parsed result. Re-handshakes once on
        a lost session (404), then re-issues the call."""
        body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": name, "arguments": args}}
        try:
            result = self._post(body)
        except GatewayError as exc:
            if "session lost" not in str(exc):
                raise
            self._session_id = None
            self.connect()
            result = self._post(body)
        return _extract_text_result(result)


def _parse_response(raw: bytes, content_type: str) -> dict:
    """Parse a JSON-RPC response that may be plain JSON or text/event-stream."""
    text = raw.decode("utf-8", errors="replace")
    if "text/event-stream" in (content_type or ""):
        for line in text.splitlines():
            if line.startswith("data:"):
                candidate = line[5:].strip()
                try:
                    payload = json.loads(candidate)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict) and ("result" in payload or "error" in payload):
                    return payload
        raise GatewayError("gateway SSE response carried no JSON-RPC result")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GatewayError(f"gateway returned non-JSON: {text[:200]!r}") from exc
    if not isinstance(payload, dict):
        raise GatewayError(f"gateway returned an unusable payload: {payload!r}")
    return payload


def _extract_text_result(result: Any) -> Any:
    """MCP tools/call returns {content: [{type: text, text: ...}], isError}."""
    if not isinstance(result, dict):
        return result
    if result.get("isError"):
        raise GatewayError(f"tool error: {result.get('content', [])!r}")
    texts: list[str] = []
    for item in result.get("content", []) or []:
        if isinstance(item, dict) and item.get("type") == "text":
            texts.append(item.get("text", ""))
    if not texts:
        return result.get("result", result)
    joined = "\n".join(texts).strip()
    try:
        return json.loads(joined)
    except (json.JSONDecodeError, TypeError):
        return joined


# ---------------------------------------------------------------------------
# awstorage-shaped operations over the wire
# ---------------------------------------------------------------------------


def _chunk_trees(trees: list[dict], max_bytes: int) -> list[list[dict]]:
    """Split `trees` into groups whose SERIALIZED size stays under `max_bytes`.
    A single tree larger than the cap still gets its own chunk (never dropped,
    never split mid-object) -- the caller/server decides what to do with an
    oversize part."""
    chunks: list[list[dict]] = []
    current: list[dict] = []
    current_bytes = 2  # "[" + "]"
    for t in trees:
        t_bytes = len(json.dumps(t, separators=(",", ":")).encode("utf-8")) + 1
        if current and current_bytes + t_bytes > max_bytes:
            chunks.append(current)
            current = []
            current_bytes = 2
        current.append(t)
        current_bytes += t_bytes
    if current or not chunks:
        chunks.append(current)
    return chunks


def _part_snapshot(base: dict, trees: list[dict], *, include_top_files: bool) -> dict:
    part = {k: v for k, v in base.items() if k not in ("trees", "top_files")}
    part["trees"] = trees
    part["top_files"] = list(base.get("top_files", [])) if include_top_files else []
    return part


def push_snapshot(client: GatewayClient, node_id: str, snapshot: dict,
                   *, max_bytes: int = MAX_PART_BYTES) -> dict:
    """Push one snapshot to Genesis through `storage_ingest_scan`, chunked so
    no part exceeds `max_bytes` serialized. Raises GatewayError -- refusing to
    report success -- when the fleet wrote zero entries for what was sent, or
    when any part is refused outright (a non-2xx from the tool)."""
    trees = list(snapshot.get("trees", []))
    if not trees:
        raise GatewayError(
            f"push refused: snapshot for {node_id}:{snapshot.get('root')} has no trees")
    safe_max = max(64 * 1024, int(max_bytes) - _CHUNK_SAFETY_MARGIN)
    chunks = _chunk_trees(trees, safe_max)
    parts = len(chunks)
    entries_written = 0
    results = []
    for i, chunk in enumerate(chunks, start=1):
        part_snap = _part_snapshot(snapshot, chunk, include_top_files=(i == 1))
        snapshot_json = json.dumps(part_snap, separators=(",", ":"))
        result = client.call_tool("storage_ingest_scan", {
            "node_id": node_id, "snapshot_json": snapshot_json,
            "part": i, "parts": parts,
        })
        if isinstance(result, dict) and result.get("error"):
            raise GatewayError(
                f"push part {i}/{parts} for {node_id}:{snapshot.get('root')} "
                f"refused: {result['error']}")
        written = 0
        if isinstance(result, dict):
            written = int(result.get("entries_written", result.get("trees", 0)) or 0)
        entries_written += written
        results.append(result)
    if entries_written == 0:
        raise GatewayError(
            f"push for {node_id}:{snapshot.get('root')} wrote 0 entries across "
            f"{parts} part(s) -- treated as a FAILED push, not an empty one")
    return {"node_id": node_id, "root": snapshot.get("root"), "parts": parts,
            "entries_written": entries_written, "results": results}


def push_snapshots(client: GatewayClient, node_id: str, snapshots: Iterable[dict],
                    *, max_bytes: int = MAX_PART_BYTES) -> list[dict]:
    """`push_snapshot` over several snapshots (one per declared root, one per
    collector) -- a node has more than one disk and more than one engine.
    Raises on the FIRST one that fails; callers that want a partial success
    (push what you can, report the rest as errors) call `push_snapshot`
    themselves per snapshot instead."""
    return [push_snapshot(client, node_id, snap, max_bytes=max_bytes) for snap in snapshots]


def fetch_requests(client: GatewayClient, node_id: str) -> dict:
    """Orders for this node runner: proposals a HUMAN has approved. Never a
    proposal this client raised or approved itself.

    Two error shapes reach here, and both must raise. `mcp_awstorage._get()`
    (the shipped tool this call wraps) wraps a NETWORK exception as
    `{"error": ...}` -- but an HTTP error status with a valid JSON body (a
    401 from `get_auth_caller`, a 403 for an unknown node) reaches
    `resp.json()` untouched, and FastAPI's own default body for that is
    `{"detail": "..."}`. Treating either shape as "zero orders" would
    silently stop applying every human-approved order on this node -- with
    `entries_written` from the unrelated scan+push half still nonzero, so
    `run_once` never raises and nothing is recorded in `summary["errors"]`.
    """
    result = client.call_tool("storage_requests", {"node_id": node_id})
    if isinstance(result, dict) and result.get("error"):
        raise GatewayError(f"fetch_requests for {node_id} refused: {result['error']}")
    if isinstance(result, dict) and "orders" not in result and result.get("detail"):
        raise GatewayError(f"fetch_requests for {node_id} refused: {result['detail']}")
    if not isinstance(result, dict):
        return {"node_id": node_id, "orders": [], "count": 0}
    return result


def report_apply(client: GatewayClient, node_id: str, rows: list[dict]) -> dict:
    """Report apply outcomes (dry-run, applied, refused, drifted -- whatever
    `policy.apply()` returned) for orders this node acted on.

    Same guard as `fetch_requests`, for the same reason: a FastAPI
    `{"detail": ...}` body from a rejected `/ledger/{node_id}` POST is not
    `{"error": ...}` and would otherwise land in `summary["reported"]` as if
    the ledger write had succeeded.
    """
    if not rows:
        return {"written": 0, "skipped": "no rows to report"}
    result = client.call_tool("storage_report_apply", {
        "node_id": node_id, "rows_json": json.dumps(rows, separators=(",", ":")),
    })
    if isinstance(result, dict) and result.get("error"):
        raise GatewayError(f"report_apply for {node_id} refused: {result['error']}")
    if isinstance(result, dict) and "written" not in result and result.get("detail"):
        raise GatewayError(f"report_apply for {node_id} refused: {result['detail']}")
    return result if isinstance(result, dict) else {"raw": result}
