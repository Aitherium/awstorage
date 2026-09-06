"""node_run.py -- the loop every node runs.

Four steps, in order, every pass:

    fetch orders (GET /requests/{node_id}, via storage_requests)
        -> apply the ones a human approved (awstorage.apply, dry_run=False)
        -> report what happened (POST /ledger/{node_id}, via storage_report_apply)
        -> scan the declared roots + run the configured collectors
        -> push what was found (POST /scans/{node_id}, via storage_ingest_scan)

Every step degrades honestly rather than aborting the pass: a fetch failure
means no orders are applied this time (not a crash); an apply refusal is a
ledger row, not a lost error; a push failure for one root does not stop the
others. The one thing this loop refuses outright is reporting SUCCESS when it
wrote nothing anywhere -- see `run_once`'s closing check, the same discipline
`remote.push_snapshot` already applies per snapshot.

`apply_orders` is the only place `engine_prune_hook` is wired: `prune-engine`
carries out `podman image prune -f` (dangling images only -- never `-a`, never
a volume) when podman exists, and is refused -- never silently skipped -- when
it does not, exactly as `policy.apply()` already documents for that action.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from ._fs import ScanError, scan
from .classify import classify_snapshot
from .collectors import COLLECTORS
from .collectors.podman import podman_available
from .policy import ApplyRefused, Proposal, apply
from .remote import GatewayClient, GatewayError, fetch_requests, push_snapshot, report_apply


def _engine_prune_hook(_path: Path, *, run=subprocess.run) -> str:
    """`prune-engine`: dangling images only, via the engine -- never `rm` on
    the container store (that corrupts it). Raises if podman is missing; the
    caller (`policy.apply`) turns that into a REFUSED ledger row, never a
    silent skip."""
    if not podman_available():
        raise RuntimeError("podman is not on PATH; cannot prune")
    try:
        p = run(["podman", "image", "prune", "-f"], capture_output=True,
                 text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"podman image prune failed: {type(exc).__name__}: {exc}") from exc
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()[:300]
        raise RuntimeError(f"podman image prune failed: {detail}")
    out = (p.stdout or "").strip()
    return out[:500] if out else "podman image prune -f: nothing to prune"


def apply_orders(orders: list[dict], *, roots: list, run=subprocess.run) -> list[dict]:
    """Apply every order whose status is `approved`; anything else (proposed,
    rejected, expired, ...) is left alone -- a node runner acts on APPROVALS,
    never on a proposal it merely sees.

    Returns ledger-shaped rows: {proposal_id, path, action, outcome, bytes,
    detail} -- exactly the shape `storage_report_apply` expects, and exactly
    one row per order (a refusal is a row too; see `policy.py`'s "a storage
    tool that deletes without a ledger is indistinguishable from a bug")."""
    hook = (lambda p: _engine_prune_hook(p, run=run)) if podman_available() else None
    rows: list[dict] = []
    for row in orders:
        if row.get("status") != "approved":
            continue
        p = Proposal(**{k: v for k, v in row.items()
                         if k in Proposal.__dataclass_fields__ and k != "extra"})
        try:
            r = apply(p, roots=roots, dry_run=False, approved=True, engine_prune_hook=hook)
        except ApplyRefused as exc:
            rows.append({"proposal_id": p.id, "path": p.path, "action": p.action,
                         "outcome": "refused", "bytes": 0, "detail": str(exc)})
            continue
        rows.append({"proposal_id": p.id, "path": p.path, "action": p.action,
                     "outcome": r.get("outcome"), "bytes": r.get("bytes", 0),
                     "detail": r.get("detail")})
    return rows


def run_once(client: GatewayClient, *, node_id: str, roots: Iterable, depth: int = 3,
             budget: float = 300.0, collectors: Iterable[str] = ()) -> dict:
    """One full pass over an ALREADY-CONNECTED client. Returns a summary dict;
    raises GatewayError when the pass, taken as a whole, wrote nothing to the
    fleet -- the caller (`run_loop`) turns that into a non-zero exit, never a
    quiet 'ok'."""
    roots = list(roots)
    collectors = list(collectors)
    summary: dict = {
        "node_id": node_id, "applied": [], "reported": None, "pushes": [],
        "entries_written": 0, "errors": [],
    }

    try:
        req = fetch_requests(client, node_id)
    except GatewayError as exc:
        summary["errors"].append(f"fetch_requests: {exc}")
        req = {"orders": []}
    orders = req.get("orders", []) if isinstance(req, dict) else []

    rows = apply_orders(orders, roots=roots)
    summary["applied"] = rows
    if rows:
        try:
            summary["reported"] = report_apply(client, node_id, rows)
        except GatewayError as exc:
            summary["errors"].append(f"report_apply: {exc}")

    for root in roots:
        try:
            snap = scan(Path(root), max_depth=depth, time_budget_s=budget, node=node_id)
            classify_snapshot(snap)
            res = push_snapshot(client, node_id, snap)
        except (ScanError, GatewayError) as exc:
            summary["errors"].append(f"root {root}: {exc}")
            continue
        summary["pushes"].append(res)
        summary["entries_written"] += res["entries_written"]

    for name in collectors:
        fn = COLLECTORS.get(name)
        if fn is None:
            summary["errors"].append(f"collector {name!r} is not registered")
            continue
        try:
            snap = fn(node=node_id)
            res = push_snapshot(client, node_id, snap)
        except GatewayError as exc:
            summary["errors"].append(f"collector {name}: {exc}")
            continue
        summary["pushes"].append(res)
        summary["entries_written"] += res["entries_written"]

    if summary["entries_written"] == 0:
        raise GatewayError(
            f"node-run for {node_id} wrote 0 entries across {len(roots)} root(s) and "
            f"{len(collectors)} collector(s) -- refusing to report success "
            f"(errors: {summary['errors']!r})")
    return summary


def run_loop(*, once: bool, node_id: str, roots: Iterable, gateway: str | None = None,
             bearer_file: Path | None = None, depth: int = 3, budget: float = 300.0,
             collectors: Iterable[str] = (), interval_s: float = 900.0,
             out=sys.stdout, err=sys.stderr) -> int:
    """The persistent loop `awstorage node-run` drives. Exit 0 a pass wrote
    something, 1 a pass ran and wrote nothing (or an order was refused with
    nothing else to show for it), 2 the gateway could not be reached at all.
    """
    roots = list(roots)
    collectors = list(collectors)
    while True:
        try:
            client = GatewayClient(base_url=gateway, bearer_file=bearer_file).connect()
        except GatewayError as exc:
            print(f"node-run: cannot reach the gateway: {exc}", file=err)
            if once:
                return 2
        else:
            try:
                summary = run_once(client, node_id=node_id, roots=roots, depth=depth,
                                    budget=budget, collectors=collectors)
            except GatewayError as exc:
                print(f"node-run FAILED: {exc}", file=err)
                if once:
                    return 1
            else:
                print(f"node-run ok: {summary['entries_written']} entries across "
                      f"{len(summary['pushes'])} push(es), "
                      f"{len(summary['applied'])} order(s) applied", file=out)
                for e in summary["errors"]:
                    print(f"  warning: {e}", file=err)
                if once:
                    return 0
        if once:
            break
        time.sleep(interval_s)
    return 0
