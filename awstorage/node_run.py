"""node_run.py -- the loop every node runs.

The steps, in order, every pass:

    fetch orders (GET /requests/{node_id}, via storage_requests)
        -> apply the ones a human approved (awstorage.apply, dry_run=False)
        -> report what happened (POST /ledger/{node_id}, via storage_report_apply)
        -> hash what a `{kind: 'hash', paths}` order names, push the index delta (A3)
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

ONE dispatch table (`DISPATCH`) covers the one closed vocabulary `policy.ACTIONS`.
The card-only actions (`policy.CARD_ACTIONS`: hardlink, quarantine-copy, archive,
share) go to `awstorage.manage.apply_manage` WITH the decision card that approved
them -- fetched with the order from Genesis (`storage_manage_order`), re-verified
here -- never to `policy.apply`, which refuses them. Every exception becomes a
ledger row; a card order this node already ran is never run twice.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from ._fs import ScanError, scan
from .classify import classify_snapshot
from .collectors import COLLECTORS
from .collectors.podman import podman_available
from .policy import ACTIONS, CARD_ACTIONS, ApplyRefused, Proposal, apply
from .remote import (
    GatewayClient,
    GatewayError,
    fetch_manage_order,
    fetch_requests,
    push_files,
    push_snapshot,
    report_apply,
    report_manage,
)

#: The node-local catalog for card orders (quarantine entries, shares, run record).
#: Separate from any scan catalog so a Genesis proposal id never collides with a
#: local one.
DEFAULT_MANAGE_DB = Path(os.environ.get(
    "AWSTORAGE_MANAGE_DB", str(Path.home() / ".aither" / "awstorage" / "manage-node.db")))


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


@dataclass
class ManageContext:
    """What a node needs to carry out card orders.

    fetch_order(pid) -> {"order": <ManageProposal.to_dict()>, "card": <decision record>}
    comes from Genesis; the hooks are the transport (None = that action is refused,
    ledgered, never silently skipped)."""

    fetch_order: Callable[[int], dict]
    catalog: Any
    strata_hook: Optional[Callable[..., dict]] = None
    readback_hook: Optional[Callable[[str], dict]] = None
    share_hook: Optional[Callable[..., dict]] = None


def _row_of(order: dict, outcome: str, detail: Any = None, bytes_: int = 0) -> dict:
    return {"proposal_id": order.get("id", order.get("proposal_id")),
            "path": order.get("path"), "action": order.get("action"),
            "outcome": outcome, "bytes": int(bytes_ or 0), "detail": detail}


def _policy_order(order: dict, *, roots: list, hook: Any,
                  manage: Optional[ManageContext]) -> dict:
    if order.get("status") != "approved":  # never act on a proposal merely seen
        raise ApplyRefused(f"order {order.get('id')} is not approved")
    p = Proposal(**{k: v for k, v in order.items()
                    if k in Proposal.__dataclass_fields__ and k != "extra"})
    r = apply(p, roots=roots, dry_run=False, approved=True, engine_prune_hook=hook)
    return _row_of(order, str(r.get("outcome")), r.get("detail"), r.get("bytes", 0))


def _card_order(order: dict, *, roots: list, hook: Any,
                manage: Optional[ManageContext]) -> dict:
    from . import manage as m  # noqa: PLC0415

    pid = int(order.get("id", order.get("proposal_id")))
    if order.get("status") != "approved":  # never act on a proposal merely seen
        raise ApplyRefused(f"order {pid} is not approved")
    if manage is None:
        raise ApplyRefused(f"{order.get('action')} is card-only and this runner has no "
                           "manage context (order source + local manage catalog)")
    with m.ManageStore(manage.catalog) as st:
        prior = st.get_run(pid)
    if prior is not None:
        return _row_of(order, "already-executed",
                       f"ran {prior['at']} -> {prior['outcome']}; never twice")
    got = manage.fetch_order(pid) or {}
    raw = got.get("order") or {}
    if int(raw.get("id") or -1) != pid or raw.get("node") != order.get("node"):
        raise ApplyRefused(f"Genesis returned no matching manage order for {pid}")
    prop = m.ManageProposal.from_order(raw)
    try:
        out = m.apply_manage(prop, catalog=manage.catalog, roots=roots, card=got.get("card"),
                             dry_run=False, strata_hook=manage.strata_hook,
                             readback_hook=manage.readback_hook, share_hook=manage.share_hook)
    except ApplyRefused:
        with m.ManageStore(manage.catalog) as st:
            st.record_run(pid, card_id=prop.card_id, action=prop.action, outcome="refused")
        raise
    with m.ManageStore(manage.catalog) as st:
        st.record_run(pid, card_id=prop.card_id, action=prop.action, outcome=out["outcome"])
    return {**_row_of(order, str(out["outcome"]), out.get("detail"), out.get("bytes", 0)),
            "members": out.get("results", [])}


#: The ONE dispatch table: every action in the closed vocabulary has exactly one
#: handler, and the card actions never reach `policy.apply`.
DISPATCH: dict[str, Callable[..., dict]] = {
    a: (_card_order if a in CARD_ACTIONS else _policy_order) for a in ACTIONS
}


def apply_orders(orders: list[dict], *, roots: list, run=subprocess.run,
                 manage: Optional[ManageContext] = None) -> list[dict]:
    """Apply every order whose status is `approved`; anything else (proposed,
    rejected, expired, ...) is left alone -- a node runner acts on APPROVALS,
    never on a proposal it merely sees.

    Returns ledger-shaped rows: {proposal_id, path, action, outcome, bytes,
    detail} -- exactly the shape `storage_report_apply` expects, and exactly
    one row per order: a refusal is a row, and so is ANY exception (outcome
    `failed`), because a storage tool that deletes without a ledger is
    indistinguishable from a bug."""
    from .manage import normalize_action  # noqa: PLC0415

    hook = (lambda p: _engine_prune_hook(p, run=run)) if podman_available() else None
    rows: list[dict] = []
    for row in orders:
        if row.get("kind") == "hash" or row.get("status") != "approved":
            continue  # hash orders run in run_hash_orders; unapproved never runs
        order = {**row, "action": normalize_action(str(row.get("action", "")))}
        handler = DISPATCH.get(order["action"])
        try:
            if handler is None:
                raise ApplyRefused(f"unknown action {order['action']!r}")
            rows.append(handler(order, roots=roots, hook=hook, manage=manage))
        except ApplyRefused as exc:
            rows.append(_row_of(order, "refused", str(exc)))
        except Exception as exc:  # noqa: BLE001 -- every failure is a ledger row
            rows.append(_row_of(order, "failed", f"{type(exc).__name__}: {exc}"[:500]))
    return rows


def run_hash_orders(client: GatewayClient, node_id: str, orders: list[dict], *,
                    index: Optional[Path] = None, time_budget_s: float = 1800.0,
                    push: Optional[Callable[..., dict]] = None) -> dict:
    """A3: carry out Genesis `{kind: 'hash', paths}` orders -- full-sha256 exactly
    those paths in this node's local files index, then push the index delta so the
    fleet's duplicate groups cover the confirmed hashes. Only paths the local index
    already holds are read (an order never widens what this node hashes beyond its own
    indexed roots). Raises GatewayError when the push is refused."""
    from . import files as awfiles  # noqa: PLC0415

    paths: list[str] = []
    for o in orders:
        if o.get("node") not in (None, node_id):
            continue  # an order for another node is never executed here
        paths += [p for p in (o.get("paths") or []) if isinstance(p, str)]
    db = awfiles.open_index(index or awfiles.default_index_path())
    try:
        st = awfiles.hash_paths(db, node_id, paths, time_budget_s=time_budget_s)
        st["pushed"] = None
        if st["hashed"]:
            st["pushed"] = (push or push_files)(client, db, node_id)
    finally:
        db.close()
    return st


#: Where `share` card orders publish (an awshare bundle per share). Unset = the
#: share action is refused and ledgered, never published somewhere invented.
SHARE_ROOT_ENV = "AWSTORAGE_SHARE_ROOT"


def default_manage_context(client: GatewayClient, node_id: str,
                           db: Optional[Path] = None,
                           env: Optional[Mapping[str, str]] = None
                           ) -> Optional[ManageContext]:
    """Card orders fetched from Genesis over the gateway, recorded in the node-local
    manage catalog, with the transport hooks this node is CONFIGURED for:

    - archive: `strata.archive_hooks` -- a Strata write proven by stat, and an
      independent read-back that hashes the stored bytes -- when the node holds a
      Strata credential (AWSTORAGE_STRATA_BEARER or AWSTORAGE_STRATA_KEY);
    - share: an awshare bundle under AWSTORAGE_SHARE_ROOT when that is set.

    An unconfigured hook stays None, so that action is refused and ledgered --
    never run against a transport that does not exist. dedup needs none."""
    from .catalog import Catalog  # noqa: PLC0415
    from .manage import local_awshare_hook  # noqa: PLC0415
    from .strata import archive_hooks  # noqa: PLC0415

    e = os.environ if env is None else env
    try:
        cat = Catalog(db or DEFAULT_MANAGE_DB)
    except Exception:  # noqa: BLE001 -- no local catalog: card orders are refused
        return None
    strata_hook, readback_hook = archive_hooks(e)
    share_root = (e.get(SHARE_ROOT_ENV) or "").strip()
    share_hook = local_awshare_hook(share_root)[0] if share_root else None
    return ManageContext(fetch_order=lambda pid: fetch_manage_order(client, node_id, pid),
                         catalog=cat, strata_hook=strata_hook,
                         readback_hook=readback_hook, share_hook=share_hook)


def run_once(client: GatewayClient, *, node_id: str, roots: Iterable, depth: int = 3,
             budget: float = 300.0, collectors: Iterable[str] = (),
             manage: Optional[ManageContext] = None, orders_only: bool = False) -> dict:
    """One full pass over an ALREADY-CONNECTED client. Returns a summary dict;
    raises GatewayError when the pass, taken as a whole, wrote nothing to the
    fleet -- the caller (`run_loop`) turns that into a non-zero exit, never a
    quiet 'ok'.

    ``orders_only``: fetch, apply and report orders, but neither scan nor push
    (the caller already did -- `awstorage-scan.sh` runs the scans first). The
    roots still bound where an order may act. No orders is a success; a failed
    fetch or report raises GatewayError, since then nothing was judged."""
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

    if manage is None and any(o.get("action") in CARD_ACTIONS for o in orders):
        manage = default_manage_context(client, node_id)
    rows = apply_orders(orders, roots=roots, manage=manage)
    summary["applied"] = rows
    if rows:
        ledger_rows = [{k: v for k, v in r.items() if k != "members"} for r in rows]
        for r in rows:  # one ledger row per member of a card order (A7)
            for mem in r.get("members") or []:
                ledger_rows.append({"proposal_id": r["proposal_id"], "path": mem.get("path"),
                                    "action": r["action"], "outcome": mem.get("result"),
                                    "bytes": mem.get("bytes", 0),
                                    "detail": f"member {mem.get('member')}"})
        try:
            summary["reported"] = report_apply(client, node_id, ledger_rows)
        except GatewayError as exc:
            summary["errors"].append(f"report_apply: {exc}")
        card_rows = [{k: v for k, v in r.items() if k != "members"} for r in rows
                     if r.get("action") in CARD_ACTIONS
                     and r.get("outcome") != "already-executed"]
        if card_rows:
            try:
                summary["manage_reported"] = report_manage(client, node_id, card_rows)
            except GatewayError as exc:
                summary["errors"].append(f"report_manage: {exc}")

    hash_orders = [o for o in orders if isinstance(o, dict) and o.get("kind") == "hash"]
    if hash_orders:
        try:
            summary["hash_orders"] = run_hash_orders(client, node_id, hash_orders)
        except (GatewayError, OSError, ValueError) as exc:
            summary["errors"].append(f"hash_orders: {type(exc).__name__}: {exc}")

    if orders_only:
        if summary["errors"]:
            raise GatewayError(f"node-run --orders-only for {node_id}: "
                               f"{'; '.join(summary['errors'])}")
        return summary

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
             orders_only: bool = False, out=sys.stdout, err=sys.stderr) -> int:
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
                                    budget=budget, collectors=collectors,
                                    orders_only=orders_only)
            except GatewayError as exc:
                print(f"node-run FAILED: {exc}", file=err)
                if once:
                    return 1
            else:
                if orders_only:
                    print(f"node-run ok (orders only): {len(summary['applied'])} order(s)"
                          " applied", file=out)
                    if once:
                        return 0
                    time.sleep(interval_s)
                    continue
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
