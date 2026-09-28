"""`awstorage` -- scan, inventory, diff, propose, apply.

    awstorage scan <root> [--depth 3] [--budget 300] [--catalog inv.db] [--json out.json]
    awstorage inventory --catalog inv.db [--snapshot ID] [--top 30] [--json]
    awstorage diff --catalog inv.db --root <root> [--node NAME] [--json]
    awstorage propose --catalog inv.db --snapshot ID [--policy policy.json] [--json]
    awstorage approve --catalog inv.db --proposal ID
    awstorage apply --catalog inv.db --proposal ID --root <root> [--yes]
    awstorage quarantine --root <root> [--purge-older-than 14 --yes]
    awstorage revert <quarantine-entry>
    awstorage graph --catalog inv.db --snapshot ID [--min-bytes N]
    awstorage push --catalog inv.db --node ID --gateway URL [--snapshot ID] [--bearer-file F]
    awstorage node-run --node ID --root ROOT [--root ROOT ...] [--gateway URL] [--once]
    awstorage hash <path...>
    awstorage sweep --rules agent-scratch,temp-toplevel [--policy F] [--yes]
                    [--harvest-to D] [--emergency-free-gb N] [--measure-cap-s S]
                    [--receipt PATH] [--json]
    awstorage audit verify [--audit-log PATH]
    awstorage harvest verify <shelf> | harvest publish <day-dir> --to <target>
    awstorage --self-test            (also: python -m awstorage --self-test)

Exit 0 on success, 1 when a proposal is REFUSED (the refusal is the answer) or a
swept item failed (it is kept and reported), 2 when the command could not run or
could not judge at all (bad root, bad rule, missing catalog row).
Dry-run is the default everywhere destructive; `--yes` is the only way to act.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

from . import __version__
from ._fs import ScanError, scan
from .catalog import Catalog
from .classify import classify_snapshot
from .diff import diff_snapshots
from .graph import to_graph
from .node_run import run_loop
from .policy import (
    ApplyRefused,
    Proposal,
    apply,
    default_policy,
    list_quarantine,
    propose,
    purge_quarantine,
    revert,
)
from .remote import GatewayClient, GatewayError, push_snapshot
from .report import human, rank, render_table, summarize
from .sweep import LIVE_IDS_ENV


def _load_policy(path: str | None) -> dict:
    if not path:
        return default_policy()
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore  # optional extra
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise SystemExit("policy is YAML but pyyaml is not installed; use JSON or"
                             " `pip install awstorage[yaml]`") from exc
        return yaml.safe_load(text)
    return json.loads(text)


def _cmd_scan(a) -> int:
    try:
        snap = scan(Path(a.root), max_depth=a.depth, time_budget_s=a.budget,
                    top_files=a.top_files, node=a.node)
    except ScanError as exc:
        print(f"cannot scan: {exc}", file=sys.stderr)
        return 2
    classify_snapshot(snap)
    s = summarize(snap)
    print(f"{snap['node']} {snap['root']}: {human(s['total_bytes'])} in {s['files']} files, "
          f"{len(snap['trees'])} trees, {s['errors']} errors, {snap['elapsed_s']}s"
          + ("  [TRUNCATED by time budget -- totals are a floor]" if snap["truncated"] else ""))
    print(f"  re-fetchable: {human(s['refetchable_bytes'])}   keep: {human(s['keep_bytes'])}"
          f"   unclassified: {human(s['unclassified_bytes'])}")
    if a.json:
        Path(a.json).write_text(json.dumps(snap, indent=1), encoding="utf-8")
        print(f"  snapshot -> {a.json}")
    if a.catalog:
        cat = Catalog(a.catalog)
        sid = cat.put_snapshot(snap)
        print(f"  catalog {a.catalog}: snapshot id {sid}")
        cat.close()
    if not a.quiet:
        print(render_table(rank(snap), limit=a.top))
    return 0


def _get_snapshot(cat: Catalog, sid: int | None, node: str | None, root: str | None) -> dict | None:
    if sid is not None:
        return cat.get_snapshot(sid)
    rows = cat.list_snapshots(node=node, root=root, limit=1)
    return cat.get_snapshot(rows[0]["id"]) if rows else None


def _cmd_inventory(a) -> int:
    cat = Catalog(a.catalog)
    if a.snapshot is None and not a.root:
        tot = cat.totals()
        if a.json:
            print(json.dumps(tot, indent=1))
            return 0
        print(f"{len(tot['roots'])} root(s) on {len(tot['nodes'])} node(s): "
              f"{human(tot['total_bytes'])} total")
        for r in tot["roots"]:
            flag = "  [TRUNCATED]" if r["truncated"] else ""
            print(f"  {human(r['total_bytes']):>10}  {r['node']:<18} {r['root']}  "
                  f"({r['taken_at']}, snapshot {r['id']}){flag}")
        return 0
    snap = _get_snapshot(cat, a.snapshot, a.node, a.root)
    if not snap:
        print("no such snapshot", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps({"summary": summarize(snap), "top": rank(snap, top=a.top)}, indent=1))
        return 0
    s = summarize(snap)
    print(f"{snap['node']} {snap['root']} @ {snap['taken_at']}: {human(s['total_bytes'])}"
          + ("  [TRUNCATED]" if s["truncated"] else ""))
    for cls, b in s["by_class"].items():
        print(f"  {human(b):>10}  {cls}")
    print(render_table(rank(snap), limit=a.top))
    return 0


def _cmd_diff(a) -> int:
    cat = Catalog(a.catalog)
    node = a.node or socket.gethostname()
    newer, older = cat.latest_pair(node, a.root.replace("\\", "/"))
    if a.against is not None:
        older = cat.get_snapshot(a.against)
    if not newer or not older:
        print("need two snapshots of this root to diff", file=sys.stderr)
        return 2
    d = diff_snapshots(older, newer, min_delta_bytes=a.min_delta)
    if a.json:
        print(json.dumps(d, indent=1))
        return 0
    s = d["summary"]
    print(f"{d['root']}: {human(s['root_before'])} -> {human(s['root_after'])} "
          f"({'+' if s['root_delta'] >= 0 else ''}{human(s['root_delta'])})"
          + ("  [one side TRUNCATED]" if s["either_truncated"] else ""))
    for label in ("grown", "added", "shrunk", "removed"):
        rows = d[label][:a.top]
        if rows:
            print(f"-- {label} ({len(d[label])})")
            for r in rows:
                sign = "+" if r["delta"] >= 0 else ""
                print(f"  {sign}{human(r['delta']):>10}  {r['path']}")
    return 0


def _cmd_propose(a) -> int:
    cat = Catalog(a.catalog)
    snap = cat.get_snapshot(a.snapshot)
    if not snap:
        print("no such snapshot", file=sys.stderr)
        return 2
    # Re-run the heuristic rules over the stored trees so a policy decision always
    # reflects the CURRENT rules (model verdicts, if any, are kept).
    classify_snapshot(snap)
    props = propose(snap, _load_policy(a.policy), snapshot_id=a.snapshot)
    ids = cat.put_proposals([p.to_dict() for p in props]) if props else []
    for p, pid in zip(props, ids):
        p.id = pid
    if a.json:
        print(json.dumps([p.to_dict() for p in props], indent=1))
        return 0
    if not props:
        print("no proposals: nothing matched the policy")
        return 0
    total = sum(p.bytes for p in props)
    auto = sum(p.bytes for p in props if p.auto)
    print(f"{len(props)} proposal(s), {human(total)} ({human(auto)} pre-approved by policy)")
    for p in props:
        tag = "AUTO " if p.auto else "ASK  "
        print(f"  #{p.id:<4} {tag} {p.action:<18} {human(p.bytes):>10}  {p.cls:<15} {p.path}")
    return 0


def _cmd_approve(a) -> int:
    cat = Catalog(a.catalog)
    if not cat.get_proposal(a.proposal):
        print("no such proposal", file=sys.stderr)
        return 2
    cat.set_status(a.proposal, "rejected" if a.reject else "approved", a.note)
    print(f"proposal {a.proposal}: {'rejected' if a.reject else 'approved'}")
    return 0


def _cmd_apply(a) -> int:
    cat = Catalog(a.catalog)
    row = cat.get_proposal(a.proposal)
    if not row:
        print("no such proposal", file=sys.stderr)
        return 2
    p = Proposal(**{k: v for k, v in row.items() if k in Proposal.__dataclass_fields__})
    try:
        r = apply(p, roots=[a.root], dry_run=not a.yes)
    except ApplyRefused as exc:
        cat.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
                   outcome="refused", detail=str(exc))
        print(f"REFUSED: {exc}")
        return 1
    cat.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
               outcome=r["outcome"], bytes_=r.get("bytes", 0), detail=r.get("detail"))
    if r["outcome"] == "applied":
        cat.set_status(p.id, "applied")
    print(f"{r['outcome']}: {p.action} {p.path} ({human(r.get('bytes', 0))}) -- {r.get('detail')}")
    if r["outcome"] == "dry-run":
        print("dry run. Re-run with --yes to act.")
    return 0


def _cmd_quarantine(a) -> int:
    entries = list_quarantine([a.root])
    if a.purge_older_than is not None:
        res = purge_quarantine([a.root], older_than_days=a.purge_older_than, dry_run=not a.yes)
        for r in res:
            print(f"{r['outcome']:<8} {human(r['bytes']):>10}  {r['entry']}  (from {r['origin']})")
        if not res:
            print("nothing old enough to purge")
        elif not a.yes:
            print("dry run. Re-run with --yes to purge.")
        return 0
    if not entries:
        print("quarantine is empty")
        return 0
    for e in entries:
        print(f"{human(e['bytes']):>10}  {e['age_days']:>5.1f}d  {e['entry']}  <- {e['origin']}")
    return 0


def _cmd_revert(a) -> int:
    try:
        dest = revert(Path(a.entry))
    except ApplyRefused as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(f"restored -> {dest}")
    return 0


def _cmd_graph(a) -> int:
    cat = Catalog(a.catalog)
    snap = cat.get_snapshot(a.snapshot)
    if not snap:
        print("no such snapshot", file=sys.stderr)
        return 2
    print(json.dumps(to_graph(snap, min_bytes=a.min_bytes), indent=None))
    return 0


def _cmd_push(a) -> int:
    cat = Catalog(a.catalog)
    snap = _get_snapshot(cat, a.snapshot, a.node, a.root)
    if not snap:
        print("no such snapshot", file=sys.stderr)
        return 2
    node_id = a.node or snap.get("node") or socket.gethostname()
    try:
        client = GatewayClient(base_url=a.gateway,
                               bearer_file=Path(a.bearer_file) if a.bearer_file else None)
        client.connect()
        result = push_snapshot(client, node_id, snap)
    except GatewayError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(f"pushed {node_id}:{result['root']}: {result['entries_written']} entries "
          f"across {result['parts']} part(s)")
    return 0


def _cmd_node_run(a) -> int:
    collectors = [c.strip() for c in (a.collector or "").split(",") if c.strip()]
    return run_loop(
        once=a.once, node_id=a.node, roots=a.root, gateway=a.gateway,
        bearer_file=Path(a.bearer_file) if a.bearer_file else None,
        depth=a.depth, budget=a.budget, collectors=collectors, interval_s=a.interval,
    )


def _cmd_hash(a) -> int:
    rc = 0
    for raw in a.path:
        p = Path(raw)
        if not p.exists():
            print(f"{raw}: does not exist", file=sys.stderr)
            rc = 2
            continue
        h = hashlib.sha256()
        try:
            if p.is_file():
                with p.open("rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
            else:
                # Deterministic over the tree: relative path then content, in
                # sorted order, so the same tree hashes the same on any node.
                for sub in sorted(p.rglob("*")):
                    if not sub.is_file():
                        continue
                    rel = str(sub.relative_to(p)).replace("\\", "/")
                    h.update(rel.encode("utf-8"))
                    with sub.open("rb") as f:
                        for chunk in iter(lambda: f.read(1 << 20), b""):
                            h.update(chunk)
        except OSError as exc:
            print(f"{raw}: {type(exc).__name__}: {exc}", file=sys.stderr)
            rc = 2
            continue
        print(f"{h.hexdigest()}  {raw}")
    return rc


_AITHER = Path.home() / ".aither"


def _cmd_sweep(a) -> int:
    from .integrations import default_audit_log
    from .sweep import sweep

    policy = None
    if a.policy:
        try:
            policy = _load_policy(a.policy)
        except (OSError, ValueError) as exc:
            # Judged, not crashed: sweep() exits 2 on it WITH a receipt written.
            policy = {"_error": f"cannot load policy {a.policy}: {exc}"}
    names = [n for n in (a.rules or "").split(",") if n.strip()]
    rec = sweep(
        names, policy=policy, dry_run=not a.yes, harvest_to=a.harvest_to,
        harvest_offdrive=a.harvest_offdrive, emergency_free_gb=a.emergency_free_gb,
        receipt=a.receipt, catalog=None if a.no_catalog else a.catalog,
        live_ids_file=a.live_ids,
        audit_log=None if a.no_audit else (a.audit_log or default_audit_log()),
        require_audit=a.require_audit, seal_key=a.seal_key, seal=not a.no_seal,
        publish_to=a.publish_to,
        land_to_awm=a.land_to_awm, awm_db=a.awm_db, snapshot_store=a.snapshot_store,
        time_budget_s=a.time_budget or None,
        measure_cap_s=None if a.measure_cap_s < 0 else a.measure_cap_s,
    )
    if a.json:
        print(json.dumps(rec, indent=1, sort_keys=True, default=str))
        return int(rec["exit_code"])
    for e in rec["emergency"]:
        print(e["message"])
    mode = "DRY RUN (plan)" if rec["dry_run"] else "SWEEP"
    if rec.get("truncated"):
        mode += " [TRUNCATED by --time-budget]"
    print(f"{mode}: rules {', '.join(r['name'] for r in rec['rules']) or '-'}; "
          f"{rec['items_seen']} seen, {rec['items_eligible']} eligible, "
          f"{rec['kept_fresh']} fresh, {len(rec['skipped_live'])} live, "
          f"{len(rec['skipped_busy'])} busy")
    for it in rec["items"]:
        hv = it.get("harvest") or {}
        extra = ""
        if hv:
            extra = f"  harvest {hv.get('files', 0)} file(s)/{human(hv.get('bytes', 0))}"
            if hv.get("withheld"):
                extra += f", withheld {hv['withheld']}"
        size = "capped" if it.get("capped") else human(it.get("bytes", 0))
        print(f"  {it['outcome']:<12} {size:>10}  "
              f"{it.get('age_h', 0):>7.1f}h  {it['path']}{extra}  -- {it['reason']}")
    for q in rec["purged"]:
        print(f"  {'purge ' + q['outcome']:<12} {human(q['bytes']):>10}  {q['entry']}")
    print(f"removed {rec['items_removed']} item(s): freed {human(rec['bytes_freed'])}, "
          f"quarantined {human(rec['bytes_quarantined'])}, harvested "
          f"{rec['files_harvested']} file(s) / {human(rec['bytes_harvested'])}"
          + (f", withheld {rec['withheld_secret']} (secret pattern)"
             if rec["withheld_secret"] else ""))
    if rec.get("emergency_deleted") or rec.get("bytes_purged"):
        print(f"  freed by: purge {human(rec.get('bytes_purged', 0))}, emergency delete "
              f"{rec.get('emergency_deleted', 0)} item(s) / "
              f"{human(rec.get('bytes_emergency_deleted', 0))}")
    for c in rec.get("capped", []):
        print(f"  capped measure ({c['verdict']}): {c['path']} -- saw {c['files_seen']} "
              f"file(s)/{human(c['bytes_seen'])} + {c['sample_files']} sampled")
    for k, v in rec["free_before"].items():
        after = rec["free_after"].get(k)
        print(f"  free {k}: {human(v)} -> {human(after) if after is not None else '?'}")
    for n in rec["notes"]:
        print(f"  note: {n}")
    for w in rec["warnings"]:
        print(f"  warning: {w}")
    for e in rec["errors"]:
        print(f"  FAILED: {e}", file=sys.stderr)
    for e in rec["could_not_judge"]:
        print(f"  COULD NOT JUDGE: {e}", file=sys.stderr)
    if rec["dry_run"] and rec["exit_code"] == 0:
        print("dry run. Re-run with --yes to act.")
    if a.receipt:
        print(f"receipt -> {a.receipt}")
    return int(rec["exit_code"])


def _cmd_audit(a) -> int:
    from .integrations import audit_verify, default_audit_log

    r = audit_verify(a.audit_log or default_audit_log())
    if a.json:
        print(json.dumps(r, indent=1))
    elif not r["available"]:
        print(f"could not judge: {r['reason']}")
    else:
        print(f"{'ok' if r['ok'] else 'BROKEN'}: {r['count']} record(s)")
        for prob in r.get("problems", []):
            print(f"  {prob}")
    if not r["available"]:
        return 2
    return 0 if r["ok"] else 1


def _cmd_harvest(a) -> int:
    from .integrations import publish_day, verify_shelf

    if a.harvest_cmd == "verify":
        r = verify_shelf(Path(a.shelf), expect_key=a.expect_key)
        if a.json:
            print(json.dumps(r, indent=1))
        elif not r["available"]:
            print(f"could not judge: {r['reason']}")
        else:
            c = r["counts"]
            print(f"{c['sealed']} sealed, {c['tampered']} tampered, {c['missing']} unsealed")
            for it in r["items"]:
                if it["status"] != "sealed":
                    print(f"  {it['status'].upper():<9} {it['dir']}")
        if not r["available"]:
            return 2
        return 0 if r["ok"] else 1
    r = publish_day(Path(a.day_dir), Path(a.to), seal_key=a.seal_key)
    if a.json:
        print(json.dumps(r, indent=1))
    elif r["ok"]:
        print(f"published {r['name']} ({human(r['size'])}, sha256 {r['digest'][:16]}...)"
              f" -> {r['manifest']}")
    else:
        print(f"{'could not publish' if r['available'] else 'unavailable'}: {r['reason']}")
    if not r["available"]:
        return 2
    return 0 if r["ok"] else 1


def self_test() -> int:
    """Prove the tool can still fail: refusals refuse, quarantine reverts, diff sees growth."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "root"
        (root / "build").mkdir(parents=True)
        (root / "data").mkdir()
        (root / "build" / "x.o").write_bytes(b"0" * 4096)
        (root / "data" / "d.db").write_bytes(b"1" * 4096)
        old = time.time() - 30 * 86400
        os.utime(root / "build" / "x.o", (old, old))
        snap = classify_snapshot(scan(root, max_depth=2, node="selftest"))
        pol = default_policy()
        for r in pol["rules"]:
            r["min_bytes"] = 1
        props = propose(snap, pol)
        b = [p for p in props if p.path.endswith("/build")]
        if not b or not b[0].auto:
            print("self-test FAIL: build-temp not proposed as auto")
            return 1
        refused = False
        try:
            apply(b[0], roots=[Path(td) / "elsewhere"], dry_run=False)
        except ApplyRefused as exc:
            refused = "outside the declared roots" in str(exc)
        if not refused:
            print("self-test FAIL: apply accepted a path outside the roots")
            return 1
        r = apply(b[0], roots=[root], dry_run=False)
        if r["outcome"] != "applied" or (root / "build").exists():
            print("self-test FAIL: quarantine did not move the tree")
            return 1
        q = list_quarantine([root])
        revert(Path(q[0]["entry"]))
        if not (root / "build" / "x.o").exists():
            print("self-test FAIL: revert did not restore the tree")
            return 1
        (root / "data" / "big").write_bytes(b"2" * 65536)
        snap2 = scan(root, max_depth=2, node="selftest")
        d = diff_snapshots(snap, snap2)
        if not any(g["path"].endswith("/data") for g in d["grown"]):
            print("self-test FAIL: diff did not see growth")
            return 1
        data_props = [p for p in propose(classify_snapshot(snap2), pol) if p.path.endswith("/data")]
        if any(p.auto for p in data_props):
            print("self-test FAIL: service-state proposed as auto")
            return 1
    print("apply/revert guards ok; sweep guards:")
    from ._selftest import run as _sweep_self_test

    if _sweep_self_test() != 0:
        return 1
    print("self-test ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    # GENERATED repo-state intercept (gen_aw_doctor.py) -- do not edit
    try:
        from awgit import state as _aw_state
    except Exception:
        _aw_state = None
    if _aw_state is not None:
        _sv = locals().get("argv")
        if _aw_state.cli_banner(_sv if _sv is not None else __import__("sys").argv[1:]):
            return 0
    ap = argparse.ArgumentParser(prog="awstorage", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=f"awstorage {__version__}")
    ap.add_argument("--self-test", action="store_true", help="prove the tool can still fail")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a root into a snapshot")
    s.add_argument("root")
    s.add_argument("--depth", type=int, default=3)
    s.add_argument("--budget", type=float, default=300.0, help="seconds before TRUNCATED")
    s.add_argument("--top-files", type=int, default=50)
    s.add_argument("--top", type=int, default=30, help="rows to print")
    s.add_argument("--node", help="node name (default: hostname)")
    s.add_argument("--catalog", help="SQLite catalog to store the snapshot in")
    s.add_argument("--json", help="write the snapshot JSON here")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(fn=_cmd_scan)

    i = sub.add_parser("inventory", help="ranked view of a stored snapshot, or all roots")
    i.add_argument("--catalog", required=True)
    i.add_argument("--snapshot", type=int)
    i.add_argument("--node")
    i.add_argument("--root")
    i.add_argument("--top", type=int, default=30)
    i.add_argument("--json", action="store_true")
    i.set_defaults(fn=_cmd_inventory)

    d = sub.add_parser("diff", help="what changed between the two newest snapshots of a root")
    d.add_argument("--catalog", required=True)
    d.add_argument("--root", required=True)
    d.add_argument("--node")
    d.add_argument("--against", type=int, help="older snapshot id (default: previous)")
    d.add_argument("--min-delta", type=int, default=1024 * 1024)
    d.add_argument("--top", type=int, default=15)
    d.add_argument("--json", action="store_true")
    d.set_defaults(fn=_cmd_diff)

    p = sub.add_parser("propose", help="match a snapshot against the policy")
    p.add_argument("--catalog", required=True)
    p.add_argument("--snapshot", type=int, required=True)
    p.add_argument("--policy", help="JSON/YAML policy file (default: shipped policy)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=_cmd_propose)

    ap_ = sub.add_parser("approve", help="a human approves (or rejects) a proposal")
    ap_.add_argument("--catalog", required=True)
    ap_.add_argument("--proposal", type=int, required=True)
    ap_.add_argument("--reject", action="store_true")
    ap_.add_argument("--note")
    ap_.set_defaults(fn=_cmd_approve)

    a_ = sub.add_parser("apply", help="carry out a proposal (dry-run unless --yes)")
    a_.add_argument("--catalog", required=True)
    a_.add_argument("--proposal", type=int, required=True)
    a_.add_argument("--root", required=True, help="declared root the path must be under")
    a_.add_argument("--yes", action="store_true")
    a_.set_defaults(fn=_cmd_apply)

    q = sub.add_parser("quarantine", help="list or purge quarantined trees under a root")
    q.add_argument("--root", required=True)
    q.add_argument("--purge-older-than", type=float, metavar="DAYS")
    q.add_argument("--yes", action="store_true")
    q.set_defaults(fn=_cmd_quarantine)

    r = sub.add_parser("revert", help="restore a quarantined tree to its origin")
    r.add_argument("entry")
    r.set_defaults(fn=_cmd_revert)

    g = sub.add_parser("graph", help="snapshot as nodes/edges JSON")
    g.add_argument("--catalog", required=True)
    g.add_argument("--snapshot", type=int, required=True)
    g.add_argument("--min-bytes", type=int, default=0)
    g.set_defaults(fn=_cmd_graph)

    psh = sub.add_parser("push", help="push a stored snapshot to Genesis through the MCP gateway")
    psh.add_argument("--catalog", required=True)
    psh.add_argument("--snapshot", type=int, help="default: newest matching --node/--root")
    psh.add_argument("--node", help="node id to push as (default: the snapshot's own node)")
    psh.add_argument("--root")
    psh.add_argument("--gateway", help=f"default: {os.environ.get('AWSTORAGE_GATEWAY', '')}"
                                       " or http://127.0.0.1:8182/mcp")
    psh.add_argument("--bearer-file", help="default: ~/.aither/session-bearer")
    psh.set_defaults(fn=_cmd_push)

    nr = sub.add_parser("node-run", help="fetch orders, apply them, scan, push -- the loop"
                                          " every node runs")
    nr.add_argument("--node", required=True, help="node id to run as")
    nr.add_argument("--root", action="append", required=True, dest="root",
                    help="a declared root to scan; repeat for more than one")
    nr.add_argument("--gateway")
    nr.add_argument("--bearer-file")
    nr.add_argument("--depth", type=int, default=3)
    nr.add_argument("--budget", type=float, default=300.0)
    nr.add_argument("--collector", help="comma-separated: podman,journal")
    nr.add_argument("--interval", type=float, default=900.0, help="seconds between passes"
                                                                    " when not --once")
    nr.add_argument("--once", action="store_true", help="run one pass and exit"
                                                          " (default: loop forever)")
    nr.set_defaults(fn=_cmd_node_run)

    h = sub.add_parser("hash", help="sha256 a file or a directory tree, on demand")
    h.add_argument("path", nargs="+")
    h.set_defaults(fn=_cmd_hash)

    sw = sub.add_parser("sweep", help="retention sweep: measure, guard, harvest, remove"
                                       " (dry-run unless --yes)")
    sw.add_argument("--rules", help="comma-separated rule names (presets: agent-scratch,"
                                    " temp-toplevel); default: the --policy file's rules")
    sw.add_argument("--policy", help="JSON policy file with a `retention` list")
    grp = sw.add_mutually_exclusive_group()
    grp.add_argument("--dry-run", action="store_true", help="print the plan (the default)")
    grp.add_argument("--yes", action="store_true", help="act")
    sw.add_argument("--harvest-to", default=str(_AITHER / "harvest"),
                    help="harvest shelf dir (default ~/.aither/harvest), or strata:<hot|warm|"
                         "cold> to ship verified harvests to AitherStrata (key from"
                         " $AWSTORAGE_STRATA_KEY, URL from $AITHERSTRATA_URL)")
    sw.add_argument("--harvest-offdrive", action="store_true",
                    help="refuse a shelf on the same drive as the item")
    sw.add_argument("--emergency-free-gb", type=float,
                    help="below this free space on an item's drive, max_idle is halved and"
                         " rules with emergency_delete DELETE (after a verified harvest)"
                         " instead of quarantining")
    sw.add_argument("--measure-cap-s", type=float, default=120.0, metavar="SECONDS",
                    help="per-item age-walk cap (default 120); past it the item is judged"
                         " by its top mtime + a 2000-file sample; negative = no cap")
    sw.add_argument("--receipt", help="write the receipt JSON here (on every exit path)")
    sw.add_argument("--time-budget", type=float, default=3000.0, metavar="SECONDS",
                    help="stop cleanly after this long, receipt marked truncated (default"
                         " 3000: inside a 3600 s scheduler timeout); 0 = no limit")
    sw.add_argument("--json", action="store_true", help="print the receipt as JSON")
    sw.add_argument("--catalog", default=str(_AITHER / "awstorage" / "catalog.db"),
                    help="catalog whose ledger records every decision")
    sw.add_argument("--no-catalog", action="store_true")
    sw.add_argument("--live-ids", help=f"file of live ids, one per line (also ${LIVE_IDS_ENV})")
    sw.add_argument("--audit-log", help="awdit log (default ~/.aither/awstorage/audit.log)")
    sw.add_argument("--no-audit", action="store_true")
    sw.add_argument("--require-audit", action="store_true",
                    help="refuse to remove anything unless awdit records it (exit 2)")
    sw.add_argument("--seal-key", help="awseal key for sealing each harvested item dir"
                                       " (default: awseal's own key location, if any)")
    sw.add_argument("--no-seal", action="store_true", help="do not seal harvested item dirs")
    sw.add_argument("--publish-to", help="awshare-publish each touched harvest day here")
    sw.add_argument("--land-to-awm", metavar="SCOPE",
                    help="land one awm memory per harvested item at SCOPE")
    sw.add_argument("--awm-db", help="awm db (default: awm's own)")
    sw.add_argument("--snapshot-store", help="awrecover store for rules with snapshot: true")
    sw.set_defaults(fn=_cmd_sweep)

    au = sub.add_parser("audit", help="verify the sweep audit log (awdit)")
    au.add_argument("audit_cmd", choices=["verify"])
    au.add_argument("--audit-log")
    au.add_argument("--json", action="store_true")
    au.set_defaults(fn=_cmd_audit)

    hv = sub.add_parser("harvest", help="verify seals on / publish a harvest shelf")
    hsub = hv.add_subparsers(dest="harvest_cmd", required=True)
    hvv = hsub.add_parser("verify", help="check every item seal under a shelf")
    hvv.add_argument("shelf")
    hvv.add_argument("--expect-key", help="publisher public key (hex) to trust")
    hvv.add_argument("--json", action="store_true")
    hvp = hsub.add_parser("publish", help="awshare-bundle one day's harvest")
    hvp.add_argument("day_dir")
    hvp.add_argument("--to", required=True)
    hvp.add_argument("--seal-key")
    hvp.add_argument("--json", action="store_true")
    hv.set_defaults(fn=_cmd_harvest)

    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.cmd:
        ap.print_help()
        return 2
    return a.fn(a)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
