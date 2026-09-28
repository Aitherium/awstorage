"""CLI verbs for 0.4.0: suggest / suggestions / suggestion / apply-suggestions / trust,
watch, place, shelf prune. Wired into `awstorage.cli.main` by `add_parsers`.

    awstorage suggest PATH --reason R --by AGENT [--action quarantine|delete|archive]
                           [--evidence JSON] [--ttl-days N] [--json]
    awstorage suggestions [--status S] [--limit N] [--json]
    awstorage suggestion approve|reject|revert ID [--card FILE|JSON] [--json]
    awstorage apply-suggestions [--yes] [--harvest-to D] [--receipt P] [--json]
    awstorage trust [--agent A] [--json]
    awstorage watch --floors C:=40,D:=60,E:=30 [--once] [--yes] [--receipt P]
                    [--interval 300] [--alerts P] [--harvest-to D] [--json]
    awstorage place --size 90GB [--from PATH] [--to DRIVE] [--floors ...] [--json]
    awstorage shelf prune --older-than 30d [--shelf D] [--yes] [--json]

Exit codes as everywhere: 0 ok, 1 refused / violation, 2 could not judge.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from .report import human

_AITHER = Path.home() / ".aither"


def _catalog_arg(p) -> None:
    p.add_argument("--catalog", help="catalog (default $AWSTORAGE_CATALOG or "
                                     "~/.aither/awstorage/catalog.db)")


def _print_json(obj) -> None:
    print(json.dumps(obj, indent=1, sort_keys=True, default=str))


# -- suggest -------------------------------------------------------------------------

def _cmd_suggest(a) -> int:
    from .suggest import suggest

    ev = None
    if a.evidence:
        try:
            ev = json.loads(a.evidence)
        except ValueError as exc:
            print(f"could not judge: --evidence is not JSON: {exc}", file=sys.stderr)
            return 2
    try:
        r = suggest(a.path, reason=a.reason, suggested_by=a.by, action=a.action,
                    evidence=ev, ttl_days=a.ttl_days, catalog=a.catalog)
    except ValueError as exc:
        print(f"could not judge: {exc}", file=sys.stderr)
        return 2
    if a.json:
        _print_json(r)
    else:
        size = (human(r["size"]) if r["size"] is not None
                else "-" if r["status"] == "refused" else "capped")
        print(f"#{r['id']} {r['status'].upper()}: {r['class']} {size} -- {r['why']}")
        for c in r["checks"]:
            print(f"  {c}")
    return 1 if r["status"] == "refused" else 0


def _cmd_suggestions(a) -> int:
    from .suggest import suggestions

    try:
        rows = suggestions(a.status, limit=a.limit, catalog=a.catalog)
    except ValueError as exc:
        print(f"could not judge: {exc}", file=sys.stderr)
        return 2
    if a.json:
        _print_json(rows)
        return 0
    if not rows:
        print("no suggestions")
    for r in rows:
        size = "capped" if r["size"] is None else human(r["size"])
        print(f"#{r['id']:<5} {r['status']:<13} {r['action']:<10} {size:>10}  "
              f"{r['suggested_by']:<16} {r['path']}  -- {r.get('why') or ''}")
    return 0


def _load_card(spec: str | None):
    if not spec:
        return None
    if os.path.isfile(spec):
        return json.loads(Path(spec).read_text(encoding="utf-8"))
    return json.loads(spec)


def _cmd_suggestion(a) -> int:
    from .suggest import resolve_suggestion, revert_suggestion

    if a.verb == "revert":
        r = revert_suggestion(a.id, catalog=a.catalog)
    else:
        try:
            card = _load_card(a.card)
        except (OSError, ValueError) as exc:
            print(f"could not judge: --card: {exc}", file=sys.stderr)
            return 2
        r = resolve_suggestion(a.id, a.verb, card=card, catalog=a.catalog)
    if a.json:
        _print_json(r)
    else:
        print(f"#{r['id']} {'ok' if r['ok'] else 'REFUSED'}: "
              f"{r.get('status', '')} {r['why']}".replace("  ", " "))
    return 0 if r["ok"] else 1


def _cmd_apply_suggestions(a) -> int:
    from .suggest import apply_suggestions
    from .sweep import write_receipt

    rec = apply_suggestions(dry_run=not a.yes, harvest_to=a.harvest_to, catalog=a.catalog)
    if a.receipt:
        try:
            write_receipt(a.receipt, rec)
        except OSError as exc:
            rec["could_not_judge"].append(f"receipt not written: {exc}")
            rec["exit_code"] = 2
    if a.json:
        _print_json(rec)
        return int(rec["exit_code"])
    mode = "DRY RUN (plan)" if rec["dry_run"] else "APPLY"
    print(f"{mode}: {len(rec['items'])} approved suggestion(s); {rec['applied']} applied, "
          f"{rec['drifted']} drifted, {rec['demoted']} demoted, {rec['expired']} expired, "
          f"{rec['reverts_detected']} revert(s) detected")
    for it in rec["items"]:
        print(f"  #{it['id']:<5} {it.get('outcome', '?'):<16} {it['path']}  -- "
              f"{it.get('reason', '')}")
    for q in rec["purged"]:
        print(f"  purge {q.get('outcome')}: {q['entry']}")
    print(f"freed {human(rec['bytes_freed'])}, quarantined {human(rec['bytes_quarantined'])},"
          f" harvested {rec['files_harvested']} file(s)")
    for e in rec["errors"]:
        print(f"  FAILED: {e}", file=sys.stderr)
    for e in rec["could_not_judge"]:
        print(f"  COULD NOT JUDGE: {e}", file=sys.stderr)
    if rec["dry_run"] and rec["exit_code"] == 0:
        print("dry run. Re-run with --yes to act.")
    return int(rec["exit_code"])


def _cmd_trust(a) -> int:
    from .suggest import trust

    rows = trust(a.agent, catalog=a.catalog)
    if a.json:
        _print_json(rows)
        return 0
    print("trust = (applied - 3*reverted + 1) / (applied + rejected + 2); "
          f"auto lane at >= {rows[0]['threshold'] if rows else '-'}")
    print(f"{'agent':<24} {'made':>5} {'appr':>5} {'rej':>5} {'appl':>5} {'rev':>5} "
          f"{'refd':>5} {'trust':>7}  auto")
    for r in rows:
        print(f"{r['agent']:<24} {r['made']:>5} {r['approved']:>5} {r['rejected']:>5} "
              f"{r['applied']:>5} {r['reverted']:>5} {r['refused']:>5} {r['trust']:>7.3f}  "
              f"{'yes' if r['auto_eligible'] else 'no'}")
    if not rows:
        print("(no suggestions yet)")
    return 0


# -- watch / place / shelf -----------------------------------------------------------

def _cmd_watch(a) -> int:
    from .space import FloorsError, parse_floors, watch_once

    try:
        floors = parse_floors(a.floors)
    except FloorsError as exc:
        print(f"could not judge: {exc}", file=sys.stderr)
        return 2
    rules = [r.strip() for r in a.rules.split(",") if r.strip()]
    policy = None
    if a.policy:
        from .cli import _load_policy
        try:
            policy = _load_policy(a.policy)
        except (OSError, ValueError) as exc:
            print(f"could not judge: cannot load policy {a.policy}: {exc}", file=sys.stderr)
            return 2
    while True:
        rec = watch_once(floors, yes=a.yes, rules=rules, policy=policy,
                         harvest_to=a.harvest_to,
                         catalog=None if a.no_catalog else a.catalog,
                         alerts_path=a.alerts, receipt=a.receipt)
        if a.json:
            _print_json(rec)
        else:
            for k, d in rec["drives"].items():
                after = d["free_after"]
                flag = "UNDER" if d["under_after"] else ("recovered" if d["under_before"]
                                                         else "ok")
                print(f"{k:<6} floor {d['floor_gb']:>6g} GB  free {human(d['free_before'])}"
                      f" -> {human(after) if after is not None else '?'}  {flag}")
                if d.get("sweep"):
                    sw = d["sweep"]
                    print(f"       emergency sweep ({'act' if a.yes else 'plan'}): rules "
                          f"{','.join(sw.get('rules') or []) or '-'}; freed "
                          f"{human(sw.get('bytes_freed') or 0)}"
                          + (f"; {len(sw['harvest_skipped'])} kept (shelf drive low)"
                             if sw.get("harvest_skipped") else "")
                          + (f"; {sw['note']}" if sw.get("note") else ""))
            for e in rec["could_not_judge"]:
                print(f"  COULD NOT JUDGE: {e}", file=sys.stderr)
            print(f"watch pass {rec['elapsed_s']}s, exit {rec['exit_code']}")
        if a.once:
            return int(rec["exit_code"])
        time.sleep(max(5.0, float(a.interval)))


def _cmd_place(a) -> int:
    from .space import FloorsError, drive_label, parse_floors, place

    try:
        floors = parse_floors(a.floors)
        rows = place(a.size, floors, source=a.from_path, default_floor_gb=a.default_floor_gb)
    except FloorsError as exc:
        print(f"could not judge: {exc}", file=sys.stderr)
        return 2
    target_ok = None
    if a.to:
        want = drive_label(a.to if not a.to.rstrip(":").isalpha() else a.to[0] + ":/")
        hit = [r for r in rows if r["drive"].lower() == want.lower()]
        target_ok = bool(hit and hit[0]["ok"])
    if a.json:
        _print_json({"rows": rows, "to": a.to, "to_ok": target_ok})
    else:
        for r in rows:
            fa = r["free_after"]
            print(f"{r['drive']:<8} free {human(r['free']) if r['free'] is not None else '?':>10}"
                  f" -> {human(fa) if fa is not None else '?':>10}  floor {r['floor_gb']:g} GB"
                  f"  {'OK' if r['ok'] else 'NO'}  {r['why']}")
    if target_ok is not None:
        return 0 if target_ok else 1
    return 0 if any(r["ok"] for r in rows) else 1


def _cmd_shelf(a) -> int:
    from .space import prune_shelf
    from .sweep import SweepConfigError, parse_duration

    try:
        older = parse_duration(a.older_than)
    except SweepConfigError as exc:
        print(f"could not judge: {exc}", file=sys.stderr)
        return 2
    r = prune_shelf(a.shelf, older_than_s=older, dry_run=not a.yes)
    if a.json:
        _print_json(r)
    else:
        for x in r["removed"]:
            print(f"  {'would remove' if r['dry_run'] else 'removed'} {x['dir']} "
                  f"({x['age_days']}d)")
        print(f"{len(r['removed'])} day dir(s) {'to prune' if r['dry_run'] else 'pruned'}, "
              f"{r['kept']} kept, freed {human(r['bytes_freed'])}")
        for e in r["errors"]:
            print(f"  FAILED: {e}", file=sys.stderr)
        if r["dry_run"]:
            print("dry run. Re-run with --yes to act.")
    if r["errors"] and not r["removed"] and not Path(os.path.expanduser(a.shelf)).is_dir():
        return 2
    return 1 if r["errors"] else 0


def add_parsers(sub) -> None:
    from .suggest import STATUSES, SUGGEST_ACTIONS

    s = sub.add_parser("suggest", help="an agent proposes removing a path (never acts)")
    s.add_argument("path")
    s.add_argument("--reason", required=True)
    s.add_argument("--by", required=True, help="the suggesting agent's name")
    s.add_argument("--action", default="quarantine", choices=SUGGEST_ACTIONS)
    s.add_argument("--evidence", help='JSON claims, e.g. {"bytes": 123, "idle_hours": 48}')
    s.add_argument("--ttl-days", type=float, default=7.0)
    _catalog_arg(s)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=_cmd_suggest)

    ls = sub.add_parser("suggestions", help="list suggestions")
    ls.add_argument("--status", choices=STATUSES)
    ls.add_argument("--limit", type=int, default=50)
    _catalog_arg(ls)
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(fn=_cmd_suggestions)

    one = sub.add_parser("suggestion", help="approve (with a decision card), reject or "
                                            "revert one suggestion")
    one.add_argument("verb", choices=["approve", "reject", "revert"])
    one.add_argument("id", type=int)
    one.add_argument("--card", help="decision card JSON (a file or the JSON itself)")
    _catalog_arg(one)
    one.add_argument("--json", action="store_true")
    one.set_defaults(fn=_cmd_suggestion)

    ap = sub.add_parser("apply-suggestions", help="act on approved suggestions (dry-run "
                                                  "unless --yes)")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--harvest-to", default=str(_AITHER / "harvest"))
    ap.add_argument("--receipt")
    _catalog_arg(ap)
    ap.add_argument("--json", action="store_true")
    ap.set_defaults(fn=_cmd_apply_suggestions)

    tr = sub.add_parser("trust", help="per-agent suggestion ledger and trust score")
    tr.add_argument("--agent")
    _catalog_arg(tr)
    tr.add_argument("--json", action="store_true")
    tr.set_defaults(fn=_cmd_trust)

    w = sub.add_parser("watch", help="fast free-space guard: emergency sweep + alert under "
                                     "a floor")
    w.add_argument("--floors", help="C:=40,D:=60,E:=30 (GB; default $AWSTORAGE_FLOORS)")
    w.add_argument("--once", action="store_true", help="one pass, then exit")
    w.add_argument("--yes", action="store_true", help="let the emergency sweep act "
                                                      "(default: plan + alert only)")
    w.add_argument("--interval", type=float, default=300.0)
    w.add_argument("--rules", default="agent-scratch,temp-toplevel")
    w.add_argument("--policy", help="JSON/YAML policy whose `retention` rules may be named")
    w.add_argument("--receipt")
    w.add_argument("--alerts", help="alerts jsonl (default ~/.aither/awstorage/alerts.jsonl)")
    w.add_argument("--harvest-to", default=str(_AITHER / "harvest"))
    w.add_argument("--catalog", default=str(_AITHER / "awstorage" / "catalog.db"))
    w.add_argument("--no-catalog", action="store_true")
    w.add_argument("--json", action="store_true")
    w.set_defaults(fn=_cmd_watch)

    pl = sub.add_parser("place", help="where may N GB go? refuses a drive it would push "
                                      "under its floor")
    pl.add_argument("--size", required=True, help="e.g. 90GB")
    pl.add_argument("--from", dest="from_path", help="the data's current path (its drive "
                                                     "is not a target)")
    pl.add_argument("--to", help="judge this one target drive (exit 1 when refused)")
    pl.add_argument("--floors", help="C:=40,D:=60 (default $AWSTORAGE_FLOORS)")
    pl.add_argument("--default-floor-gb", type=float, default=20.0)
    pl.add_argument("--json", action="store_true")
    pl.set_defaults(fn=_cmd_place)

    sh = sub.add_parser("shelf", help="harvest shelf maintenance")
    shs = sh.add_subparsers(dest="shelf_cmd", required=True)
    pr = shs.add_parser("prune", help="remove harvest day dirs older than N")
    pr.add_argument("--older-than", required=True, help="e.g. 30d")
    pr.add_argument("--shelf", default=str(_AITHER / "harvest"))
    pr.add_argument("--yes", action="store_true")
    pr.add_argument("--json", action="store_true")
    sh.set_defaults(fn=_cmd_shelf)
