"""Ranked views over a snapshot -- what a human reads first."""

from __future__ import annotations

from ._fs import exclusive_bytes


def human(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024 or unit == "PB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def rank(snapshot: dict, *, by: str = "exclusive", top: int | None = None,
         min_depth: int = 1) -> list[dict]:
    """Trees sorted by exclusive bytes (default) or aggregate bytes."""
    excl = exclusive_bytes(snapshot)
    rows = []
    for t in snapshot.get("trees", []):
        if t["depth"] < min_depth:
            continue
        rows.append({**t, "exclusive_bytes": excl.get(t["path"], t["bytes"])})
    key = "exclusive_bytes" if by == "exclusive" else "bytes"
    rows.sort(key=lambda r: -r[key])
    return rows[:top] if top else rows


def summarize(snapshot: dict) -> dict:
    """Totals by class and by refetchability -- the numbers a dashboard tile shows."""
    excl = exclusive_bytes(snapshot)
    by_cls: dict[str, int] = {}
    refetch = 0
    keep = 0
    unknown = 0
    for t in snapshot.get("trees", []):
        if t["depth"] == 0:
            continue
        e = excl.get(t["path"], 0)
        c = t.get("cls") or "unclassified"
        by_cls[c] = by_cls.get(c, 0) + e
        if t.get("refetchable") is True:
            refetch += e
        elif t.get("refetchable") is False:
            keep += e
        else:
            unknown += e
    root = next((t for t in snapshot.get("trees", []) if t["depth"] == 0), None)
    return {
        "node": snapshot.get("node"), "root": snapshot.get("root"),
        "taken_at": snapshot.get("taken_at"), "truncated": bool(snapshot.get("truncated")),
        "total_bytes": root["bytes"] if root else 0,
        "files": root["files"] if root else 0,
        "by_class": dict(sorted(by_cls.items(), key=lambda kv: -kv[1])),
        "refetchable_bytes": refetch, "keep_bytes": keep, "unclassified_bytes": unknown,
        "errors": snapshot.get("error_count", len(snapshot.get("errors", []))),
        "elapsed_s": snapshot.get("elapsed_s"),
    }


def render_table(rows: list[dict], *, limit: int = 30) -> str:
    out = [f"{'EXCLUSIVE':>10} {'TOTAL':>10} {'FILES':>8}  {'CLASS':<16} {'RF':<3} PATH"]
    for r in rows[:limit]:
        rf = {True: "yes", False: "no"}.get(r.get("refetchable"), "?")
        out.append(f"{human(r.get('exclusive_bytes', r['bytes'])):>10} {human(r['bytes']):>10} "
                   f"{r['files']:>8}  {str(r.get('cls') or '-'):<16} {rf:<3} {r['path']}")
    return "\n".join(out)
