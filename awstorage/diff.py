"""Diff two snapshots of the same root: what appeared, vanished, grew, shrank."""

from __future__ import annotations


def diff_snapshots(older: dict, newer: dict, *, min_delta_bytes: int = 0) -> dict:
    """Return {added, removed, grown, shrunk, summary} keyed by tree path.

    Both snapshots must share `root` (a diff across roots is a category error and
    raises). `node` may differ -- the same mount seen from two hosts is legal.
    Deltas are on AGGREGATE bytes, so a parent grows when any child does; sort by
    |delta| and read from the deepest paths for the actual culprits.
    """
    if older.get("root") != newer.get("root"):
        raise ValueError(f"cannot diff different roots: {older.get('root')!r} vs "
                         f"{newer.get('root')!r}")
    a = {t["path"]: t for t in older.get("trees", [])}
    b = {t["path"]: t for t in newer.get("trees", [])}
    added, removed, grown, shrunk = [], [], [], []
    for p, t in b.items():
        if p not in a:
            if t["bytes"] >= min_delta_bytes:
                added.append({"path": p, "depth": t["depth"], "bytes": t["bytes"],
                              "delta": t["bytes"], "cls": t.get("cls")})
            continue
        d = t["bytes"] - a[p]["bytes"]
        if abs(d) < max(1, min_delta_bytes):
            continue
        row = {"path": p, "depth": t["depth"], "bytes": t["bytes"], "before": a[p]["bytes"],
               "delta": d, "cls": t.get("cls")}
        (grown if d > 0 else shrunk).append(row)
    for p, t in a.items():
        if p not in b and t["bytes"] >= min_delta_bytes:
            removed.append({"path": p, "depth": t["depth"], "bytes": t["bytes"],
                            "delta": -t["bytes"], "cls": t.get("cls")})
    for bucket in (added, removed, grown, shrunk):
        bucket.sort(key=lambda r: -abs(r["delta"]))
    root_a = a.get(older["root"], {}).get("bytes", 0)
    root_b = b.get(newer["root"], {}).get("bytes", 0)
    return {
        "root": newer["root"],
        "older": {"node": older.get("node"), "taken_at": older.get("taken_at"),
                  "truncated": bool(older.get("truncated"))},
        "newer": {"node": newer.get("node"), "taken_at": newer.get("taken_at"),
                  "truncated": bool(newer.get("truncated"))},
        "added": added, "removed": removed, "grown": grown, "shrunk": shrunk,
        "summary": {"root_before": root_a, "root_after": root_b, "root_delta": root_b - root_a,
                    "added": len(added), "removed": len(removed), "grown": len(grown),
                    "shrunk": len(shrunk),
                    # A diff where either side was truncated is a diff of two partial
                    # views; consumers must print this, not hide it.
                    "either_truncated": bool(older.get("truncated") or newer.get("truncated"))},
    }
