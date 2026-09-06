"""Export a snapshot (or a diff) as a graph: nodes and typed edges.

Node kinds: host, root, tree. Edge kinds: hosts (host->root), contains
(root/tree -> tree), duplicate_of (tree -> tree; same basename and bytes within
1%, across different parents). The shape is deliberately generic JSON so
awgraph, a knowledge graph, or a treemap widget can ingest it without knowing
awstorage.
"""

from __future__ import annotations

from ._fs import exclusive_bytes


def to_graph(snapshot: dict, *, min_bytes: int = 0, duplicates: bool = True) -> dict:
    trees = [t for t in snapshot.get("trees", []) if t["bytes"] >= min_bytes or t["depth"] == 0]
    excl = exclusive_bytes(snapshot)
    host_id = f"host:{snapshot['node']}"
    root_id = f"root:{snapshot['node']}:{snapshot['root']}"
    nodes = [
        {"id": host_id, "kind": "host", "label": snapshot["node"]},
        {"id": root_id, "kind": "root", "label": snapshot["root"],
         "bytes": next((t["bytes"] for t in trees if t["depth"] == 0), 0),
         "taken_at": snapshot.get("taken_at"), "truncated": bool(snapshot.get("truncated"))},
    ]
    edges = [{"src": host_id, "dst": root_id, "kind": "hosts"}]
    by_path = {t["path"]: t for t in trees}

    def tid(p: str) -> str:
        return f"tree:{snapshot['node']}:{p}"

    for t in trees:
        if t["depth"] == 0:
            continue
        nodes.append({
            "id": tid(t["path"]), "kind": "tree", "label": t["path"].rsplit("/", 1)[-1],
            "path": t["path"], "depth": t["depth"], "bytes": t["bytes"],
            "exclusive_bytes": excl.get(t["path"], t["bytes"]), "files": t["files"],
            "cls": t.get("cls"), "refetchable": t.get("refetchable"),
            "confidence": t.get("confidence"), "newest_mtime": t.get("newest_mtime"),
        })
        parent = _parent_path(t["path"], by_path, t["depth"])
        src = tid(parent) if parent and parent != snapshot["root"] else root_id
        edges.append({"src": src, "dst": tid(t["path"]), "kind": "contains"})

    if duplicates:
        buckets: dict[str, list[dict]] = {}
        for t in trees:
            if t["depth"] == 0 or t["bytes"] < max(min_bytes, 1):
                continue
            buckets.setdefault(t["path"].rsplit("/", 1)[-1].lower(), []).append(t)
        for same_name in buckets.values():
            if len(same_name) < 2:
                continue
            same_name.sort(key=lambda x: x["bytes"])
            for i in range(len(same_name) - 1):
                a, b = same_name[i], same_name[i + 1]
                if a["bytes"] and abs(a["bytes"] - b["bytes"]) <= 0.01 * b["bytes"]:
                    if _parent_path(a["path"], by_path, a["depth"]) != \
                            _parent_path(b["path"], by_path, b["depth"]):
                        edges.append({"src": tid(a["path"]), "dst": tid(b["path"]),
                                      "kind": "duplicate_of", "confidence": 0.5,
                                      "reason": "same name, bytes within 1%"})
    return {"schema": 1, "nodes": nodes, "edges": edges,
            "meta": {"node": snapshot["node"], "root": snapshot["root"],
                     "taken_at": snapshot.get("taken_at"), "trees": len(trees)}}


def _parent_path(path: str, by_path: dict, depth: int) -> str | None:
    if depth <= 0:
        return None
    cands = [p for p, t in by_path.items()
             if t["depth"] == depth - 1 and path.startswith(p.rstrip("/") + "/")]
    return max(cands, key=len) if cands else None


def diff_to_graph_delta(diff: dict) -> dict:
    """A diff as graph mutations: which tree nodes to add/remove/update."""
    return {
        "schema": 1,
        "root": diff["root"],
        "add": [{"path": r["path"], "bytes": r["bytes"]} for r in diff["added"]],
        "remove": [{"path": r["path"]} for r in diff["removed"]],
        "update": [{"path": r["path"], "bytes": r["bytes"], "delta": r["delta"]}
                   for r in diff["grown"] + diff["shrunk"]],
        "summary": diff["summary"],
    }
