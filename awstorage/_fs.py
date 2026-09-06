"""Bounded, resumable directory scanning -> a snapshot dict.

A snapshot is a plain dict (JSON-serialisable) so it can cross any wire:

    {"schema": 1, "node": "<hostname>", "root": "E:/", "taken_at": "...",
     "max_depth": 3, "time_budget_s": 120, "truncated": false,
     "trees": [ {"path": "E:/Caches", "depth": 1, "bytes": 157_000_000_000,
                 "files": 12000, "dirs": 340, "newest_mtime": 1756000000.0,
                 "oldest_mtime": 1700000000.0, "fingerprint": "sha1:..."} ],
     "top_files": [ {"path": ..., "bytes": ..., "mtime": ...} ],
     "errors": ["E:/System Volume Information: PermissionError"],
     "elapsed_s": 41.2}

`trees` holds every directory at depth <= max_depth (depth 0 is the root),
each with the AGGREGATE of everything beneath it -- so a parent's bytes
already include its children's. Consumers that want exclusive sizes subtract.

The fingerprint is sha1 over (bytes, files, newest_mtime): cheap, and enough
to notice that a tree changed between the scan and an apply. It is NOT a
content hash; awstorage never reads file contents.

Bounded on purpose: a scan that runs forever on a 4 TB drive is one nobody
runs twice. `time_budget_s` stops the walk and marks the snapshot TRUNCATED
(a real field, printed by every consumer) rather than returning a total that
looks complete and is not.
"""

from __future__ import annotations

import hashlib
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCHEMA_VERSION = 1

# Directories that are never worth descending into: either they lie about size
# (reparse/junction targets, /proc) or they are the OS's own business.
DEFAULT_SKIP_NAMES = frozenset(
    {
        "$recycle.bin",
        "system volume information",
        "proc",
        "sys",
        "dev",
        "run",
    }
)


class ScanError(Exception):
    """The scan could not run at all (root missing, unreadable, not a dir)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm(p: Path) -> str:
    # Forward slashes everywhere so the same tree has ONE spelling in the
    # catalog whether it was scanned from Windows, WSL, or a Linux node.
    return str(p).replace("\\", "/")


def fingerprint(bytes_: int, files: int, newest_mtime: float) -> str:
    h = hashlib.sha1(f"{bytes_}|{files}|{int(newest_mtime)}".encode())
    return "sha1:" + h.hexdigest()[:16]


def scan(
    root: Path | str,
    *,
    max_depth: int = 3,
    time_budget_s: float = 300.0,
    top_files: int = 50,
    skip_names: Iterable[str] = DEFAULT_SKIP_NAMES,
    node: str | None = None,
    follow_symlinks: bool = False,
) -> dict:
    """Walk `root` and return a snapshot dict. Never raises past the root check.

    Per-entry errors (permission denied, vanished file) are recorded in
    `errors` and the walk continues; only an unusable ROOT raises ScanError.
    """
    root_p = Path(root)
    if not root_p.exists():
        raise ScanError(f"root does not exist: {root}")
    if not root_p.is_dir():
        raise ScanError(f"root is not a directory: {root}")
    skip = {s.lower() for s in skip_names}
    t0 = time.monotonic()
    deadline = t0 + float(time_budget_s)

    # Aggregates keyed by the directory path (string), for dirs at depth <= max_depth.
    agg: dict[str, dict] = {}
    errors: list[str] = []
    biggest: list[tuple[int, float, str]] = []  # (bytes, mtime, path) kept small
    truncated = False

    def account(dir_key: str, size: int, mtime: float, is_file: bool) -> None:
        a = agg[dir_key]
        a["bytes"] += size
        if is_file:
            a["files"] += 1
        else:
            a["dirs"] += 1
        if mtime > a["newest_mtime"]:
            a["newest_mtime"] = mtime
        if mtime and (a["oldest_mtime"] == 0.0 or mtime < a["oldest_mtime"]):
            a["oldest_mtime"] = mtime

    def ensure(path_str: str, depth: int) -> None:
        if path_str not in agg:
            agg[path_str] = {
                "path": path_str,
                "depth": depth,
                "bytes": 0,
                "files": 0,
                "dirs": 0,
                "newest_mtime": 0.0,
                "oldest_mtime": 0.0,
                "git": False,
            }

    root_key = _norm(root_p)
    ensure(root_key, 0)
    # Stack of (dir path, depth, ancestors-at-or-below-max-depth keys)
    stack: list[tuple[str, int, tuple[str, ...]]] = [(str(root_p), 0, (root_key,))]

    while stack:
        if time.monotonic() >= deadline:
            truncated = True
            break
        d, depth, owners = stack.pop()
        try:
            it = os.scandir(d)
        except OSError as exc:
            errors.append(f"{_norm(Path(d))}: {type(exc).__name__}")
            continue
        with it:
            for e in it:
                try:
                    if e.is_symlink() and not follow_symlinks:
                        continue
                    if e.is_dir(follow_symlinks=follow_symlinks):
                        if e.name == ".git" and owners[-1] in agg:
                            # A git working tree: its build outputs may be TRACKED
                            # (tenant repos `git add -f` their dist/), so the policy
                            # must not auto-delete inside one. Recorded, not decided.
                            agg[owners[-1]]["git"] = True
                        if e.name.lower() in skip:
                            continue
                        child_depth = depth + 1
                        child_key = _norm(Path(e.path))
                        for k in owners:
                            account(k, 0, 0.0, is_file=False)
                        if child_depth <= max_depth:
                            ensure(child_key, child_depth)
                            stack.append((e.path, child_depth, owners + (child_key,)))
                        else:
                            stack.append((e.path, child_depth, owners))
                    else:
                        st = e.stat(follow_symlinks=follow_symlinks)
                        size = int(st.st_size)
                        mtime = float(st.st_mtime)
                        for k in owners:
                            account(k, size, mtime, is_file=True)
                        if top_files > 0:
                            biggest.append((size, mtime, _norm(Path(e.path))))
                            if len(biggest) > top_files * 4:
                                biggest.sort(reverse=True)
                                del biggest[top_files:]
                except OSError as exc:
                    errors.append(f"{_norm(Path(e.path))}: {type(exc).__name__}")

    biggest.sort(reverse=True)
    trees = []
    for a in sorted(agg.values(), key=lambda x: (x["depth"], x["path"])):
        a = dict(a)
        a["fingerprint"] = fingerprint(a["bytes"], a["files"], a["newest_mtime"])
        trees.append(a)

    return {
        "schema": SCHEMA_VERSION,
        "node": node or socket.gethostname(),
        "root": root_key,
        "taken_at": _now_iso(),
        "max_depth": int(max_depth),
        "time_budget_s": float(time_budget_s),
        "truncated": truncated,
        "trees": trees,
        "top_files": [
            {"path": p, "bytes": b, "mtime": m} for b, m, p in biggest[:top_files]
        ],
        "errors": errors[:200],
        "error_count": len(errors),
        "elapsed_s": round(time.monotonic() - t0, 2),
    }


def exclusive_bytes(snapshot: dict) -> dict[str, int]:
    """Bytes owned by each tree EXCLUDING its scanned children (depth-aware)."""
    by_depth: dict[int, list[dict]] = {}
    for t in snapshot["trees"]:
        by_depth.setdefault(t["depth"], []).append(t)
    children: dict[str, int] = {}
    for depth, trees in by_depth.items():
        if depth == 0:
            continue
        parents = by_depth.get(depth - 1, [])
        for t in trees:
            # The parent is the depth-1 tree whose path is the longest prefix of ours.
            cand = [p["path"] for p in parents
                    if t["path"].startswith(p["path"].rstrip("/") + "/")]
            if cand:
                parent = max(cand, key=len)
                children[parent] = children.get(parent, 0) + t["bytes"]
    return {t["path"]: max(0, t["bytes"] - children.get(t["path"], 0))
            for t in snapshot["trees"]}
