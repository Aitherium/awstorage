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

import errno
import hashlib
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .identity import whoami

SCHEMA_VERSION = 1
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

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


def is_reparse(st: os.stat_result) -> bool:
    """True for a Windows reparse point (junction, mount point, symlink)."""
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE)


def iter_file_stats(path: str | os.PathLike) -> Iterator[os.stat_result]:
    """stat of every regular file under `path`, never following a symlink or a
    reparse point (junction). The walker `policy` uses to size and fingerprint a
    tree at apply time, so it agrees with `scan` about what is inside it."""
    stack = [str(path)]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if e.is_symlink() or is_reparse(st):
                    continue
                if stat.S_ISDIR(st.st_mode):
                    stack.append(e.path)
                elif stat.S_ISREG(st.st_mode):
                    yield st


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
                    if not follow_symlinks and entry_is_link(e):
                        # Junctions too: before 3.12 is_symlink() says False for
                        # one, and its target's bytes are not this tree's bytes.
                        continue
                    # A Windows junction is NOT a symlink to Python (is_symlink() is
                    # False) yet points elsewhere: following it double-counts a tree
                    # and lets a quarantine reach outside the root. Refuse every
                    # reparse point unless the caller asked to follow links.
                    if not follow_symlinks and is_reparse(e.stat(follow_symlinks=False)):
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
        "node": node or whoami(),
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


# -- links: never followed, never recursed, only ever unlinked -------------------
#
# A Windows JUNCTION is not a symlink to Python before 3.12: `is_symlink()` is
# False, `os.walk(followlinks=False)` descends into it, and a hand-rolled
# recursive delete walks straight into the TARGET. A scratch tree that holds a
# junction to a real checkout (agents make them for node_modules) would then take
# the checkout with it. So every destructive walk in this package asks
# `is_link()`, which answers True for a symlink, a junction, or any other reparse
# point, and treats the answer as "remove the link itself, never its contents".

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _stat_is_link(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def is_link(path: str | os.PathLike) -> bool:
    """True for a symlink, a Windows junction, or any reparse point. Never follows."""
    isj = getattr(os.path, "isjunction", None)  # 3.12+
    try:
        if os.path.islink(path) or (isj is not None and isj(path)):
            return True
        return _stat_is_link(os.lstat(path))
    except OSError:
        return False


def entry_is_link(e: os.DirEntry) -> bool:
    """`is_link` for a scandir entry, without a second stat on POSIX."""
    try:
        if e.is_symlink():
            return True
        isj = getattr(e, "is_junction", None)  # 3.12+
        if isj is not None and isj():
            return True
        return _stat_is_link(e.stat(follow_symlinks=False))
    except OSError:
        return False


def long_path(p: str | os.PathLike) -> str:
    """Windows extended-length spelling (\\\\?\\) so a 300-char scratch path can be
    removed at all; identity elsewhere. Agent review trees nest node_modules inside
    copies of repos -- MAX_PATH is not hypothetical there."""
    s = os.path.abspath(os.fspath(p))
    if os.name != "nt" or s.startswith("\\\\?\\"):
        return s
    if s.startswith("\\\\"):
        return "\\\\?\\UNC\\" + s[2:]
    return "\\\\?\\" + s


def unlink_link(path: str) -> None:
    """Remove a link ITSELF. A directory junction/symlink on Windows needs rmdir;
    neither call touches the target."""
    try:
        os.unlink(path)
    except OSError:
        os.rmdir(path)


def _force(fn, path: str) -> None:
    try:
        fn(path)
    except PermissionError:
        # Read-only bit on Windows; clear it and retry once.
        os.chmod(path, stat.S_IWRITE)
        fn(path)


def walk_no_follow(root: str | os.PathLike):
    """Yield (dirpath, dir_entries, file_entries, link_entries) top-down.

    Like os.walk, except a link of ANY kind (symlink, junction, reparse point)
    is reported in `link_entries` and never descended -- the one property every
    destructive caller here depends on.
    """
    stack = [os.fspath(root)]
    while stack:
        d = stack.pop()
        dirs: list[os.DirEntry] = []
        files: list[os.DirEntry] = []
        links: list[os.DirEntry] = []
        try:
            with os.scandir(d) as it:
                for e in it:
                    if entry_is_link(e):
                        links.append(e)
                    else:
                        try:
                            isdir = e.is_dir(follow_symlinks=False)
                        except OSError:
                            isdir = False
                        (dirs if isdir else files).append(e)
        except OSError:
            continue
        yield d, dirs, files, links
        stack.extend(e.path for e in reversed(dirs))


# Windows: 5 = access denied (an open handle without FILE_SHARE_DELETE, or a
# delete-pending file), 32 = sharing violation, 33 = lock violation.
BUSY_WINERRORS = (5, 32, 33)
# rmdir on a directory still holding a busy file: ERROR_DIR_NOT_EMPTY (145) on
# Windows, ENOTEMPTY / EEXIST elsewhere. A consequence of the busy file, not a new fault.
_NOT_EMPTY_WINERRORS = (145,)
_NOT_EMPTY_ERRNOS = (errno.ENOTEMPTY, errno.EEXIST)


def is_busy_error(exc: BaseException) -> bool:
    """Is this OSError "something holds the file open", i.e. a live signal, not a fault?

    PermissionError covers EACCES/EPERM (and Windows winerror 5 / 32 map to it);
    the winerror check covers a sharing/lock violation raised as a bare OSError.
    """
    if not isinstance(exc, OSError):
        return False
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in BUSY_WINERRORS


def _is_not_empty(exc: OSError) -> bool:
    return (getattr(exc, "winerror", None) in _NOT_EMPTY_WINERRORS
            or exc.errno in _NOT_EMPTY_ERRNOS)


def _under(child: str, parent: str) -> bool:
    c = os.path.normcase(child).rstrip("\\/")
    p = os.path.normcase(parent).rstrip("\\/")
    return c == p or c.startswith(p + os.sep) or c.startswith(p + "/")


def remove_tree_detail(path: str | os.PathLike) -> tuple[int, list[str], list[str]]:
    """Delete a file or tree without following any link. Returns (bytes, errors, busy).

    `busy` lists what could not be removed because something holds it open
    (`is_busy_error`), plus directories left non-empty ONLY because a busy file sits
    under them. Everything else that failed is in `errors`. Nothing is raised: a
    busy file stays for the next pass, the rest of the tree is still removed.
    """
    top = long_path(path)
    errors: list[str] = []
    busy: list[str] = []
    busy_paths: list[str] = []
    removed = 0

    def fail(p: str, exc: OSError) -> None:
        if is_busy_error(exc):
            busy.append(f"{p}: {type(exc).__name__}")
            busy_paths.append(p)
        else:
            errors.append(f"{p}: {type(exc).__name__}")

    try:
        st = os.lstat(top)
    except FileNotFoundError:
        return 0, [], []
    except OSError as exc:
        fail(str(path), exc)
        return 0, errors, busy
    if _stat_is_link(st):
        try:
            unlink_link(top)
        except OSError as exc:
            fail(str(path), exc)
        return 0, errors, busy
    if not stat.S_ISDIR(st.st_mode):
        try:
            _force(os.unlink, top)
            removed += int(st.st_size)
        except OSError as exc:
            fail(str(path), exc)
        return removed, errors, busy
    dirs_in_order: list[str] = []
    for d, _dirs, files, links in walk_no_follow(top):
        dirs_in_order.append(d)
        for e in links:
            try:
                unlink_link(e.path)
            except OSError as exc:
                fail(e.path, exc)
        for e in files:
            try:
                size = e.stat(follow_symlinks=False).st_size
                _force(os.unlink, e.path)
                removed += int(size)
            except OSError as exc:
                fail(e.path, exc)
    for d in reversed(dirs_in_order):  # children before parents
        try:
            _force(os.rmdir, d)
        except OSError as exc:
            if _is_not_empty(exc) and any(_under(b, d) for b in busy_paths):
                busy.append(f"{d}: kept, holds a busy file")
                busy_paths.append(d)
            else:
                fail(d, exc)
    return removed, errors, busy


def remove_tree(path: str | os.PathLike) -> tuple[int, list[str]]:
    """Delete a file or tree without following any link. Returns (bytes, errors).

    A link at the top or anywhere inside is unlinked; its target is untouched.
    Errors are collected, not raised: the caller re-stats, so a stubborn file
    surfaces as bytes that did not go away, never as a silent success. Busy files
    count as errors here; a caller that tells busy from failed uses
    `remove_tree_detail`.
    """
    removed, errors, busy = remove_tree_detail(path)
    return removed, errors + busy


def contains_link(path: str | os.PathLike) -> bool:
    """Does the tree hold a link anywhere (the top included)?"""
    if is_link(path):
        return True
    for _d, _dirs, _files, links in walk_no_follow(long_path(path)):
        if links:
            return True
    return False


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
