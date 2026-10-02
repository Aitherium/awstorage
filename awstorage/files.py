"""File index: every file on every declared root -- searchable, hashed for duplicates,
rolled up by directory, pushed to the fleet as a DELTA.

The snapshot plane (`_fs.scan`) answers "which TREE is big"; this module answers
"where is that FILE" and "which files are the same bytes". It lives in a sibling
SQLite file, ``files.db``, next to the awstorage catalog -- same package, same schema
family, not a third inventory (it replaces the design's unimplemented ``artifacts``):

    files(tenant, node, path, name, parent, bytes, mtime_ns, ext, mime, partial_hash,
          sha256, dev, ino, nlink, git_root, sensitive, never, seq, scanned_at, push_id)
          PRIMARY KEY (tenant, node, path)
    files_fts(name)          FTS5 over the BASENAME, trigram tokenizer when available
    dirs(tenant, node, path, parent, name, bytes, files, newest_mtime_ns)
                             rollup maintained at every change: /files/tree reads it
    roots, files_deleted (tombstones, 30 d), dupe_groups, file_push_state,
    node_volumes, push_jobs, meta(seq)

**Incremental.** A rescan writes ONLY rows whose size, mtime or hash actually changed;
each such write takes a new node-local ``seq``. Deletions are found after a COMPLETED
walk through a TEMP ``seen(path)`` table and become tombstones; a truncated walk
deletes nothing. A delta push sends ``seq > since_seq``.

**Duplicates, cheaply.** Ported from the dedup engine (credited in the commit; source
was an uncommitted ``lib/storage/dedup.py``): size bucket -> head+tail partial hash ->
full sha256, each stage only for files the previous one could not rule out, on 8
threads, bounded by time AND bytes. A hash is stored only if the file still has the
size and mtime the row describes when the read finishes. Hard links (same node, dev,
ino) collapse to one member; ``actionable_bytes`` counts only copies a manage action
could really reclaim.

**Tenancy.** Every table carries ``tenant`` (default ``platform``); every read filters
on it and duplicate groups never cross it. The Genesis router stamps it from the
authenticated caller -- this module never reads it from a payload.

Stdlib only. Never deletes a file on disk, only index rows.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import math
import mimetypes
import os
import re
import sqlite3
import stat as stat_mod
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from . import guards as _guards

# -- wire constants (a node and Genesis must agree on these) ------------------------
PARTIAL_BYTES = 64 * 1024
PARTIAL_ALGO = "sha256-headtail-65536"   # sha256(head + b"\x00" + tail), 64 KiB each
PLATFORM_TENANT = "platform"

# -- bounds --------------------------------------------------------------------------
DEFAULT_MIN_HASH_BYTES = 4096
DEFAULT_HASH_BUDGET_BYTES = 50 * 1024 ** 3
DEFAULT_MIN_DUPE_BYTES = 1024 * 1024
HASH_WORKERS = 8
TXN_ROWS = 5000                 # rows per transaction, per keyset page
MAX_PART_ROWS = 50_000          # upserts per pushed part
MAX_SYNC_DELETES = 50_000       # deletes per part above which ingest becomes a job
SEARCH_SCAN_CAP = 50_000        # FTS matches scanned per search call -> partial:true
GROUP_PATHS = 20                # paths listed per duplicate group
MAX_TREE_NODES = 2000
TOMBSTONE_DAYS = 30
STALE_SECONDS = 48 * 3600
BIG_PRUNE = 100_000             # after a prune this large: FTS optimize + vacuum
MAX_PATH_CHARS = 4096
MAX_EXT_CHARS = 32
MAX_MIME_CHARS = 255
_MAX_TS = 1e11
_IN_CHUNK = 400
_CHUNK = 1 << 20
_REPARSE = getattr(stat_mod, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DRIVE_ROOT = re.compile(r"^[A-Za-z]:/$")

HASH_MODES = ("auto", "none", "full")

#: Directory NAMES never descended into (case-insensitive). Ported from dedup.yaml.
DEFAULT_EXCLUDE_DIRS = frozenset({
    ".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "$recycle.bin", "system volume information", ".awstorage-quarantine",
    ".dedup-quarantine", "proc", "sys", "dev", "run",
})

#: Indexed (real disk usage) but never HASHED: huge, always-open or always-changing.
NO_HASH_GLOBS = ("*.vhdx", "*.vhd", "*.avhdx", "pagefile.sys", "hiberfil.sys",
                 "swapfile.sys")

_DDL = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files (
  tenant TEXT NOT NULL DEFAULT 'platform',
  node TEXT NOT NULL,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  parent TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL,
  ext TEXT NOT NULL DEFAULT '',
  mime TEXT,
  partial_hash TEXT,
  sha256 TEXT,
  dev INTEGER,
  ino INTEGER,
  nlink INTEGER,
  git_root TEXT,
  sensitive INTEGER NOT NULL DEFAULT 0,
  never INTEGER NOT NULL DEFAULT 0,
  seq INTEGER NOT NULL DEFAULT 0,
  scanned_at TEXT NOT NULL,
  push_id TEXT,
  PRIMARY KEY (tenant, node, path)
);
CREATE INDEX IF NOT EXISTS files_ext ON files(ext, node, path);
CREATE INDEX IF NOT EXISTS files_mtime ON files(node, mtime_ns);
CREATE INDEX IF NOT EXISTS files_sha256 ON files(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS files_bytes ON files(tenant, node, bytes);
CREATE INDEX IF NOT EXISTS files_seq ON files(tenant, node, seq);
CREATE INDEX IF NOT EXISTS files_parent ON files(tenant, node, parent, bytes);
CREATE TABLE IF NOT EXISTS dirs (
  tenant TEXT NOT NULL DEFAULT 'platform',
  node TEXT NOT NULL,
  path TEXT NOT NULL,
  parent TEXT NOT NULL,
  name TEXT NOT NULL,
  bytes INTEGER NOT NULL DEFAULT 0,
  files INTEGER NOT NULL DEFAULT 0,
  newest_mtime_ns INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant, node, path)
);
CREATE INDEX IF NOT EXISTS dirs_parent ON dirs(tenant, node, parent, bytes);
CREATE TABLE IF NOT EXISTS roots (
  tenant TEXT NOT NULL DEFAULT 'platform',
  node TEXT NOT NULL,
  root TEXT NOT NULL,
  files INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0,
  scanned_at TEXT,
  hashed_pct REAL,
  truncated INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  last_push_at TEXT,
  pushed_seq INTEGER NOT NULL DEFAULT 0,
  content_ingest INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant, node, root)
);
CREATE TABLE IF NOT EXISTS files_deleted (
  tenant TEXT NOT NULL DEFAULT 'platform',
  node TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT,
  bytes INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT NOT NULL,
  seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS files_deleted_seq ON files_deleted(tenant, node, seq, path);
CREATE INDEX IF NOT EXISTS files_deleted_at ON files_deleted(deleted_at);
CREATE TABLE IF NOT EXISTS dupe_groups (
  tenant TEXT NOT NULL DEFAULT 'platform',
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  count INTEGER NOT NULL,
  nodes INTEGER NOT NULL,
  wasted_bytes INTEGER NOT NULL,
  actionable_bytes INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant, sha256)
);
CREATE INDEX IF NOT EXISTS dupe_groups_rank ON dupe_groups(tenant, wasted_bytes, sha256);
CREATE TABLE IF NOT EXISTS file_push_state (
  tenant TEXT NOT NULL,
  node TEXT NOT NULL,
  root TEXT NOT NULL,
  last_seq INTEGER NOT NULL DEFAULT 0,
  scan_id TEXT,
  parts INTEGER,
  parts_seen TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant, node, root)
);
CREATE TABLE IF NOT EXISTS node_volumes (
  tenant TEXT NOT NULL,
  node TEXT NOT NULL,
  volumes TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant, node)
);
CREATE TABLE IF NOT EXISTS push_jobs (
  job_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  node TEXT NOT NULL,
  status TEXT NOT NULL,
  result TEXT,
  created_at TEXT NOT NULL
);
"""

_FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
  INSERT INTO files_fts(rowid, name) VALUES (new.rowid, new.name);
END;
CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
  INSERT INTO files_fts(files_fts, rowid, name) VALUES ('delete', old.rowid, old.name);
END;
CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE OF name ON files BEGIN
  INSERT INTO files_fts(files_fts, rowid, name) VALUES ('delete', old.rowid, old.name);
  INSERT INTO files_fts(rowid, name) VALUES (new.rowid, new.name);
END;
"""

_COLS = ("path", "name", "parent", "bytes", "mtime_ns", "ext", "mime", "partial_hash",
         "sha256", "dev", "ino", "nlink", "git_root", "sensitive", "never", "seq",
         "scanned_at")
_CMP = ("bytes", "mtime_ns", "partial_hash", "sha256", "dev", "ino", "nlink", "git_root",
        "sensitive", "never")
_UPSERT = (
    "INSERT INTO files(tenant, node, " + ", ".join(_COLS) + ", push_id) VALUES ("
    + ",".join("?" * (len(_COLS) + 3)) + ") ON CONFLICT(tenant, node, path) DO UPDATE SET "
    + ", ".join(f"{c} = excluded.{c}" for c in _COLS if c != "path")
    + ", push_id = COALESCE(excluded.push_id, files.push_id)"
)


# ---------------------------------------------------------------------------
# connection
# ---------------------------------------------------------------------------

def open_index(path: str | os.PathLike) -> sqlite3.Connection:
    """Open (creating) a files.db: 30 s lock wait, incremental auto-vacuum, WAL."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    new = not p.exists() or p.stat().st_size == 0
    db = sqlite3.connect(str(p), timeout=30)
    db.execute("PRAGMA busy_timeout=30000")
    if new:
        db.execute("PRAGMA auto_vacuum=INCREMENTAL")
    db.execute("PRAGMA journal_mode=WAL")
    ensure_schema(db)
    return db


def ensure_schema(db: sqlite3.Connection) -> str | None:
    """Create the tables; returns the FTS tokenizer in use (None: no FTS5 at all)."""
    db.executescript(_DDL)
    row = db.execute("SELECT v FROM meta WHERE k = 'fts_tokenizer'").fetchone()
    if row:
        return row[0] or None
    tok = None
    for cand in ("trigram", "unicode61 remove_diacritics 2"):
        try:
            db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5("
                       f"name, content='files', content_rowid='rowid', tokenize='{cand}')")
            tok = cand.split()[0]
            break
        except sqlite3.OperationalError:
            continue
    if tok:
        db.executescript(_FTS_TRIGGERS)
    with db:
        db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES ('fts_tokenizer', ?)", (tok or "",))
        db.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('seq', '0')")
    return tok


def fts_tokenizer(db: sqlite3.Connection) -> str | None:
    row = db.execute("SELECT v FROM meta WHERE k = 'fts_tokenizer'").fetchone()
    return (row[0] or None) if row else None


def current_seq(db: sqlite3.Connection) -> int:
    row = db.execute("SELECT v FROM meta WHERE k = 'seq'").fetchone()
    return int(row[0]) if row else 0


def _next_seq(db: sqlite3.Connection) -> int:
    db.execute("UPDATE meta SET v = CAST(v AS INTEGER) + 1 WHERE k = 'seq'")
    return current_seq(db)


def default_catalog_path() -> Path:
    env = os.environ.get("AWSTORAGE_CATALOG")
    return Path(env) if env else Path.home() / ".aither" / "awstorage" / "catalog.db"


def default_index_path(catalog: str | os.PathLike | None = None) -> Path:
    """files.db, the sibling of the catalog."""
    env = os.environ.get("AWSTORAGE_FILES_DB")
    if env and catalog is None:
        return Path(env)
    return Path(catalog or default_catalog_path()).with_name("files.db")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def norm_path(p: str | os.PathLike) -> str:
    """One spelling per path whatever OS scanned it (matches `_fs._norm`)."""
    return str(p).replace("\\", "/")


def norm_root(root: str | os.PathLike) -> str:
    r = norm_path(os.path.abspath(str(root)))
    if len(r) > 1 and r.endswith("/") and not _DRIVE_ROOT.match(r):
        r = r.rstrip("/")
    return r


def _clean(p: str) -> str:
    p = norm_path(p)
    if len(p) > 1 and p.endswith("/") and not _DRIVE_ROOT.match(p):
        p = p.rstrip("/")
    return p


def _prefix(root: str) -> str:
    return root if root.endswith("/") else root + "/"


def _under(prefix: str) -> tuple[str, str]:
    """(lo, hi) with `path >= lo AND path < hi` exactly "path starts with prefix" under
    SQLite's binary collation -- an index range on (tenant, node, path). Equivalent to
    the contract's `path < :p || X'FFFF'` (no UTF-8 byte is 0xFF) and never a LIKE,
    which is case-insensitive and cannot use the index with an ESCAPE clause."""
    return prefix, prefix[:-1] + chr(ord(prefix[-1]) + 1)


def parent_of(path: str) -> str | None:
    """Parent directory in index spelling; None above a drive / filesystem root."""
    if path == "/" or _DRIVE_ROOT.match(path):
        return None
    i = path.rfind("/")
    if i < 0:
        return None
    head = path[:i]
    if head == "":
        return "/"
    if re.fullmatch(r"[A-Za-z]:", head):
        return head + "/"
    return head


def name_of(path: str) -> str:
    if path == "/" or _DRIVE_ROOT.match(path):
        return path
    return path.rsplit("/", 1)[-1]


def ext_of(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    if "." not in base.lstrip("."):
        return ""
    return base.rsplit(".", 1)[-1].lower()[:MAX_EXT_CHARS]


def mime_of(name: str) -> str | None:
    return mimetypes.guess_type(name, strict=False)[0]


def partial_hash(path: str, size: int, partial_bytes: int = PARTIAL_BYTES
                 ) -> tuple[str, str | None]:
    """`(partial, sha256_or_None)`: sha256 over head + NUL + tail. A file no larger
    than two samples is read whole, so its partial IS its full sha256."""
    with open(path, "rb") as fh:
        if size <= partial_bytes * 2:
            digest = hashlib.sha256(fh.read()).hexdigest()
            return digest, digest
        head = fh.read(partial_bytes)
        fh.seek(-partial_bytes, os.SEEK_END)
        tail = fh.read(partial_bytes)
    return hashlib.sha256(head + b"\x00" + tail).hexdigest(), None


def full_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _no_hash(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return any(fnmatch.fnmatchcase(name, g) for g in NO_HASH_GLOBS)


def _nz(v: Any) -> int | None:
    try:
        i = int(v)
    except (TypeError, ValueError):
        return None
    return i if i > 0 else None


def _chunks(seq: list, n: int) -> Iterator[list]:
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# ---------------------------------------------------------------------------
# the one write path: apply_changes (local scan AND Genesis ingest)
# ---------------------------------------------------------------------------

def _prior(db: sqlite3.Connection, tenant: str, node: str, paths: list[str]) -> dict:
    out: dict[str, dict] = {}
    for part in _chunks(paths, _IN_CHUNK):
        q = ("SELECT path, " + ", ".join(_CMP) + " FROM files WHERE tenant = ? AND node = ?"
             " AND path IN (" + ",".join("?" * len(part)) + ")")
        for r in db.execute(q, [tenant, node, *part]):
            out[r[0]] = dict(zip(_CMP, r[1:]))
    return out


def _add_delta(deltas: dict, path: str, d_bytes: int, d_files: int, mtime_ns: int) -> None:
    p = parent_of(path)
    while p is not None:
        cur = deltas.get(p)
        if cur is None:
            deltas[p] = [d_bytes, d_files, mtime_ns]
        else:
            cur[0] += d_bytes
            cur[1] += d_files
            if mtime_ns > cur[2]:
                cur[2] = mtime_ns
        p = parent_of(p)


def _apply_dir_deltas(db: sqlite3.Connection, tenant: str, node: str, deltas: dict) -> None:
    if not deltas:
        return
    db.executemany(
        "INSERT INTO dirs(tenant, node, path, parent, name, bytes, files, newest_mtime_ns)"
        " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(tenant, node, path) DO UPDATE SET"
        " bytes = dirs.bytes + excluded.bytes, files = dirs.files + excluded.files,"
        " newest_mtime_ns = MAX(dirs.newest_mtime_ns, excluded.newest_mtime_ns)",
        [(tenant, node, d, parent_of(d) or "", name_of(d), v[0], v[1], v[2])
         for d, v in deltas.items()])
    for part in _chunks(list(deltas), _IN_CHUNK):
        db.execute("DELETE FROM dirs WHERE tenant = ? AND node = ? AND files <= 0 AND path IN ("
                   + ",".join("?" * len(part)) + ")", [tenant, node, *part])


def _group_stats(rows: list[tuple]) -> dict:
    """rows: (node, path, bytes, dev, ino, nlink, git_root, sensitive, never)."""
    members: dict[tuple, tuple] = {}
    for r in rows:
        node, path, _b, dev, ino = r[0], r[1], r[2], r[3], r[4]
        key = (node, dev, ino) if dev and ino else (node, "path", path)
        members.setdefault(key, r)  # hard links to one inode are ONE member
    size = int(rows[0][2]) if rows else 0
    count = len(members)
    parts: dict[tuple, list[tuple]] = {}
    for r in members.values():
        parts.setdefault((r[0], r[3]), []).append(r)
    actionable = 0
    for (_node, dev), ms in parts.items():
        if not dev or len(ms) < 2:
            continue
        eligible = sum(1 for m in ms if m[6] is None and m[5] == 1 and not m[7] and not m[8])
        actionable += max(0, min(eligible, len(ms) - 1)) * size
    return {"bytes": size, "count": count, "nodes": len({r[0] for r in members.values()}),
            "wasted_bytes": max(0, count - 1) * size, "actionable_bytes": actionable}


def _refresh_groups(db: sqlite3.Connection, tenant: str, shas: Iterable[str | None]) -> None:
    now = iso_now()
    for sha in {s for s in shas if s}:
        rows = db.execute(
            "SELECT node, path, bytes, dev, ino, nlink, git_root, sensitive, never FROM files"
            " WHERE sha256 = ? AND tenant = ?", (sha, tenant)).fetchall()
        st = _group_stats([tuple(r) for r in rows]) if rows else {"count": 0}
        if st["count"] < 2:
            db.execute("DELETE FROM dupe_groups WHERE tenant = ? AND sha256 = ?", (tenant, sha))
            continue
        db.execute(
            "INSERT INTO dupe_groups(tenant, sha256, bytes, count, nodes, wasted_bytes,"
            " actionable_bytes, updated_at) VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(tenant, sha256) DO UPDATE SET bytes=excluded.bytes,"
            " count=excluded.count, nodes=excluded.nodes, wasted_bytes=excluded.wasted_bytes,"
            " actionable_bytes=excluded.actionable_bytes, updated_at=excluded.updated_at",
            (tenant, sha, st["bytes"], st["count"], st["nodes"], st["wasted_bytes"],
             st["actionable_bytes"], now))


def apply_changes(db: sqlite3.Connection, tenant: str, node: str, *,
                  upserts: Iterable[dict] = (), deletes: Iterable[str] = (),
                  seq: int | None = None, push_id: str | None = None,
                  tombstone_seq: int | None = None) -> dict:
    """Write upserts/deletes for (tenant, node), keeping files, dirs, tombstones and
    dupe_groups consistent, at most TXN_ROWS rows per transaction.

    An upsert that changes nothing (size, mtime, hashes, inode, flags) is NOT written
    -- only its push_id is stamped when a resync is tracking what it saw. A changed
    row takes the row's own ``seq`` (a pushed row) or ``seq`` / a fresh node-local
    seq (a local scan). An incoming row without hashes keeps the stored hashes when
    size and mtime are unchanged."""
    out = {"new": 0, "changed": 0, "unchanged": 0, "deleted": 0}
    ups = list(upserts)
    now = iso_now()
    for chunk in _chunks(ups, TXN_ROWS):
        with db:
            prior = _prior(db, tenant, node, [u["path"] for u in chunk])
            rows, stamp, deltas, shas = [], [], {}, set()
            row_seq = seq
            for u in chunk:
                p = prior.get(u["path"])
                same_content = p is not None and (p["bytes"], p["mtime_ns"]) == (
                    u["bytes"], u["mtime_ns"])
                for k in ("partial_hash", "sha256", "dev", "ino", "nlink"):
                    if u.get(k) is None and same_content:
                        u[k] = p[k]
                if p is not None and all(p[k] == u.get(k) for k in _CMP):
                    out["unchanged"] += 1
                    if push_id:
                        stamp.append(u["path"])
                    continue
                if u.get("seq") is None:
                    if row_seq is None:
                        row_seq = _next_seq(db)
                    u["seq"] = row_seq
                if p is None:
                    out["new"] += 1
                    _add_delta(deltas, u["path"], u["bytes"], 1, u["mtime_ns"])
                else:
                    out["changed"] += 1
                    _add_delta(deltas, u["path"], u["bytes"] - p["bytes"], 0, u["mtime_ns"])
                    shas.add(p["sha256"])
                shas.add(u.get("sha256"))
                rows.append((tenant, node, *(u.get(c) for c in _COLS), push_id))
            db.executemany(_UPSERT, rows)
            for part in _chunks(stamp, _IN_CHUNK):
                db.execute("UPDATE files SET push_id = ? WHERE tenant = ? AND node = ?"
                           " AND path IN (" + ",".join("?" * len(part)) + ")",
                           [push_id, tenant, node, *part])
            _apply_dir_deltas(db, tenant, node, deltas)
            _refresh_groups(db, tenant, shas)
    dels = list(dict.fromkeys(deletes))
    for chunk in _chunks(dels, TXN_ROWS):
        with db:
            got = []
            for part in _chunks(chunk, _IN_CHUNK):
                got += db.execute(
                    "SELECT path, bytes, sha256 FROM files WHERE tenant = ? AND node = ?"
                    " AND path IN (" + ",".join("?" * len(part)) + ")",
                    [tenant, node, *part]).fetchall()
            if not got:
                continue
            ts = tombstone_seq if tombstone_seq is not None else (seq or _next_seq(db))
            deltas, shas = {}, set()
            for path, b, sha in got:
                _add_delta(deltas, path, -int(b), -1, 0)
                shas.add(sha)
            for part in _chunks([g[0] for g in got], _IN_CHUNK):
                db.execute("DELETE FROM files WHERE tenant = ? AND node = ? AND path IN ("
                           + ",".join("?" * len(part)) + ")", [tenant, node, *part])
            db.executemany(
                "INSERT INTO files_deleted(tenant, node, path, sha256, bytes, deleted_at, seq)"
                " VALUES (?,?,?,?,?,?,?)",
                [(tenant, node, g[0], g[2], int(g[1]), now, ts) for g in got])
            _apply_dir_deltas(db, tenant, node, deltas)
            _refresh_groups(db, tenant, shas)
            out["deleted"] += len(got)
    return out


# ---------------------------------------------------------------------------
# walk + local scan
# ---------------------------------------------------------------------------

WalkItem = tuple  # (path, bytes, mtime_ns, dev, ino, nlink, git_root)


def _walk(root: str, exclude: set[str], deadline: float,
          skip_dir: Callable[[str], bool] | None = None) -> Iterator[WalkItem | None]:
    """Yield (path, bytes, mtime_ns, dev, ino, nlink, git_root) per regular file; None
    once per unreadable entry. Symlinks and reparse points (junctions) are never
    followed nor indexed. Raises TimeoutError at the deadline."""
    stack: list[tuple[str, str | None]] = [(root, None)]
    while stack:
        if time.monotonic() >= deadline:
            raise TimeoutError
        d, git_root = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            yield None
            continue
        if any(e.name == ".git" for e in entries):
            git_root = norm_path(d)
        for e in entries:
            try:
                if e.name.lower() in exclude:
                    continue
                st = e.stat(follow_symlinks=False)
                if e.is_symlink() or getattr(st, "st_file_attributes", 0) & _REPARSE:
                    continue
                if stat_mod.S_ISDIR(st.st_mode):
                    if skip_dir is not None and skip_dir(norm_path(e.path)):
                        continue
                    stack.append((e.path, git_root))
                elif stat_mod.S_ISREG(st.st_mode):
                    # Windows DirEntry.stat() leaves dev/ino/nlink 0: filled at hash time.
                    yield (norm_path(e.path), int(st.st_size), int(st.st_mtime_ns),
                           _nz(st.st_dev), _nz(st.st_ino), _nz(st.st_nlink), git_root)
            except OSError:
                yield None


def _new_stats(node: str, tenant: str) -> dict:
    return {"node": node, "tenant": tenant, "roots": [], "files_seen": 0, "new": 0,
            "changed": 0, "unchanged": 0, "removed": 0, "errors": 0, "truncated": False,
            "partial_hashed": 0, "full_hashed": 0, "bytes_read": 0, "hash_truncated": False,
            "bytes_remaining": 0}


def _row_from_walk(item: WalkItem, scanned_at: str, g: _guards.Guards) -> dict:
    path, size, mtime_ns, dev, ino, nlink, git_root = item
    return {"path": path, "name": name_of(path), "parent": parent_of(path) or "",
            "bytes": size, "mtime_ns": mtime_ns, "ext": ext_of(path), "mime": mime_of(path),
            "partial_hash": None, "sha256": None, "dev": dev, "ino": ino, "nlink": nlink,
            "git_root": git_root, "sensitive": 1 if _guards.is_sensitive(path) else 0,
            "never": 1 if g.is_never(path) else 0, "seq": None, "scanned_at": scanned_at}


def index_root(db: sqlite3.Connection, root: str | os.PathLike, *, node: str,
               tenant: str = PLATFORM_TENANT, time_budget_s: float = 3600.0,
               exclude_dirs: Iterable[str] | None = None, guards: _guards.Guards | None = None,
               skip_never_dirs: bool = False, stats: dict | None = None,
               progress: Callable[[dict], None] | None = None) -> dict:
    """Walk one root into the index. Only changed rows are written; after a COMPLETED
    walk, rows under the root that were not seen become tombstones."""
    rootn = norm_root(root)
    if not os.path.isdir(rootn):
        raise NotADirectoryError(f"root is not a directory: {root}")
    g = guards or _guards.Guards()
    exclude = {n.lower() for n in (DEFAULT_EXCLUDE_DIRS if exclude_dirs is None
                                   else exclude_dirs)}
    st = stats if stats is not None else _new_stats(node, tenant)
    scanned_at = iso_now()
    deadline = time.monotonic() + float(time_budget_s)
    db.execute("CREATE TEMP TABLE IF NOT EXISTS seen(path TEXT PRIMARY KEY)")
    db.execute("DELETE FROM temp.seen")
    batch: list[dict] = []
    files = total = errors = 0
    truncated = False
    last_tick = time.monotonic()

    def flush() -> None:
        with db:
            db.executemany("INSERT OR IGNORE INTO temp.seen(path) VALUES (?)",
                           [(b["path"],) for b in batch])
        res = apply_changes(db, tenant, node, upserts=batch)
        for k in ("new", "changed", "unchanged"):
            st[k] += res[k]

    try:
        for item in _walk(rootn, exclude, deadline,
                          skip_dir=g.is_never_dir if skip_never_dirs else None):
            if item is None:
                errors += 1
                continue
            batch.append(_row_from_walk(item, scanned_at, g))
            files += 1
            total += item[1]
            if len(batch) >= TXN_ROWS:
                flush()
                batch = []
            if progress is not None and time.monotonic() - last_tick >= 5.0:
                last_tick = time.monotonic()
                progress({"phase": "walk", "root": rootn, "files": files, "bytes": total})
    except TimeoutError:
        truncated = True
    if batch:
        flush()
    removed = 0
    if not truncated:
        lo, hi = _under(_prefix(rootn))
        after = ""
        while True:
            gone = [r[0] for r in db.execute(
                "SELECT f.path FROM files f WHERE f.tenant = ? AND f.node = ? AND f.path >= ?"
                " AND f.path < ? AND f.path > ? AND NOT EXISTS"
                " (SELECT 1 FROM temp.seen s WHERE s.path = f.path) ORDER BY f.path LIMIT ?",
                (tenant, node, lo, hi, after, TXN_ROWS))]
            if not gone:
                break
            removed += apply_changes(db, tenant, node, deletes=gone)["deleted"]
            after = gone[-1]
    with db:
        db.execute(
            "INSERT INTO roots(tenant, node, root, files, bytes, scanned_at, truncated, errors)"
            " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(tenant, node, root) DO UPDATE SET"
            " files=excluded.files, bytes=excluded.bytes, scanned_at=excluded.scanned_at,"
            " truncated=excluded.truncated, errors=excluded.errors",
            (tenant, node, rootn, files, total, scanned_at, 1 if truncated else 0, errors))
        db.execute("DELETE FROM temp.seen")
    st["roots"].append({"root": rootn, "files": files, "bytes": total, "errors": errors,
                        "truncated": truncated, "scanned_at": scanned_at})
    st["files_seen"] += files
    st["removed"] += removed
    st["errors"] += errors
    st["truncated"] = st["truncated"] or truncated
    return st


# ---------------------------------------------------------------------------
# hashing
# ---------------------------------------------------------------------------

def _hash_one(args: tuple) -> tuple | None:
    path, size, mtime_ns, full, partial_bytes = args
    try:
        s1 = os.stat(path)
        if s1.st_size != size or s1.st_mtime_ns != mtime_ns:
            return None
        if full:
            p, f, read = None, full_sha256(path), size
        else:
            p, f = partial_hash(path, size, partial_bytes)
            read = min(size, partial_bytes * 2)
        s2 = os.stat(path)
        if s2.st_size != size or s2.st_mtime_ns != mtime_ns:
            return None  # changed mid-read: the row no longer describes these bytes
    except OSError:
        return ("error",)
    return (path, size, mtime_ns, p, f, _nz(s2.st_dev), _nz(s2.st_ino), _nz(s2.st_nlink),
            read)


def hash_node(db: sqlite3.Connection, node: str, *, tenant: str = PLATFORM_TENANT,
              mode: str = "auto", min_bytes: int = DEFAULT_MIN_HASH_BYTES,
              partial_bytes: int = PARTIAL_BYTES, time_budget_s: float = 3600.0,
              budget_bytes: int = DEFAULT_HASH_BUDGET_BYTES, workers: int = HASH_WORKERS,
              stats: dict | None = None,
              progress: Callable[[dict], None] | None = None) -> dict:
    """Fill hashes for rows that lack them (auto: size bucket -> partial -> sha256;
    full: sha256 everything >= min_bytes; none: nothing). Bounded by time AND bytes
    read; reports hash_truncated and bytes_remaining. Rows that already carry a hash
    are never re-read."""
    if mode not in HASH_MODES:
        raise ValueError(f"hash mode must be one of {HASH_MODES}, not {mode!r}")
    st = stats if stats is not None else _new_stats(node, tenant)
    if mode == "none":
        return st
    deadline = time.monotonic() + float(time_budget_s)
    tick = [time.monotonic()]

    def stage(where: str, args: list, full: bool) -> None:
        after = ""
        with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
            while not st["hash_truncated"]:
                page = db.execute(
                    "SELECT path, bytes, mtime_ns FROM files WHERE tenant = ? AND node = ?"
                    " AND path > ? AND " + where + " ORDER BY path LIMIT ?",
                    [tenant, node, after, *args, TXN_ROWS]).fetchall()
                if not page:
                    return
                after = page[-1][0]
                todo = []
                for path, size, mtime_ns in page:
                    if _no_hash(path):
                        continue
                    cost = size if full else min(size, partial_bytes * 2)
                    if (time.monotonic() >= deadline
                            or st["bytes_read"] + cost > budget_bytes):
                        st["hash_truncated"] = True
                        break
                    st["bytes_read"] += cost  # reserved; released below on a miss
                    todo.append((path, size, mtime_ns, full, partial_bytes))
                got, shas = [], set()
                for a, r in zip(todo, pool.map(_hash_one, todo)):
                    if r is None or r[0] == "error":
                        st["bytes_read"] -= a[1] if full else min(a[1], partial_bytes * 2)
                        if r is not None:
                            st["errors"] += 1
                        continue
                    got.append(r)
                    shas.add(r[4])
                    if full:
                        st["full_hashed"] += 1
                    else:
                        st["partial_hashed"] += 1
                        if r[4]:
                            st["full_hashed"] += 1
                if got:
                    with db:
                        s = _next_seq(db)
                        db.executemany(
                            "UPDATE files SET partial_hash = COALESCE(?, partial_hash),"
                            " sha256 = COALESCE(?, sha256), dev = COALESCE(?, dev),"
                            " ino = COALESCE(?, ino), nlink = COALESCE(?, nlink), seq = ?"
                            " WHERE tenant = ? AND node = ? AND path = ? AND bytes = ?"
                            " AND mtime_ns = ?",
                            [(r[3], r[4], r[5], r[6], r[7], s, tenant, node, r[0], r[1], r[2])
                             for r in got])
                        _refresh_groups(db, tenant, shas)
                if progress is not None and time.monotonic() - tick[0] >= 5.0:
                    tick[0] = time.monotonic()
                    progress({"phase": "hash", "hashed": st["partial_hashed"]
                              + st["full_hashed"], "bytes_read": st["bytes_read"]})

    size_bucket = ("bytes IN (SELECT bytes FROM files WHERE tenant = ? AND node = ?"
                   " AND bytes >= ? GROUP BY bytes HAVING COUNT(*) > 1)")
    partial_collide = ("(bytes, partial_hash) IN (SELECT bytes, partial_hash FROM files"
                       " WHERE tenant = ? AND node = ? AND partial_hash IS NOT NULL"
                       " GROUP BY bytes, partial_hash HAVING COUNT(*) > 1)")
    if mode == "full":
        where = "sha256 IS NULL AND bytes >= ?"
        stage(where, [min_bytes], True)
        remaining = db.execute(
            "SELECT COALESCE(SUM(bytes), 0) FROM files WHERE tenant = ? AND node = ? AND "
            + where, (tenant, node, min_bytes)).fetchone()[0]
    else:
        w1 = "partial_hash IS NULL AND bytes >= ? AND " + size_bucket
        a1 = [min_bytes, tenant, node, min_bytes]
        stage(w1, a1, False)
        w2 = "sha256 IS NULL AND partial_hash IS NOT NULL AND " + partial_collide
        a2 = [tenant, node]
        stage(w2, a2, True)
        remaining = sum(db.execute(
            "SELECT COALESCE(SUM(bytes), 0) FROM files WHERE tenant = ? AND node = ? AND " + w,
            [tenant, node, *a]).fetchone()[0] for w, a in ((w1, a1), (w2, a2)))
    st["bytes_remaining"] = int(remaining)
    with db:
        for r in st["roots"]:
            _update_root_hash_pct(db, tenant, node, r["root"])
    return st


def _update_root_hash_pct(db: sqlite3.Connection, tenant: str, node: str, root: str) -> None:
    lo, hi = _under(_prefix(root))
    n, h = db.execute(
        "SELECT COUNT(*), COUNT(sha256) FROM files WHERE tenant = ? AND node = ? AND path >= ?"
        " AND path < ?", (tenant, node, lo, hi)).fetchone()
    db.execute("UPDATE roots SET hashed_pct = ? WHERE tenant = ? AND node = ? AND root = ?",
               (round(100.0 * h / n, 1) if n else None, tenant, node, root))


# ---------------------------------------------------------------------------
# cross-node hash orders (A3): a size collision ACROSS nodes is invisible to one
# node's own `hash_node` (its size buckets are per node), so Genesis -- the only
# place that sees every node -- names the paths each node must hash, and the node
# hashes exactly those and pushes. `dupes()` without a node then covers them.
# ---------------------------------------------------------------------------

HASH_ORDER_MAX = 10_000   # paths per hash order (per node, per /requests read)


def hash_orders(db: sqlite3.Connection, node: str, *, tenant: str = PLATFORM_TENANT,
                min_bytes: int = DEFAULT_MIN_HASH_BYTES,
                limit: int = HASH_ORDER_MAX) -> list[str]:
    """Paths on `node` that carry no sha256 and whose size equals a file's on ANOTHER
    node of the same tenant -- the candidates only a cross-node view can see. Largest
    first (most bytes a confirmed duplicate could reclaim), capped at `limit` (at most
    HASH_ORDER_MAX). `never` rows are excluded: they are never hashed."""
    limit = max(0, min(int(limit), HASH_ORDER_MAX))
    if not limit:
        return []
    return [r[0] for r in db.execute(
        "SELECT path FROM files WHERE tenant = ? AND node = ? AND sha256 IS NULL"
        " AND never = 0 AND bytes >= ? AND bytes IN (SELECT bytes FROM files"
        " WHERE tenant = ? AND node <> ? AND bytes >= ?)"
        " ORDER BY bytes DESC, path LIMIT ?",
        (tenant, node, int(min_bytes), tenant, node, int(min_bytes), limit))]


def hash_paths(db: sqlite3.Connection, node: str, paths: Iterable[str], *,
               tenant: str = PLATFORM_TENANT, time_budget_s: float = 3600.0,
               budget_bytes: int = DEFAULT_HASH_BUDGET_BYTES,
               workers: int = HASH_WORKERS) -> dict:
    """Full-sha256 exactly `paths` (a Genesis hash order) where the local index holds
    them unhashed. A path not indexed here, already hashed, in the no-hash set, or
    changed since it was indexed is counted, never hashed blind. Each hash bumps the
    row's seq so the next `push_files` delta carries it. Bounded by time AND bytes: the
    deadline ends the pass, but a file that does not fit the remaining byte budget is
    only passed over (truncated=True) -- the rows come back in index order, so stopping
    at one oversized file would starve every path after it on every pass."""
    want = list(dict.fromkeys(norm_path(p) for p in paths if p))[:HASH_ORDER_MAX]
    st = {"requested": len(want), "hashed": 0, "already": 0, "missing": 0, "skipped": 0,
          "errors": 0, "bytes_read": 0, "truncated": False}
    rows: list[tuple] = []
    for part in _chunks(want, _IN_CHUNK):
        rows += db.execute(
            "SELECT path, bytes, mtime_ns, sha256 FROM files WHERE tenant = ? AND node = ?"
            " AND path IN (" + ",".join("?" * len(part)) + ")",
            [tenant, node, *part]).fetchall()
    st["missing"] = len(want) - len(rows)
    deadline = time.monotonic() + float(time_budget_s)
    todo = []
    for path, size, mtime_ns, sha in rows:
        if sha:
            st["already"] += 1
            continue
        if _no_hash(path):
            st["skipped"] += 1
            continue
        if time.monotonic() >= deadline:
            st["truncated"] = True
            break
        if st["bytes_read"] + size > budget_bytes:
            st["truncated"] = True
            continue
        st["bytes_read"] += size
        todo.append((path, size, mtime_ns, True, PARTIAL_BYTES))
    got, shas = [], set()
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        for a, r in zip(todo, pool.map(_hash_one, todo)):
            if r is None or r[0] == "error":
                st["bytes_read"] -= a[1]
                st["errors" if r is not None else "skipped"] += 1
                continue
            got.append(r)
            shas.add(r[4])
    if got:
        with db:
            s = _next_seq(db)
            db.executemany(
                "UPDATE files SET sha256 = ?, dev = COALESCE(?, dev), ino = COALESCE(?, ino),"
                " nlink = COALESCE(?, nlink), seq = ? WHERE tenant = ? AND node = ?"
                " AND path = ? AND bytes = ? AND mtime_ns = ?",
                [(r[4], r[5], r[6], r[7], s, tenant, node, r[0], r[1], r[2]) for r in got])
            _refresh_groups(db, tenant, shas)
            for r in local_roots(db, node, tenant):
                _update_root_hash_pct(db, tenant, node, r["root"])
        st["hashed"] = len(got)
    return st


def scan_files(db: sqlite3.Connection, roots: Iterable[str | os.PathLike], *, node: str,
               tenant: str = PLATFORM_TENANT, hash_mode: str = "auto",
               time_budget_s: float = 3600.0, min_hash_bytes: int = DEFAULT_MIN_HASH_BYTES,
               hash_budget_bytes: int = DEFAULT_HASH_BUDGET_BYTES,
               exclude_dirs: Iterable[str] | None = None, guards: _guards.Guards | None = None,
               skip_never_dirs: bool = False,
               progress: Callable[[dict], None] | None = None) -> dict:
    """Index every root, then hash per `hash_mode`. The whole call shares one budget."""
    if hash_mode not in HASH_MODES:
        raise ValueError(f"hash mode must be one of {HASH_MODES}, not {hash_mode!r}")
    t0 = time.monotonic()
    st = _new_stats(node, tenant)
    g = guards or _guards.Guards()
    for r in roots:
        left = max(0.0, float(time_budget_s) - (time.monotonic() - t0))
        index_root(db, r, node=node, tenant=tenant, time_budget_s=left,
                   exclude_dirs=exclude_dirs, guards=g, skip_never_dirs=skip_never_dirs,
                   stats=st, progress=progress)
    left = max(0.0, float(time_budget_s) - (time.monotonic() - t0))
    hash_node(db, node, tenant=tenant, mode=hash_mode, min_bytes=min_hash_bytes,
              time_budget_s=left, budget_bytes=hash_budget_bytes, stats=st, progress=progress)
    st["elapsed_s"] = round(time.monotonic() - t0, 3)
    return st


# ---------------------------------------------------------------------------
# push (node side): delta parts
# ---------------------------------------------------------------------------

def _wire_row(r: Any) -> dict:
    (path, b, m, ext, mime, ph, sha, dev, ino, nlink, git_root, sens, never, seq,
     scanned_at) = tuple(r)[:15]
    return {"path": path, "bytes": b, "mtime": m / 1e9, "mtime_ns": m, "ext": ext,
            "mime": mime, "partial_hash": ph, "partial_algo": PARTIAL_ALGO if ph else None,
            "sha256": sha, "dev": dev, "ino": ino, "nlink": nlink, "git_root": git_root,
            "sensitive": sens, "never": never, "seq": seq, "scanned_at": scanned_at}


_WIRE_SELECT = ("SELECT path, bytes, mtime_ns, ext, mime, partial_hash, sha256, dev, ino,"
                " nlink, git_root, sensitive, never, seq, scanned_at FROM files")


def push_parts(db: sqlite3.Connection, *, node: str, root: str, since_seq: int,
               scan_id: str, tenant: str = PLATFORM_TENANT, truncated: bool = False,
               volumes: list | None = None, scanned_at: str | None = None,
               max_bytes: int = 7 * 1024 * 1024,
               max_rows: int = MAX_PART_ROWS) -> Iterator[dict]:
    """The push body parts for one root: `since_seq == 0` is a FULL resync (every row
    under the root), otherwise a delta (rows and tombstones with seq > since_seq).
    Two passes: boundaries first (so every part knows `parts`), then each part is read
    back by keyset -- never the whole root in memory."""
    lo, hi = _under(_prefix(root))
    to_seq = current_seq(db)
    where = "tenant = ? AND node = ? AND path >= ? AND path < ?"
    args: list[Any] = [tenant, node, lo, hi]
    if since_seq:
        where += " AND seq > ?"
        args.append(since_seq)
    bounds: list[tuple[str, str]] = []  # (after, last) per upsert part
    after, start, size, n = "", "", 2, 0
    for path, ext, mime, ph, sha, gr in db.execute(
            "SELECT path, ext, mime, partial_hash, sha256, git_root FROM files WHERE "
            + where + " ORDER BY path", args):
        est = 300 + 2 * len(path.encode("utf-8")) + len(ext or "") + len(mime or "") + len(
            (gr or "").encode("utf-8")) + (70 if sha else 0) + (100 if ph else 0)
        if n and (size + est > max_bytes or n >= max_rows):
            bounds.append((start, after))
            start, size, n = after, 2, 0
        size += est
        n += 1
        after = path
    if n:
        bounds.append((start, after))
    deletes: list[str] = []
    if since_seq:
        deletes = [r[0] for r in db.execute(
            "SELECT DISTINCT path FROM files_deleted WHERE tenant = ? AND node = ? AND seq > ?"
            " AND path >= ? AND path < ? ORDER BY path", (tenant, node, since_seq, lo, hi))]
    del_parts = list(_chunks(deletes, MAX_SYNC_DELETES))
    parts = max(1, len(bounds) + len(del_parts))
    base = {"scan_id": scan_id, "root": root, "since_seq": int(since_seq), "to_seq": to_seq,
            "parts": parts, "truncated": bool(truncated), "scanned_at": scanned_at}
    i = 0
    for a, last in bounds:
        i += 1
        rows = db.execute(_WIRE_SELECT + " WHERE " + where + " AND path > ? AND path <= ?"
                          " ORDER BY path", [*args, a, last]).fetchall()
        yield {**base, "part": i, "upserts": [_wire_row(r) for r in rows], "deletes": [],
               "volumes": (volumes or []) if i == parts else []}
    for d in del_parts:
        i += 1
        yield {**base, "part": i, "upserts": [], "deletes": d,
               "volumes": (volumes or []) if i == parts else []}
    if i == 0:
        yield {**base, "part": 1, "upserts": [], "deletes": [], "volumes": volumes or []}


def mark_pushed(db: sqlite3.Connection, *, node: str, root: str, to_seq: int,
                tenant: str = PLATFORM_TENANT) -> None:
    with db:
        db.execute("UPDATE roots SET pushed_seq = ?, last_push_at = ? WHERE tenant = ?"
                   " AND node = ? AND root = ?", (int(to_seq), iso_now(), tenant, node, root))


def reset_pushed(db: sqlite3.Connection, *, node: str, root: str,
                 tenant: str = PLATFORM_TENANT) -> None:
    with db:
        db.execute("UPDATE roots SET pushed_seq = 0 WHERE tenant = ? AND node = ? AND root = ?",
                   (tenant, node, root))


def local_roots(db: sqlite3.Connection, node: str, tenant: str = PLATFORM_TENANT) -> list[dict]:
    return [dict(zip(("root", "pushed_seq", "truncated", "scanned_at"), r)) for r in db.execute(
        "SELECT root, pushed_seq, truncated, scanned_at FROM roots WHERE tenant = ? AND node = ?"
        " ORDER BY root", (tenant, node))]


# ---------------------------------------------------------------------------
# ingest (Genesis side)
# ---------------------------------------------------------------------------

class ResyncRequired(Exception):
    """The node's since_seq does not continue what this index holds (HTTP 409)."""

    def __init__(self, last_seq: int) -> None:
        super().__init__(f"seq gap: the fleet index holds this root up to seq {last_seq}")
        self.last_seq = last_seq


class BadPush(ValueError):
    """The push body is malformed (HTTP 422)."""


def _valid_hash(v: Any) -> str | None | bool:
    if v is None or v == "":
        return None
    if isinstance(v, str) and _HEX64.match(v.lower()):
        return v.lower()
    return False


def _opt_int(v: Any) -> int | None | bool:
    if v is None:
        return None
    if isinstance(v, bool):
        return False
    try:
        i = int(v)
    except (TypeError, ValueError, OverflowError):
        return False
    return i if 0 <= i < 2 ** 63 else False


def validate_row(r: Any, *, root: str, to_seq: int, g: _guards.Guards
                 ) -> tuple[dict | None, str | None]:
    """A pushed row, normalized -- or the reason it is refused. Pushed data is never
    trusted: bounded strings, non-negative ints, hashes that are 64 hex with the wire's
    partial algorithm, a path under the pushed root. `sensitive`/`never` are
    RECOMPUTED here (the node's flag can only add, never clear)."""
    if not isinstance(r, dict):
        return None, "row is not an object"
    path = r.get("path")
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_CHARS or "\x00" in path:
        return None, "bad path"
    path = _clean(path)
    if not path.startswith(_prefix(root)):
        return None, f"{path[:200]}: not under the pushed root {root}"
    b = _opt_int(r.get("bytes"))
    m = _opt_int(r.get("mtime_ns"))
    if m is None and r.get("mtime") is not None:
        try:
            mf = float(r["mtime"])
            m = int(mf * 1e9) if math.isfinite(mf) and 0 <= mf < _MAX_TS else False
        except (TypeError, ValueError):
            m = False
    if b is None or b is False or m is None or m is False:
        return None, f"{path[:200]}: bytes/mtime missing or out of range"
    ph, sh = _valid_hash(r.get("partial_hash")), _valid_hash(r.get("sha256"))
    if ph is False or sh is False:
        return None, f"{path[:200]}: hash is not 64 hex chars"
    if ph and r.get("partial_algo") != PARTIAL_ALGO:
        return None, f"{path[:200]}: partial_algo {r.get('partial_algo')!r} != {PARTIAL_ALGO}"
    dev, ino, nlink = _opt_int(r.get("dev")), _opt_int(r.get("ino")), _opt_int(r.get("nlink"))
    if dev is False or ino is False or nlink is False:
        return None, f"{path[:200]}: dev/ino/nlink out of range"
    seq = _opt_int(r.get("seq"))
    if seq is False or (seq is not None and seq > to_seq):
        return None, f"{path[:200]}: seq beyond the push's to_seq"
    gr = r.get("git_root")
    gr = _clean(gr) if isinstance(gr, str) and gr and len(gr) <= MAX_PATH_CHARS else None
    ext = r.get("ext")
    ext = ext_of(path) if not isinstance(ext, str) else ext.lower()[:MAX_EXT_CHARS]
    mime = r.get("mime")
    mime = mime[:MAX_MIME_CHARS] if isinstance(mime, str) and mime else None
    sa = r.get("scanned_at")
    sa = sa if isinstance(sa, str) and 0 < len(sa) <= 40 else iso_now()
    return {"path": path, "name": name_of(path), "parent": parent_of(path) or "",
            "bytes": b, "mtime_ns": m, "ext": ext, "mime": mime, "partial_hash": ph,
            "sha256": sh, "dev": dev or None, "ino": ino or None, "nlink": nlink or None,
            "git_root": gr,
            "sensitive": 1 if (_guards.is_sensitive(path) or r.get("sensitive")) else 0,
            "never": 1 if (g.is_never(path) or r.get("never")) else 0,
            "seq": seq if seq is not None else to_seq, "scanned_at": sa}, None


def validate_body(body: Any) -> dict:
    """The push envelope, normalized; raises BadPush. (Rows are validated one by one
    in ingest_push -- a bad row is rejected and counted, not fatal to its part.)"""
    if not isinstance(body, dict):
        raise BadPush("body must be an object")
    root = body.get("root")
    if not isinstance(root, str) or not root or len(root) > MAX_PATH_CHARS or "\x00" in root:
        raise BadPush("root must be a path")
    scan_id = body.get("scan_id")
    if not isinstance(scan_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", scan_id):
        raise BadPush("scan_id must be 1-64 of [A-Za-z0-9_.:-]")
    out: dict[str, Any] = {"root": _clean(root), "scan_id": scan_id,
                           "truncated": bool(body.get("truncated"))}
    for k in ("since_seq", "to_seq", "part", "parts"):
        v = _opt_int(body.get(k))
        if v is None or v is False:
            raise BadPush(f"{k} must be a non-negative integer")
        out[k] = v
    if out["to_seq"] < out["since_seq"]:
        raise BadPush("to_seq < since_seq")
    if not 1 <= out["part"] <= out["parts"] <= 100_000:
        raise BadPush("need 1 <= part <= parts <= 100000")
    ups, dels = body.get("upserts") or [], body.get("deletes") or []
    if not isinstance(ups, list) or not isinstance(dels, list):
        raise BadPush("upserts and deletes must be lists")
    out["upserts"], out["deletes"] = ups, dels
    vols = body.get("volumes") or []
    out["volumes"] = [v for v in vols if isinstance(v, dict)][:64] if isinstance(vols, list) \
        else []
    sa = body.get("scanned_at")
    out["scanned_at"] = sa if isinstance(sa, str) and len(sa) <= 40 else None
    return out


def ingest_push(db: sqlite3.Connection, tenant: str, node: str, body: Any, *,
                guards: _guards.Guards | None = None) -> dict:
    """Apply one pushed part for (tenant, node) -- both decided by the CALLER (the
    router derives them from the authenticated identity), never by the body.

    Raises BadPush (422) or ResyncRequired (409). A full resync (since_seq 0) prunes
    the root only once parts 1..N of its scan_id have all arrived and the node's walk
    was not truncated."""
    b = validate_body(body)
    g = guards or _guards.Guards()
    root = b["root"]
    state = db.execute(
        "SELECT last_seq, scan_id, parts, parts_seen FROM file_push_state WHERE tenant = ?"
        " AND node = ? AND root = ?", (tenant, node, root)).fetchone()
    last = int(state[0]) if state else 0
    if b["since_seq"] and b["since_seq"] != last:
        raise ResyncRequired(last)
    seen = set(json.loads(state[3])) if state and state[1] == b["scan_id"] else set()
    good, rejected = [], []
    for r in b["upserts"]:
        row, err = validate_row(r, root=root, to_seq=b["to_seq"], g=g)
        if err:
            rejected.append(err)
        else:
            good.append(row)
    dels = []
    for d in b["deletes"]:
        if isinstance(d, str) and d and len(d) <= MAX_PATH_CHARS and "\x00" not in d \
                and _clean(d).startswith(_prefix(root)):
            dels.append(_clean(d))
        else:
            rejected.append(f"delete {str(d)[:80]!r}: not a path under {root}")
    resync = b["since_seq"] == 0
    res = apply_changes(db, tenant, node, upserts=good, deletes=dels,
                        push_id=b["scan_id"] if resync else None, tombstone_seq=b["to_seq"])
    seen.add(b["part"])
    missing = sorted(set(range(1, b["parts"] + 1)) - seen)
    pruned = 0
    with db:
        db.execute(
            "INSERT INTO file_push_state(tenant, node, root, last_seq, scan_id, parts,"
            " parts_seen, updated_at) VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(tenant, node, root) DO UPDATE SET scan_id=excluded.scan_id,"
            " parts=excluded.parts, parts_seen=excluded.parts_seen,"
            " updated_at=excluded.updated_at",
            (tenant, node, root, last, b["scan_id"], b["parts"], json.dumps(sorted(seen)),
             iso_now()))
    if not missing:
        if resync and not b["truncated"]:
            lo, hi = _under(_prefix(root))
            while True:
                stale = [r[0] for r in db.execute(
                    "SELECT path FROM files WHERE tenant = ? AND node = ? AND path >= ?"
                    " AND path < ? AND (push_id IS NULL OR push_id != ?) LIMIT ?",
                    (tenant, node, lo, hi, b["scan_id"], TXN_ROWS))]
                if not stale:
                    break
                pruned += apply_changes(db, tenant, node, deletes=stale,
                                        tombstone_seq=b["to_seq"])["deleted"]
        _complete_push(db, tenant, node, b, pruned)
    return {"written": res["new"] + res["changed"], "unchanged": res["unchanged"],
            "deleted": res["deleted"], "rejected": len(rejected), "errors": rejected[:20],
            "pruned": pruned, "complete": not missing, "missing_parts": missing[:50],
            "last_seq": b["to_seq"] if not missing else last}


def _complete_push(db: sqlite3.Connection, tenant: str, node: str, b: dict,
                   pruned: int) -> None:
    root = b["root"]
    now = iso_now()
    lo, hi = _under(_prefix(root))
    n, total, hashed = db.execute(
        "SELECT COUNT(*), COALESCE(SUM(bytes), 0), COUNT(sha256) FROM files WHERE tenant = ?"
        " AND node = ? AND path >= ? AND path < ?", (tenant, node, lo, hi)).fetchone()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=TOMBSTONE_DAYS)).isoformat(
        timespec="seconds")
    with db:
        db.execute("UPDATE file_push_state SET last_seq = ?, updated_at = ? WHERE tenant = ?"
                   " AND node = ? AND root = ?", (b["to_seq"], now, tenant, node, root))
        db.execute(
            "INSERT INTO roots(tenant, node, root, files, bytes, scanned_at, hashed_pct,"
            " truncated, last_push_at) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(tenant, node, root) DO UPDATE SET files=excluded.files,"
            " bytes=excluded.bytes, scanned_at=COALESCE(excluded.scanned_at, roots.scanned_at),"
            " hashed_pct=excluded.hashed_pct, truncated=excluded.truncated,"
            " last_push_at=excluded.last_push_at",
            (tenant, node, root, n, total, b["scanned_at"] or now,
             round(100.0 * hashed / n, 1) if n else None, 1 if b["truncated"] else 0, now))
        if b["volumes"]:
            db.execute("INSERT INTO node_volumes(tenant, node, volumes, updated_at) VALUES"
                       " (?,?,?,?) ON CONFLICT(tenant, node) DO UPDATE SET"
                       " volumes=excluded.volumes, updated_at=excluded.updated_at",
                       (tenant, node, json.dumps(b["volumes"])[:65536], now))
        db.execute("DELETE FROM files_deleted WHERE deleted_at < ?", (cutoff,))
    if pruned > BIG_PRUNE:
        maintain(db)


def maintain(db: sqlite3.Connection) -> None:
    """After a large prune: merge FTS segments and give pages back to the filesystem."""
    if fts_tokenizer(db):
        with db:
            db.execute("INSERT INTO files_fts(files_fts) VALUES ('optimize')")
    db.execute("PRAGMA incremental_vacuum")


# ---------------------------------------------------------------------------
# reads: search, dupes, tree, changes, status
# ---------------------------------------------------------------------------

def _b64(obj: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _unb64(cursor: str) -> Any:
    try:
        return json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except Exception as exc:  # noqa: BLE001 -- any undecodable cursor is the caller's bug
        raise ValueError("bad cursor") from exc


def _pair_cursor(cursor: str) -> tuple[Any, Any]:
    c = _unb64(cursor)
    if not (isinstance(c, list) and len(c) == 2):
        raise ValueError("bad cursor")
    return c[0], c[1]


def _node_clause(nodes: str | Iterable[str] | None, col: str = "f.node") -> tuple[str, list]:
    if nodes is None:
        return "", []
    if isinstance(nodes, str):
        return f" AND {col} = ?", [nodes]
    ns = sorted(set(nodes))
    if not ns:
        return " AND 0", []
    return f" AND {col} IN (" + ",".join("?" * len(ns)) + ")", ns


def _words(q: str | None) -> list[str]:
    return re.findall(r"\w+", q or "", re.UNICODE)[:16]


def _like(w: str) -> str:
    return "%" + w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _item(r: tuple, redact: bool) -> dict:
    node, path, b, m, ext, mime, sha, sens = r[:8]
    if redact and sens:
        return {"node": node, "path": _guards.redact(path), "bytes": b, "mtime": m / 1e9,
                "ext": None, "mime": None, "sha256": None, "redacted": True}
    return {"node": node, "path": path, "bytes": b, "mtime": m / 1e9, "ext": ext,
            "mime": mime, "sha256": sha}


_SEL = "f.node, f.path, f.bytes, f.mtime_ns, f.ext, f.mime, f.sha256, f.sensitive"


def search(db: sqlite3.Connection, q: str = "", *, tenant: str = PLATFORM_TENANT,
           nodes: str | Iterable[str] | None = None, ext: str | None = None,
           min_bytes: int | None = None, newer_days: float | None = None, limit: int = 100,
           cursor: str | None = None, redact: bool = False) -> dict:
    """Files whose BASENAME contains every word of `q` (trigram substring match),
    filtered. With `q`, pages follow the FTS rowid (no sort) and at most
    SEARCH_SCAN_CAP matches are scanned per call (`partial: true` past it); without
    `q`, a keyset on (node, path). A 1-2 character query needs `ext` or one `node`."""
    limit = max(1, min(int(limit), 1000))
    words = _words(q)
    if words and len("".join(words)) < 3 and not (ext or isinstance(nodes, str)):
        raise ValueError("a 1-2 character query needs ext or node to narrow it")
    where, args = " WHERE f.tenant = ?", [tenant]
    nc, na = _node_clause(nodes)
    where += nc
    args += na
    if ext:
        where += " AND f.ext = ?"
        args.append(ext.lower().lstrip("."))
    if min_bytes:
        where += " AND f.bytes >= ?"
        args.append(max(0, min(int(min_bytes), 2 ** 63 - 1)))
    if newer_days:
        nd = float(newer_days)
        if not math.isfinite(nd) or nd < 0:
            raise ValueError("newer_days must be a finite, non-negative number")
        where += " AND f.mtime_ns >= ?"
        args.append(max(0, int((time.time() - min(nd, 1e6) * 86400) * 1e9)))
    if redact and words:
        where += " AND f.sensitive = 0"  # a name search must not confirm a key file exists
    tok = fts_tokenizer(db)
    fts_words = ([w for w in words if len(w) >= 3] if tok == "trigram" else words) if tok else []
    for w in words:
        if w not in fts_words:
            where += " AND f.name LIKE ? ESCAPE '\\'"
            args.append(_like(w))
    if fts_words:
        match = " AND ".join('"' + w + '"' + ("" if tok == "trigram" else "*")
                             for w in fts_words)
        after = int(_unb64(cursor)) if cursor else 0
        ids = [r[0] for r in db.execute(
            "SELECT rowid FROM files_fts WHERE files_fts MATCH ? AND rowid > ? ORDER BY rowid"
            " LIMIT ?", (match, after, SEARCH_SCAN_CAP))]
        items: list[dict] = []
        last_scanned, more = after, False
        for part in _chunks(ids, 500):
            rows = db.execute("SELECT f.rowid, " + _SEL + " FROM files f" + where
                              + " AND f.rowid IN (" + ",".join("?" * len(part)) + ")"
                              " ORDER BY f.rowid", [*args, *part]).fetchall()
            for r in rows:
                if len(items) >= limit:
                    more = True
                    break
                items.append(_item(tuple(r)[1:], redact))
                last_scanned = r[0]
            if more:
                break
            last_scanned = part[-1]
        partial = not more and len(ids) >= SEARCH_SCAN_CAP
        return {"items": items, "next_cursor": _b64(last_scanned) if (more or partial) else None,
                "partial": partial}
    if cursor:
        cn, cp = _pair_cursor(cursor)
        where += " AND (f.node > ? OR (f.node = ? AND f.path > ?))"
        args += [str(cn), str(cn), str(cp)]
    rows = db.execute("SELECT " + _SEL + " FROM files f" + where
                      + " ORDER BY f.node, f.path LIMIT ?", [*args, limit + 1]).fetchall()
    items = [_item(tuple(r), redact) for r in rows[:limit]]
    nxt = _b64([rows[limit - 1][0], rows[limit - 1][1]]) if len(rows) > limit else None
    return {"items": items, "next_cursor": nxt, "partial": False}


_MEMBER = "node, path, bytes, dev, ino, nlink, git_root, sensitive, never"


def _group_paths(db: sqlite3.Connection, tenant: str, sha: str, nodes: Any, redact: bool,
                 limit: int, after: tuple[str, str] | None = None
                 ) -> tuple[list[dict], bool, tuple[str, str] | None]:
    nc, na = _node_clause(nodes, "node")
    extra, ea = "", []
    if after:
        extra, ea = " AND (node > ? OR (node = ? AND path > ?))", [after[0], after[0], after[1]]
    rows = db.execute("SELECT " + _MEMBER + " FROM files WHERE sha256 = ? AND tenant = ?"
                      + nc + extra + " ORDER BY node, path LIMIT ?",
                      [sha, tenant, *na, *ea, limit + 1]).fetchall()
    out = []
    for r in rows[:limit]:
        out.append({"node": r[0], "path": _guards.redact(r[1]) if (redact and r[7]) else r[1],
                    "dev": r[3], "ino": r[4], "nlink": r[5], "git_root": r[6],
                    "sensitive": bool(r[7]), "never": bool(r[8])})
    last = (rows[limit - 1][0], rows[limit - 1][1]) if len(rows) > limit else None
    return out, len(rows) > limit, last


def dupes(db: sqlite3.Connection, *, tenant: str = PLATFORM_TENANT,
          nodes: str | Iterable[str] | None = None, min_bytes: int = DEFAULT_MIN_DUPE_BYTES,
          limit: int = 50, cursor: str | None = None, redact: bool = False) -> dict:
    """Byte-identical groups within ONE tenant, most waste first, keyset on
    (wasted_bytes DESC, sha256). Hard links collapse; `actionable_bytes` counts only
    copies on the same node+volume, outside git, single-link, not sensitive, not in the
    never set. Unscoped reads come from the `dupe_groups` table maintained at ingest; a
    node-scoped read computes the groups over only those nodes' rows. Only HASHED rows
    count: without a node filter this covers confirmed hashes only."""
    limit = max(1, min(int(limit), 500))
    min_bytes = max(0, min(int(min_bytes), 2 ** 63 - 1))
    cw: int | None = None
    cs = ""
    if cursor:
        a, b = _pair_cursor(cursor)
        cw, cs = int(a), str(b)
    if nodes is None:
        where, args = " WHERE tenant = ? AND bytes >= ?", [tenant, min_bytes]
        total = db.execute("SELECT COALESCE(SUM(wasted_bytes), 0) FROM dupe_groups" + where,
                           args).fetchone()[0]
        if cw is not None:
            where += " AND (wasted_bytes < ? OR (wasted_bytes = ? AND sha256 > ?))"
            args += [cw, cw, cs]
        rows = [dict(zip(("sha256", "bytes", "count", "wasted_bytes", "actionable_bytes"), r))
                for r in db.execute(
                    "SELECT sha256, bytes, count, wasted_bytes, actionable_bytes FROM dupe_groups"
                    + where + " ORDER BY wasted_bytes DESC, sha256 LIMIT ?", [*args, limit + 1])]
    else:
        nc, na = _node_clause(nodes, "node")
        raw = db.execute(
            "SELECT sha256, " + _MEMBER + " FROM files WHERE tenant = ? AND sha256 IS NOT NULL"
            " AND bytes >= ?" + nc + " AND sha256 IN (SELECT sha256 FROM files WHERE tenant = ?"
            " AND sha256 IS NOT NULL AND bytes >= ?" + nc + " GROUP BY sha256"
            " HAVING COUNT(*) > 1)", [tenant, min_bytes, *na, tenant, min_bytes, *na]).fetchall()
        by: dict[str, list[tuple]] = {}
        for r in raw:
            by.setdefault(r[0], []).append(tuple(r[1:]))
        all_rows = []
        for sha, ms in by.items():
            st = _group_stats(ms)
            if st["count"] >= 2:
                all_rows.append({"sha256": sha, "bytes": st["bytes"], "count": st["count"],
                                 "wasted_bytes": st["wasted_bytes"],
                                 "actionable_bytes": st["actionable_bytes"]})
        all_rows.sort(key=lambda g: (-g["wasted_bytes"], g["sha256"]))
        total = sum(g["wasted_bytes"] for g in all_rows)
        if cw is not None:
            all_rows = [g for g in all_rows if g["wasted_bytes"] < cw
                        or (g["wasted_bytes"] == cw and g["sha256"] > cs)]
        rows = all_rows[:limit + 1]
    groups = []
    for g in rows[:limit]:
        paths, more, _last = _group_paths(db, tenant, g["sha256"], nodes, redact, GROUP_PATHS)
        groups.append({**g, "paths": paths, "paths_truncated": more})
    nxt = (_b64([rows[limit - 1]["wasted_bytes"], rows[limit - 1]["sha256"]])
           if len(rows) > limit else None)
    return {"groups": groups, "total_wasted_bytes": int(total), "next_cursor": nxt}


def dupe_group(db: sqlite3.Connection, sha256: str, *, tenant: str = PLATFORM_TENANT,
               nodes: str | Iterable[str] | None = None, cursor: str | None = None,
               limit: int = 200, redact: bool = False) -> dict:
    """Every member of one duplicate group (paginated), within the tenant/scope."""
    sha = (sha256 or "").lower()
    if not _HEX64.match(sha):
        raise ValueError("sha256 must be 64 hex chars")
    after = None
    if cursor:
        a, b = _pair_cursor(cursor)
        after = (str(a), str(b))
    limit = max(1, min(int(limit), 1000))
    nc, na = _node_clause(nodes, "node")
    rows = db.execute("SELECT " + _MEMBER + " FROM files WHERE sha256 = ? AND tenant = ?" + nc,
                      [sha, tenant, *na]).fetchall()
    st = _group_stats([tuple(r) for r in rows]) if rows else {
        "bytes": 0, "count": 0, "wasted_bytes": 0, "actionable_bytes": 0}
    paths, _more, last = _group_paths(db, tenant, sha, nodes, redact, limit, after)
    return {"sha256": sha, "bytes": st["bytes"], "count": st["count"],
            "wasted_bytes": st["wasted_bytes"], "actionable_bytes": st["actionable_bytes"],
            "paths": paths, "next_cursor": _b64(list(last)) if last else None}


def tree(db: sqlite3.Connection, node: str, path: str | None = None, *,
         tenant: str = PLATFORM_TENANT, depth: int = 1, limit: int = 200,
         cursor: str | None = None, redact: bool = False) -> dict:
    """Children of `path` from the `dirs` rollup + the files directly in it, biggest
    first, keyset on (bytes DESC, name). With no path: the node's indexed ROOTS.
    `depth` > 1 nests the first page of each child dir (bounded by MAX_TREE_NODES)."""
    depth = max(1, min(int(depth), 4))
    limit = max(1, min(int(limit), 1000))
    budget = [MAX_TREE_NODES]
    if not path:
        kids = []
        for root, files, b in db.execute(
                "SELECT root, files, bytes FROM roots WHERE tenant = ? AND node = ?"
                " ORDER BY root LIMIT ?", (tenant, node, limit)).fetchall():
            d = db.execute("SELECT bytes, files, newest_mtime_ns FROM dirs WHERE tenant = ?"
                           " AND node = ? AND path = ?", (tenant, node, root)).fetchone()
            row: dict[str, Any] = {"name": root, "kind": "root",
                                   "bytes": int(d[0]) if d else int(b),
                                   "files": int(d[1]) if d else int(files),
                                   "newest_mtime": (d[2] / 1e9) if d and d[2] else None}
            if depth > 1:
                row["children"] = _children(db, tenant, node, root, depth - 1, 50, None,
                                            redact, budget)[0]
            kids.append(row)
        return {"node": node, "path": "", "children": kids, "truncated": budget[0] <= 0,
                "next_cursor": None}
    p = _clean(path)
    kids, nxt = _children(db, tenant, node, p, depth, limit, cursor, redact, budget)
    return {"node": node, "path": p, "children": kids,
            "truncated": bool(nxt) or budget[0] <= 0, "next_cursor": nxt}


def _children(db: sqlite3.Connection, tenant: str, node: str, path: str, depth: int,
              limit: int, cursor: str | None, redact: bool, budget: list[int]
              ) -> tuple[list[dict], str | None]:
    if budget[0] <= 0:
        return [], None
    n = min(limit, budget[0])
    where, args = "", []
    if cursor:
        cb, cn = _pair_cursor(cursor)
        where, args = " WHERE (bytes < ? OR (bytes = ? AND name > ?))", [int(cb), int(cb),
                                                                       str(cn)]
    rows = db.execute(
        "SELECT name, kind, bytes, files, newest, sens FROM ("
        " SELECT name, 'dir' AS kind, bytes, files, newest_mtime_ns AS newest, 0 AS sens"
        "   FROM dirs WHERE tenant = ? AND node = ? AND parent = ?"
        " UNION ALL"
        " SELECT name, 'file', bytes, 1, mtime_ns, sensitive"
        "   FROM files WHERE tenant = ? AND node = ? AND parent = ?)" + where
        + " ORDER BY bytes DESC, name LIMIT ?",
        [tenant, node, path, tenant, node, path, *args, n + 1]).fetchall()
    budget[0] -= min(len(rows), n)
    out = []
    for name, kind, b, files, newest, sens in rows[:n]:
        child: dict[str, Any] = {"name": "[redacted]" if (redact and sens) else name,
                                 "kind": kind, "bytes": int(b), "files": int(files),
                                 "newest_mtime": (newest / 1e9) if newest else None}
        if kind == "dir" and depth > 1 and budget[0] > 0:
            child["children"] = _children(db, tenant, node, _prefix(path) + name, depth - 1,
                                          50, None, redact, budget)[0]
        out.append(child)
    nxt = _b64([rows[n - 1][2], rows[n - 1][0]]) if len(rows) > n else None
    return out, nxt


def changes(db: sqlite3.Connection, *, tenant: str, node: str, since_seq: int,
            cursor: str | None = None, limit: int = 1000, redact: bool = False) -> dict:
    """The change feed: rows and tombstones with seq > since_seq, keyset (seq, path)."""
    limit = max(1, min(int(limit), 5000))
    cs, cp = int(since_seq), ""
    if cursor:
        a, b = _pair_cursor(cursor)
        cs, cp = int(a), str(b)
    key = " AND (seq > ? OR (seq = ? AND path > ?))"
    ups = db.execute(_WIRE_SELECT + " WHERE tenant = ? AND node = ? AND seq > ?" + key
                     + " ORDER BY seq, path LIMIT ?",
                     (tenant, node, since_seq, cs, cs, cp, limit + 1)).fetchall()
    dels = db.execute("SELECT path, sha256, bytes, deleted_at, seq FROM files_deleted"
                      " WHERE tenant = ? AND node = ? AND seq > ?" + key
                      + " ORDER BY seq, path LIMIT ?",
                      (tenant, node, since_seq, cs, cs, cp, limit + 1)).fetchall()
    merged = sorted([("u", r[13], r[0], r) for r in ups] + [("d", r[4], r[0], r) for r in dels],
                    key=lambda x: (x[1], x[2]))
    page = merged[:limit]
    out_u, out_d = [], []
    for kind, _s, _p, r in page:
        if kind == "u":
            w = _wire_row(r)
            if redact and w["sensitive"]:
                w.update(path=_guards.redact(w["path"]), sha256=None, partial_hash=None)
            out_u.append(w)
        else:
            hide = redact and _guards.is_sensitive(r[0])
            out_d.append({"path": _guards.redact(r[0]) if hide else r[0],
                          "sha256": None if hide else r[1], "bytes": r[2],
                          "deleted_at": r[3], "seq": r[4]})
    more = len(merged) > limit
    return {"upserts": out_u, "deletes": out_d,
            "next_cursor": _b64([page[-1][1], page[-1][2]]) if more and page else None,
            "next_seq": page[-1][1] if page else int(since_seq), "more": more}


def _age_s(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return time.time() - datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def nodes_status(db: sqlite3.Connection, *, tenant: str | None,
                 nodes: Iterable[str] | None = None) -> list[dict]:
    """Per node: its roots (files, bytes, scanned_at, hashed_pct, truncated, errors),
    volumes, last_push_at and whether the index is stale (> 48 h, or nothing yet)."""
    where, args = " WHERE 1", []
    if tenant is not None:
        where += " AND tenant = ?"
        args.append(tenant)
    if nodes is not None:
        ns = sorted(set(nodes))
        if not ns:
            return []
        where += " AND node IN (" + ",".join("?" * len(ns)) + ")"
        args += ns
    out: dict[tuple, dict] = {}
    for r in db.execute("SELECT tenant, node, root, files, bytes, scanned_at, hashed_pct,"
                        " truncated, errors, last_push_at FROM roots" + where
                        + " ORDER BY node, root", args):
        n = out.setdefault((r[0], r[1]), {"node": r[1], "tenant": r[0], "roots": [],
                                         "volumes": [], "last_push_at": None})
        n["roots"].append({"root": r[2], "files": r[3], "bytes": r[4], "scanned_at": r[5],
                           "hashed_pct": r[6], "truncated": bool(r[7]), "errors": r[8]})
        if r[9] and (n["last_push_at"] is None or r[9] > n["last_push_at"]):
            n["last_push_at"] = r[9]
    for r in db.execute("SELECT tenant, node, volumes FROM node_volumes" + where, args):
        if (r[0], r[1]) in out:
            try:
                out[(r[0], r[1])]["volumes"] = json.loads(r[2])
            except ValueError:
                pass
    for n in out.values():
        newest = n["last_push_at"] or max((x["scanned_at"] or "" for x in n["roots"]),
                                          default="")
        age = _age_s(newest)
        n["stale"] = age is None or age > STALE_SECONDS
    return list(out.values())


def index_state(db: sqlite3.Connection, *, tenant: str | None,
                nodes: Iterable[str] | None) -> dict:
    """`indexed_roots` + `stale`, carried by every search/dupes/tree response so a
    surface can tell "not indexed" from "stale" from "no match"."""
    st = nodes_status(db, tenant=tenant, nodes=nodes)
    roots = [{"node": n["node"], "root": r["root"], "scanned_at": r["scanned_at"],
              "last_push_at": n["last_push_at"]} for n in st for r in n["roots"]]
    return {"indexed_roots": roots, "stale": (not st) or any(n["stale"] for n in st)}
