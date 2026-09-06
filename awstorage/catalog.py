"""SQLite catalog: snapshots, trees, proposals, ledger.

One file, stdlib sqlite3, WAL mode. The catalog is the thing a fleet posts
scans INTO and a GUI reads OUT of; the package only needs it to answer "what
did this root look like last time" and "what did we decide to do about it".

Every apply writes a LEDGER row whether it acted, dry-ran, or refused. A
storage tool that deletes without a ledger is indistinguishable from a bug.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_DDL = """
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node TEXT NOT NULL,
  root TEXT NOT NULL,
  taken_at TEXT NOT NULL,
  schema INTEGER NOT NULL,
  truncated INTEGER NOT NULL DEFAULT 0,
  total_bytes INTEGER NOT NULL DEFAULT 0,
  tree_count INTEGER NOT NULL DEFAULT 0,
  meta TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS snapshots_node_root ON snapshots(node, root, taken_at);
CREATE TABLE IF NOT EXISTS trees (
  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  depth INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  files INTEGER NOT NULL,
  dirs INTEGER NOT NULL,
  newest_mtime REAL NOT NULL,
  fingerprint TEXT NOT NULL,
  cls TEXT,
  refetchable INTEGER,
  confidence REAL,
  reason TEXT,
  source TEXT,
  PRIMARY KEY (snapshot_id, path)
);
CREATE TABLE IF NOT EXISTS top_files (
  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  mtime REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS proposals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  snapshot_id INTEGER REFERENCES snapshots(id) ON DELETE SET NULL,
  node TEXT NOT NULL,
  path TEXT NOT NULL,
  action TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  cls TEXT NOT NULL,
  policy_rule TEXT,
  auto INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'proposed',
  fingerprint TEXT,
  note TEXT
);
CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  proposal_id INTEGER,
  node TEXT NOT NULL,
  path TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  bytes INTEGER NOT NULL DEFAULT 0,
  detail TEXT
);
"""

_STATUSES = {"proposed", "approved", "rejected", "applied", "expired", "snoozed"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Catalog:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path))
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(_DDL)
        # v1.1: trees.git (scanner saw a .git). Additive, so an older catalog opens.
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(trees)")}
        if "git" not in cols:
            with self._db:
                self._db.execute("ALTER TABLE trees ADD COLUMN git INTEGER NOT NULL DEFAULT 0")

    def close(self) -> None:
        self._db.close()

    # -- snapshots -----------------------------------------------------------------

    def put_snapshot(self, snap: dict) -> int:
        trees = snap.get("trees", [])
        root_row = next((t for t in trees if t["depth"] == 0), None)
        total = int(root_row["bytes"]) if root_row else sum(t["bytes"] for t in trees)
        meta = {k: snap.get(k) for k in ("max_depth", "time_budget_s", "elapsed_s",
                                          "error_count", "classifier")}
        with self._db:
            cur = self._db.execute(
                "INSERT INTO snapshots(node, root, taken_at, schema, truncated, total_bytes,"
                " tree_count, meta) VALUES (?,?,?,?,?,?,?,?)",
                (snap["node"], snap["root"], snap["taken_at"], int(snap["schema"]),
                 1 if snap.get("truncated") else 0, total, len(trees), json.dumps(meta)),
            )
            sid = int(cur.lastrowid)
            self._db.executemany(
                "INSERT INTO trees(snapshot_id, path, depth, bytes, files, dirs, newest_mtime,"
                " fingerprint, cls, refetchable, confidence, reason, source, git)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(sid, t["path"], t["depth"], t["bytes"], t["files"], t["dirs"],
                  t["newest_mtime"], t["fingerprint"], t.get("cls"),
                  None if t.get("refetchable") is None else int(bool(t["refetchable"])),
                  t.get("confidence"), t.get("reason"), t.get("source"),
                  1 if t.get("git") else 0) for t in trees],
            )
            self._db.executemany(
                "INSERT INTO top_files VALUES (?,?,?,?)",
                [(sid, f["path"], f["bytes"], f["mtime"]) for f in snap.get("top_files", [])],
            )
        return sid

    def list_snapshots(self, node: str | None = None, root: str | None = None,
                       limit: int = 50) -> list[dict]:
        q = "SELECT * FROM snapshots"
        cond, args = [], []
        if node:
            cond.append("node = ?")
            args.append(node)
        if root:
            cond.append("root = ?")
            args.append(root)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY taken_at DESC, id DESC LIMIT ?"
        args.append(int(limit))
        return [dict(r) for r in self._db.execute(q, args)]

    def get_snapshot(self, sid: int) -> dict | None:
        row = self._db.execute("SELECT * FROM snapshots WHERE id = ?", (sid,)).fetchone()
        if not row:
            return None
        snap = dict(row)
        snap["meta"] = json.loads(snap.get("meta") or "{}")
        snap["truncated"] = bool(snap["truncated"])
        snap["trees"] = []
        for t in self._db.execute(
            "SELECT * FROM trees WHERE snapshot_id = ? ORDER BY depth, path", (sid,)
        ):
            d = dict(t)
            d.pop("snapshot_id", None)
            if d.get("refetchable") is not None:
                d["refetchable"] = bool(d["refetchable"])
            d["git"] = bool(d.get("git"))
            snap["trees"].append(d)
        snap["top_files"] = [
            {"path": r["path"], "bytes": r["bytes"], "mtime": r["mtime"]}
            for r in self._db.execute(
                "SELECT path, bytes, mtime FROM top_files WHERE snapshot_id = ?"
                " ORDER BY bytes DESC", (sid,))
        ]
        return snap

    def latest_pair(self, node: str, root: str) -> tuple[dict | None, dict | None]:
        """(newest, previous) snapshots for a node+root -- the diff's usual inputs."""
        rows = self.list_snapshots(node=node, root=root, limit=2)
        newest = self.get_snapshot(rows[0]["id"]) if rows else None
        prev = self.get_snapshot(rows[1]["id"]) if len(rows) > 1 else None
        return newest, prev

    def drop_snapshot(self, sid: int) -> None:
        with self._db:
            self._db.execute("DELETE FROM snapshots WHERE id = ?", (sid,))

    # -- proposals / ledger --------------------------------------------------------

    def put_proposals(self, proposals: list) -> list[int]:
        ids = []
        with self._db:
            for p in proposals:
                d = p if isinstance(p, dict) else p.__dict__
                cur = self._db.execute(
                    "INSERT INTO proposals(created_at, snapshot_id, node, path, action, bytes,"
                    " cls, policy_rule, auto, status, fingerprint, note)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (_now(), d.get("snapshot_id"), d["node"], d["path"], d["action"],
                     int(d["bytes"]), d["cls"], d.get("policy_rule"),
                     1 if d.get("auto") else 0, d.get("status", "proposed"),
                     d.get("fingerprint"), d.get("note")),
                )
                ids.append(int(cur.lastrowid))
        return ids

    def list_proposals(self, status: str | None = None, node: str | None = None,
                       limit: int = 200) -> list[dict]:
        q = "SELECT * FROM proposals"
        cond, args = [], []
        if status:
            cond.append("status = ?")
            args.append(status)
        if node:
            cond.append("node = ?")
            args.append(node)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY bytes DESC, id DESC LIMIT ?"
        args.append(int(limit))
        out = []
        for r in self._db.execute(q, args):
            d = dict(r)
            d["auto"] = bool(d["auto"])
            out.append(d)
        return out

    def get_proposal(self, pid: int) -> dict | None:
        r = self._db.execute("SELECT * FROM proposals WHERE id = ?", (pid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["auto"] = bool(d["auto"])
        return d

    def set_status(self, pid: int, status: str, note: str | None = None) -> None:
        if status not in _STATUSES:
            raise ValueError(f"unknown proposal status {status!r}")
        with self._db:
            if note is None:
                self._db.execute("UPDATE proposals SET status = ? WHERE id = ?", (status, pid))
            else:
                self._db.execute("UPDATE proposals SET status = ?, note = ? WHERE id = ?",
                                 (status, note, pid))

    def ledger(self, *, proposal_id: int | None, node: str, path: str, action: str,
               outcome: str, bytes_: int = 0, detail: str | None = None) -> int:
        with self._db:
            cur = self._db.execute(
                "INSERT INTO ledger(at, proposal_id, node, path, action, outcome, bytes, detail)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (_now(), proposal_id, node, path, action, outcome, int(bytes_), detail),
            )
        return int(cur.lastrowid)

    def list_ledger(self, limit: int = 200) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM ledger ORDER BY id DESC LIMIT ?", (int(limit),))]

    def totals(self) -> dict:
        """Cross-node roll-up for a dashboard: newest snapshot per (node, root)."""
        rows = self._db.execute(
            "SELECT s.* FROM snapshots s JOIN ("
            "  SELECT node, root, MAX(taken_at) AS t FROM snapshots GROUP BY node, root"
            ") m ON s.node = m.node AND s.root = m.root AND s.taken_at = m.t"
            " ORDER BY s.node, s.root"
        ).fetchall()
        out = {"roots": [], "total_bytes": 0, "nodes": set()}
        for r in rows:
            d = dict(r)
            d["truncated"] = bool(d["truncated"])
            out["roots"].append({k: d[k] for k in ("id", "node", "root", "taken_at",
                                                     "total_bytes", "truncated")})
            out["total_bytes"] += int(d["total_bytes"])
            out["nodes"].add(d["node"])
        out["nodes"] = sorted(out["nodes"])
        return out
