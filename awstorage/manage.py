"""Manage + share: dedup, archive-to-cold and share proposals over indexed files.

Four card-only actions from the ONE closed vocabulary (``policy.ACTIONS``, the
``policy.CARD_ACTIONS`` subset) ride the same pipeline as every other awstorage
change -- propose -> decision card -> apply -> ledger -> revert -- and add nothing
that can act on its own:

    hardlink         replace a byte-identical copy with a hardlink to the keeper
                     (same volume only); the copy is quarantined
    quarantine-copy  quarantine every copy but the keeper
    archive          stream a file to Strata cold with expected size + sha256, read
                     it back independently, then quarantine the local file
    share            publish a node path through a caller-supplied hook; the
                     enumeration refuses links, .git, .env*, sensitive and never paths

Rules every action obeys, each pinned by a test:

* **Dry-run is the default.** ``apply_manage(..., dry_run=True)`` reads and hashes,
  never writes outside the catalog.
* **CARD-ONLY approval.** An action runs only with a decision card whose answer is
  ``approve``, which carries the fact ``proposal_id: <id>`` for THIS proposal, which
  is the card the consumer recorded as approving it (``card_id``) on a proposal
  already ``approved``, and which carries a SIGNED answer receipt
  (``awstorage.attest.verify_receipt``): Ed25519 over {card, choice, answerer,
  time, nonce, surface, auth method, facts digest} with the platform's attestation
  key, an interactive fresh sign-in, an owner principal, an unused nonce. No
  provisioned public key, no awseal, or no receipt -> refused (fail closed). The
  card's own ``answered_by`` / ``answer_attested`` / ``answered_via`` are labels, not
  proof. There is no self-service exception.
* **Platform nodes only.** Until the decisions store carries a ``recipient`` and a
  tenant owner can approve their own node's card, every proposal whose ``tenant``
  is not ``platform`` is refused at apply (contract A7).
* **Apply-time checks no approval overrides.** Expiry; the guards (never set, OS
  trees, sensitive list); the git refusal (every member walked from its own dir up
  to the FILESYSTEM root, refusing on a ``.git`` file or dir or a bare-repo shape);
  per-member re-verification of size, mtime and sha256 -- for a hardlink the keeper
  AND the victim.
* **Quarantine is one ``os.replace``** into a quarantine dir whose ``st_dev`` was
  checked equal first. Cross-volume, a sharing violation or a permission error is
  a refusal (``cross-volume`` / ``locked``); there is never a copy fallback, in
  apply or in revert.
* **Ledgered per member.** One ledger row per member (``detail.member`` = its
  index) plus one proposal row whose ``path`` is the proposal's own path.

The package stays stdlib-only and speaks to nothing: the Strata upload, its
read-back, and the share transport are HOOKS. ``local_awshare_hook`` is the one
in-package hook, and it imports awshare lazily.

Proposal fields that do not fit the catalog's ``proposals`` row (members, keeper,
namespace, owner, tenant, expiry, approving card) live in side tables in the same
SQLite file; the catalog schema itself is not changed.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .guards import Guards
from .policy import CARD_ACTIONS, QUARANTINE_DIRNAME, ApplyRefused, _owning_root, _under_roots

#: The catalog `cls` each card action is filed under.
_CLS = {"hardlink": "dedup", "quarantine-copy": "dedup", "archive": "archive", "share": "share"}

#: Rows written by the first manage release used dotted names. They are READ as the
#: closed-vocabulary action; nothing new is ever written with them.
LEGACY_ALIASES = {"dedup.hardlink": "hardlink", "dedup.quarantine_copies": "quarantine-copy",
                  "archive.to_strata_cold": "archive", "share.awshare": "share"}

#: The only tenant whose nodes may be managed until card recipients land (A7).
PLATFORM_TENANT = "platform"
#: The pseudo-node the first share router used for workspace files. Workspace shares
#: belong to the existing /aither-share flow, never to a node-path manage proposal.
WORKSPACE_NODE = "workspace"
DEFAULT_TTL_DAYS = 7.0

#: Proposal statuses this module writes on top of the catalog's own set. The catalog
#: (`catalog._STATUSES`) does not know them yet, so they are written through the
#: side connection; see the disk-core handoff in the PR body.
MANAGE_STATUSES = frozenset({"proposed", "approved", "rejected", "expired", "snoozed",
                             "executing", "applied", "drifted", "refused", "failed"})

#: `answered_via` values that are NOT a human answering: the agent that raised the
#: card closing it itself, or the store applying the declared default at deadline.
#: A card labelled with one of these is refused even with a receipt (belt and
#: braces: such an answer never carries a genuine one).
NON_HUMAN_VIAS = frozenset({"agent", "deadline", "timeout", "expired", "steerback", ""})

#: 0.4.0's surface ALLOWLIST. No longer consulted (0.4.1): `via` is a caller-chosen
#: label; the SIGNED receipt's `surface` + `auth_method` replace it. Kept so imports
#: of the name keep working.
HUMAN_VIAS = frozenset({"popup", "desk", "phone"})

#: Env var naming the owner principals (comma-separated user ids) whose answer may
#: approve a manage proposal. Unset -> nobody's answer approves anything.
OWNERS_ENV = "AWSTORAGE_MANAGE_OWNERS"

#: MASTER SWITCH for card approvals. False refuses every answer. True (0.4.1) is NOT
#: trust in the store: every answer must still carry a receipt that
#: ``attest.verify_receipt`` accepts -- signature with the provisioned platform key,
#: owner principal, fresh interactive sign-in, unused nonce. The store's own fields
#: (``answered_by``, ``answer_attested``) are never an attestation path.
STORE_ATTESTS_ANSWERER = True

_SIDE_DDL = """
CREATE TABLE IF NOT EXISTS manage_params (
  proposal_id INTEGER PRIMARY KEY,
  action TEXT NOT NULL,
  params TEXT NOT NULL,
  owner TEXT,
  created_at TEXT NOT NULL,
  tenant TEXT NOT NULL DEFAULT 'platform'
);
CREATE TABLE IF NOT EXISTS manage_quarantine (
  entry TEXT PRIMARY KEY,
  proposal_id INTEGER,
  kind TEXT NOT NULL,
  origin TEXT NOT NULL,
  keeper TEXT,
  sha256 TEXT,
  at TEXT NOT NULL,
  reverted_at TEXT
);
CREATE TABLE IF NOT EXISTS manage_shares (
  proposal_id INTEGER PRIMARY KEY,
  owner TEXT NOT NULL,
  node TEXT NOT NULL,
  path TEXT NOT NULL,
  handle TEXT NOT NULL,
  at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS manage_runs (
  proposal_id INTEGER PRIMARY KEY,
  card_id TEXT,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS manage_cards (
  card_id TEXT PRIMARY KEY,
  proposal_id INTEGER NOT NULL,
  raised_at TEXT NOT NULL,
  consumed_at TEXT,
  outcome TEXT
);
"""

#: Columns added after the first release (additive, so an older side table opens).
_PARAM_COLUMNS = {
    "members_json": "TEXT NOT NULL DEFAULT '[]'",
    "approved_at": "TEXT",
    "expires_at": "TEXT",
    "requested_by": "TEXT",
    "node": "TEXT",
    "card_id": "TEXT",
}

ShareHook = Callable[..., dict]
UnshareHook = Callable[[dict], None]
StrataHook = Callable[..., dict]
ReadbackHook = Callable[[str], dict]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_action(action: str) -> str:
    return LEGACY_ALIASES.get(action, action)


def sha256_file(path: Path | str, *, chunk: int = 1 << 20) -> str:
    """Streaming sha256 of one file (O(chunk) memory)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------------------------
# Guards (A6): the one never set lives in awstorage.guards -- no copy of its lists here.
# ---------------------------------------------------------------------------------

def guard_refusal(path: str) -> Optional[str]:
    """Why a manage/share action must refuse `path` (A6), or None."""
    return Guards().refusal(str(path))


def git_refusal(path: Path | str) -> Optional[str]:
    """The git tree `path` lives in, or None.

    Walks from the member's own directory (the path itself when it is a dir) up to
    the FILESYSTEM root -- not the declared root -- so a repo that contains the
    declared root is found too. A ``.git`` FILE counts (worktrees, submodules), and
    so does a bare-repo shape (HEAD + objects/ + refs/).
    """
    p = Path(os.path.abspath(str(path)))
    node = p if p.is_dir() and not os.path.islink(p) else p.parent
    while True:
        if os.path.lexists(node / ".git"):
            return str(node).replace("\\", "/")
        if ((node / "HEAD").is_file() and (node / "objects").is_dir()
                and (node / "refs").is_dir()):
            return str(node).replace("\\", "/")
        parent = node.parent
        if parent == node:
            return None
        node = parent


# ---------------------------------------------------------------------------------
# Proposal model + side-table store
# ---------------------------------------------------------------------------------

@dataclass
class ManageProposal:
    """One manage/share action. `path` is the primary path (the first victim, the
    file to archive, the path to share); `members` is every file acted on, each
    ``{path, bytes, mtime_ns, sha256, dev, ino}``; `params` holds the rest (keeper,
    strata path, seal)."""

    node: str
    action: str
    path: str
    bytes: int = 0
    params: dict = field(default_factory=dict)
    owner: Optional[str] = None
    status: str = "proposed"
    note: Optional[str] = None
    id: Optional[int] = None
    tenant: str = PLATFORM_TENANT
    members: list = field(default_factory=list)
    requested_by: Optional[str] = None
    expires_at: Optional[str] = None
    approved_at: Optional[str] = None
    card_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.action = normalize_action(self.action)
        if self.expires_at is None:
            self.expires_at = (datetime.now(timezone.utc) + timedelta(days=DEFAULT_TTL_DAYS)
                               ).isoformat(timespec="seconds")

    def to_dict(self) -> dict:
        return {"id": self.id, "node": self.node, "action": self.action, "path": self.path,
                "bytes": self.bytes, "params": dict(self.params), "owner": self.owner,
                "status": self.status, "note": self.note, "tenant": self.tenant,
                "members": [dict(m) for m in self.members],
                "requested_by": self.requested_by, "expires_at": self.expires_at,
                "approved_at": self.approved_at, "card_id": self.card_id}

    @classmethod
    def from_order(cls, order: dict) -> "ManageProposal":
        """A node-side proposal from a Genesis manage order (``to_dict`` shape)."""
        keys = cls.__dataclass_fields__
        return cls(**{k: v for k, v in order.items() if k in keys and v is not None})


class ManageStore:
    """Side tables next to a Catalog. Opens its own connection to the same file."""

    def __init__(self, catalog: Any) -> None:
        self.catalog = catalog
        self._db = sqlite3.connect(str(catalog.path), timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout=30000")
        self._db.executescript(_SIDE_DDL)
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(manage_params)")}
        with self._db:
            if "tenant" not in cols:  # a side table from the first manage release
                self._db.execute("ALTER TABLE manage_params ADD COLUMN tenant TEXT NOT NULL"
                                 f" DEFAULT '{PLATFORM_TENANT}'")
            for name, decl in _PARAM_COLUMNS.items():
                if name not in cols:
                    self._db.execute(f"ALTER TABLE manage_params ADD COLUMN {name} {decl}")

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "ManageStore":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # -- proposals ------------------------------------------------------------------

    def submit(self, proposals: Iterable[ManageProposal]) -> list[int]:
        """Write proposals into the catalog's `proposals` table + their params here."""
        ids: list[int] = []
        for p in proposals:
            if p.action not in CARD_ACTIONS:
                raise ValueError(f"unknown manage action {p.action!r}")
            [pid] = self.catalog.put_proposals([{
                "node": p.node, "path": p.path, "action": p.action, "bytes": int(p.bytes),
                "cls": _CLS[p.action], "policy_rule": f"manage:{p.action}",
                "auto": False, "status": p.status, "note": p.note,
            }])
            with self._db:
                self._db.execute(
                    "INSERT INTO manage_params(proposal_id, action, params, owner, created_at,"
                    " tenant, members_json, expires_at, requested_by, node)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (pid, p.action, json.dumps(p.params, sort_keys=True), p.owner, _now(),
                     p.tenant or PLATFORM_TENANT, json.dumps(p.members, sort_keys=True),
                     p.expires_at, p.requested_by, p.node))
            p.id = pid
            ids.append(pid)
        return ids

    def load(self, pid: int) -> ManageProposal:
        row = self.catalog.get_proposal(int(pid))
        if row is None:
            raise ApplyRefused(f"no proposal {pid}")
        side = self._db.execute("SELECT * FROM manage_params WHERE proposal_id = ?",
                                (int(pid),)).fetchone()
        action = normalize_action(row["action"])
        if side is None or action not in CARD_ACTIONS:
            raise ApplyRefused(f"proposal {pid} is not a manage proposal")
        return ManageProposal(
            node=row["node"], action=action, path=row["path"], bytes=int(row["bytes"]),
            params=json.loads(side["params"]), owner=side["owner"], status=row["status"],
            note=row["note"], id=int(pid), tenant=side["tenant"] or PLATFORM_TENANT,
            members=json.loads(side["members_json"] or "[]"),
            requested_by=side["requested_by"], expires_at=side["expires_at"] or "",
            approved_at=side["approved_at"], card_id=side["card_id"])

    def set_status(self, pid: int, status: str, note: Optional[str] = None) -> None:
        """Write a proposal status, including the manage-only ones the catalog's own
        `set_status` does not know yet (executing/drifted/refused/failed)."""
        if status not in MANAGE_STATUSES:
            raise ValueError(f"unknown manage status {status!r}")
        with self._db:
            if note is None:
                self._db.execute("UPDATE proposals SET status = ? WHERE id = ?",
                                 (status, int(pid)))
            else:
                self._db.execute("UPDATE proposals SET status = ?, note = ? WHERE id = ?",
                                 (status, note, int(pid)))

    # -- cards ------------------------------------------------------------------------

    def link_card(self, card_id: str, pid: int) -> None:
        """Record that `card_id` was raised BY THIS PLANE for proposal `pid`. Only a
        linked card can ever approve: a card any agent raised with a matching fact
        line is not one of ours."""
        with self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO manage_cards(card_id, proposal_id, raised_at)"
                " VALUES (?,?,?)", (str(card_id), int(pid), _now()))

    def open_card_links(self) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM manage_cards WHERE consumed_at IS NULL ORDER BY raised_at")]

    def card_link(self, card_id: str) -> Optional[dict]:
        r = self._db.execute("SELECT * FROM manage_cards WHERE card_id = ?",
                             (str(card_id),)).fetchone()
        return dict(r) if r else None

    def close_card_link(self, card_id: str, outcome: str) -> None:
        with self._db:
            self._db.execute(
                "UPDATE manage_cards SET consumed_at = ?, outcome = ? WHERE card_id = ?"
                " AND consumed_at IS NULL", (_now(), outcome, str(card_id)))

    def mark_approved(self, pid: int, card_id: str) -> bool:
        """proposed -> approved, stamping the approving card. False when the proposal
        was not `proposed` (already decided): idempotent, never a second approval."""
        with self._db:
            cur = self._db.execute(
                "UPDATE proposals SET status = 'approved' WHERE id = ? AND status = 'proposed'",
                (int(pid),))
            if cur.rowcount != 1:
                return False
            self._db.execute(
                "UPDATE manage_params SET approved_at = ?, card_id = ? WHERE proposal_id = ?",
                (_now(), str(card_id), int(pid)))
        return True

    def mark_rejected(self, pid: int, card_id: str) -> bool:
        with self._db:
            cur = self._db.execute(
                "UPDATE proposals SET status = 'rejected' WHERE id = ? AND status = 'proposed'",
                (int(pid),))
            if cur.rowcount == 1:
                self._db.execute("UPDATE manage_params SET card_id = ? WHERE proposal_id = ?",
                                 (str(card_id), int(pid)))
        return cur.rowcount == 1

    # -- node-side execution record ---------------------------------------------------

    def record_run(self, pid: int, *, card_id: Optional[str], action: str,
                   outcome: str) -> None:
        """A node executed Genesis order `pid` to `outcome` (never re-executed)."""
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO manage_runs(proposal_id, card_id, action, outcome, at)"
                " VALUES (?,?,?,?,?)", (int(pid), card_id, action, outcome, _now()))

    def get_run(self, pid: int) -> Optional[dict]:
        r = self._db.execute("SELECT * FROM manage_runs WHERE proposal_id = ?",
                             (int(pid),)).fetchone()
        return dict(r) if r else None

    # -- quarantine entries -------------------------------------------------------

    def record_entry(self, *, entry: str, pid: Optional[int], kind: str, origin: str,
                     keeper: Optional[str], sha256: Optional[str]) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO manage_quarantine(entry, proposal_id, kind, origin, keeper, sha256,"
                " at) VALUES (?,?,?,?,?,?,?)",
                (entry, pid, kind, origin, keeper, sha256, _now()))

    def entries(self, pid: Optional[int] = None, *, include_reverted: bool = False,
                kind: Optional[str] = None) -> list[dict]:
        q = "SELECT * FROM manage_quarantine WHERE 1=1"
        args: list[Any] = []
        if pid is not None:
            q += " AND proposal_id = ?"
            args.append(int(pid))
        if kind is not None:
            q += " AND kind = ?"
            args.append(kind)
        if not include_reverted:
            q += " AND reverted_at IS NULL"
        return [dict(r) for r in self._db.execute(q + " ORDER BY entry", args)]

    def mark_reverted(self, entry: str, *, how: str = "reverted") -> None:
        with self._db:
            self._db.execute("UPDATE manage_quarantine SET reverted_at = ? WHERE entry = ?",
                             (f"{_now()} {how}", entry))

    # -- shares -----------------------------------------------------------------------

    def record_share(self, *, pid: int, owner: str, node: str, path: str, handle: dict) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO manage_shares(proposal_id, owner, node, path, handle, at)"
                " VALUES (?,?,?,?,?,?)",
                (pid, owner, node, path, json.dumps(handle, sort_keys=True), _now()))

    def get_share(self, pid: int) -> Optional[dict]:
        r = self._db.execute("SELECT * FROM manage_shares WHERE proposal_id = ?",
                             (int(pid),)).fetchone()
        return _share_row(r) if r else None

    def list_shares(self, owner: Optional[str] = None, *, include_revoked: bool = False,
                    limit: int = 200) -> list[dict]:
        q = "SELECT * FROM manage_shares"
        cond: list[str] = []
        args: list[Any] = []
        if owner is not None:
            cond.append("owner = ?")
            args.append(owner)
        if not include_revoked:
            cond.append("revoked_at IS NULL")
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY at DESC, proposal_id DESC LIMIT ?"
        args.append(int(limit))
        return [_share_row(r) for r in self._db.execute(q, args)]

    def revoke_share(self, pid: int) -> None:
        with self._db:
            self._db.execute("UPDATE manage_shares SET revoked_at = ? WHERE proposal_id = ?",
                             (_now(), int(pid)))


def _share_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["handle"] = json.loads(d.get("handle") or "{}")
    return d


# ---------------------------------------------------------------------------------
# Propose (pure -- no filesystem access)
# ---------------------------------------------------------------------------------

_SHA = re.compile(r"[0-9a-f]{64}")


def _keeper_key(m: dict) -> tuple:
    # Deterministic: the shortest path is usually the "original" (not a nested copy),
    # ties broken lexically so two runs over the same group pick the same keeper.
    return (len(str(m["path"])), str(m["path"]))


def _member(raw: Any, sha: str, size: int) -> dict:
    m = raw if isinstance(raw, dict) else {"path": str(raw)}
    return {"path": str(m["path"]), "bytes": int(m.get("bytes", m.get("size", size)) or 0),
            "mtime_ns": m.get("mtime_ns"), "sha256": m.get("sha256") or sha,
            "dev": m.get("dev"), "ino": m.get("ino"),
            "nlink": int(m.get("nlink") if m.get("nlink") is not None else 1)}


def _actionable(m: dict) -> bool:
    """A6/A5 `actionable`: not in a git tree, single-linked, not sensitive/never."""
    if m.get("git_root") or m.get("sensitive"):
        return False
    if int(m.get("nlink") or 1) != 1:
        return False
    return guard_refusal(str(m["path"])) is None


def propose_dupes(groups: Iterable[dict], *, node: str, action: str = "quarantine-copy",
                  min_bytes: int = 1, requested_by: Optional[str] = None,
                  tenant: str = PLATFORM_TENANT) -> list[ManageProposal]:
    """One proposal per duplicate group on `node`, built from the FILES INDEX shape.

    `groups` is the ``/files/dupes`` (+ drill-down) shape: ``{sha256, bytes,
    paths: [{node, path, bytes, mtime_ns, sha256, dev, ino, nlink, git_root,
    sensitive}]}``. Only actionable members on `node` are kept: other nodes, git
    trees, multiply-linked, sensitive and never paths are dropped, and so is any
    member on a different ``dev`` from the keeper (hardlink and quarantine are both
    same-volume moves). Rows sharing ``(dev, ino)`` are one file. `bytes` counts
    only members with ``nlink == 1``.
    """
    if action not in ("hardlink", "quarantine-copy"):
        raise ValueError(f"not a dedup action: {action!r}")
    out: list[ManageProposal] = []
    for g in groups:
        sha = str(g.get("sha256") or "")
        size = int(g.get("bytes", g.get("size", 0)) or 0)
        if not _SHA.fullmatch(sha) or size < max(1, int(min_bytes)):
            continue
        members: list[dict] = []
        seen: set = set()
        for raw in g.get("paths") or []:
            if isinstance(raw, dict) and raw.get("node", node) != node:
                continue
            m = _member(raw, sha, size)
            raw_d = raw if isinstance(raw, dict) else {}
            m["git_root"] = raw_d.get("git_root")
            m["sensitive"] = raw_d.get("sensitive")
            ident = (m["dev"], m["ino"]) if m["dev"] is not None and m["ino"] is not None \
                else ("path", m["path"])
            if ident in seen or not _actionable(m):
                continue
            seen.add(ident)
            members.append(m)
        members.sort(key=_keeper_key)
        if len(members) < 2:
            continue
        keep, rest = members[0], members[1:]
        victims = [m for m in rest if keep["dev"] is None or m["dev"] == keep["dev"]]
        if not victims:
            continue
        for m in [keep, *victims]:
            m.pop("git_root", None)
            m.pop("sensitive", None)
        counted = sum(m["bytes"] for m in victims if m["nlink"] == 1)
        verb = "hardlink to" if action == "hardlink" else "quarantine, keeping"
        out.append(ManageProposal(
            node=node, action=action, path=victims[0]["path"], bytes=counted,
            params={"sha256": sha, "size": size, "keep": keep}, members=victims,
            requested_by=requested_by, tenant=tenant,
            note=f"{len(victims)} byte-identical copies; {verb} {keep['path']} "
                 "[needs approval]"))
    out.sort(key=lambda x: -x.bytes)
    return out


def archive_namespace(node: str, path: str) -> str:
    """``aither://cold/disk-archive/{node}/<relpath>`` for a PLATFORM node (A7)."""
    rel = str(path).replace("\\", "/")
    rel = re.sub(r"^([A-Za-z]):", lambda m: m.group(1).lower(), rel).lstrip("/")
    safe_node = re.sub(r"[^A-Za-z0-9_.-]+", "_", node) or "node"
    return f"aither://cold/disk-archive/{safe_node}/{rel}"


def propose_archive(node: str, member: dict, *, requested_by: Optional[str] = None,
                    tenant: str = PLATFORM_TENANT) -> ManageProposal:
    """Stream one indexed file to Strata cold, read it back, then quarantine local."""
    m = _member(member, str(member.get("sha256") or ""), int(member.get("bytes") or 0))
    if not _SHA.fullmatch(str(m["sha256"] or "")):
        raise ValueError("archive needs the indexed sha256 of the file")
    if tenant != PLATFORM_TENANT:
        raise ValueError("tenant archive writes with the node's own TenantScopedToken; "
                         "manage is platform-nodes-only until card recipients land")
    spath = archive_namespace(node, m["path"])
    return ManageProposal(
        node=node, action="archive", path=m["path"], bytes=m["bytes"], members=[m],
        params={"strata_path": spath, "tier": "cold", "sha256": m["sha256"]},
        requested_by=requested_by, tenant=tenant,
        note=f"stream to {spath}, read back and verify sha256, then quarantine local "
             "(stored PLAINTEXT at rest) [needs approval]")


def propose_share(node: str, path: str, *, owner: str, seal: bool = False,
                  namespace: Optional[str] = None, bytes_: int = 0,
                  sha256: Optional[str] = None, requested_by: Optional[str] = None,
                  tenant: str = PLATFORM_TENANT) -> ManageProposal:
    """Publish a node `path`. `owner` MUST come from the authenticated caller -- the
    router derives it; nothing here trusts a payload for it."""
    if not owner:
        raise ValueError("owner is required (derive it from the authenticated caller)")
    return ManageProposal(
        node=node, action="share", path=path, bytes=int(bytes_), owner=owner,
        members=[{"path": path, "bytes": int(bytes_), "sha256": sha256, "mtime_ns": None,
                  "dev": None, "ino": None, "nlink": 1}],
        params={"seal": bool(seal), "namespace": namespace, "sha256": sha256},
        requested_by=requested_by or owner, tenant=tenant,
        note=f"publish for {owner}" + (" (sealed)" if seal else ""))


# ---------------------------------------------------------------------------------
# Cards: per-action text, and the check an answer must pass
# ---------------------------------------------------------------------------------

SHARE_EXCLUDES = (".git", ".env*", "sensitive files (keys, credentials)",
                  "never-set paths (live state, OS trees, node_modules)", "links/junctions")


def card_facts(proposal_id: int) -> list[str]:
    """The fact line a card MUST carry to approve `proposal_id`."""
    return [f"proposal_id: {int(proposal_id)}"]


#: The card fact naming WHAT was approved: ``content_sha256: <hex>``. The receipt signs
#: the card's facts, so a row edited after the card (another path, other members,
#: other params) no longer matches the digest the owner's answer is bound to.
CONTENT_FACT = "content_sha256"


def _canon_digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, default=str).encode("utf-8")
                          ).hexdigest()


def content_digest(p: "ManageProposal") -> str:
    """sha256 of the canonical content of a manage proposal: id, node, action, path,
    bytes, tenant, owner, params, and every member's path + sha256 + bytes (sorted)."""
    members = sorted(({"path": str(m.get("path")), "sha256": m.get("sha256") or None,
                       "bytes": int(m.get("bytes") or 0)} for m in (p.members or [])),
                     key=lambda m: (m["path"], str(m["sha256"])))
    return _canon_digest({"v": 1, "kind": "manage", "id": p.id, "node": p.node,
                          "action": p.action, "path": str(p.path), "bytes": int(p.bytes or 0),
                          "tenant": p.tenant or PLATFORM_TENANT, "owner": p.owner,
                          "params": p.params or {}, "members": members})


def content_fact(digest: str) -> str:
    return f"{CONTENT_FACT}: {digest}"


def _fact_key(fact: str) -> str:
    """``'proposal_id'`` for ``'Proposal_ID : 7'`` -- the key a fact line names."""
    return fact.split(":", 1)[0].strip().lower() if ":" in fact else ""


def require_content(card: Any, digest: str, *, what: str = "proposal") -> None:
    """Refuse unless the (already receipt-verified) card carries ``content_sha256`` equal
    to ``digest`` -- the content being acted on NOW, recomputed from the row."""
    facts = [re.sub(r"\s+", " ", str(f)).strip() for f in (_get(card, "facts") or [])]
    cid = str(_get(card, "id") or _get(card, "card_id") or "?")
    named = [f for f in facts if _fact_key(f) == CONTENT_FACT]
    if not named:
        raise ApplyRefused(f"card {cid} carries no '{CONTENT_FACT}' fact: it does not say "
                           f"WHAT was approved; re-raise the card")
    if len(named) != 1:
        raise ApplyRefused(f"card {cid} carries {len(named)} '{CONTENT_FACT}' facts: an "
                           "answer must approve exactly one content; re-raise the card")
    if named[0] != content_fact(digest):
        raise ApplyRefused(f"card {cid}: the {what} changed after the owner answered "
                           f"(content digest {digest[:12]} is not the approved "
                           f"{named[0].split(':', 1)[1].strip()[:12]})")


def card_spec(p: ManageProposal) -> dict:
    """Title, summary, facts, options and reversibility text for the card that asks a
    human to approve `p`. Every card action has its own text (pinned per action)."""
    if p.id is None:
        raise ValueError("submit the proposal before raising its card")
    gb = int(p.bytes) / 2**30
    keep = (p.params.get("keep") or {}).get("path", "")
    facts = card_facts(p.id) + [f"node: {p.node}", f"action: {p.action}",
                                f"members: {len(p.members)}", f"bytes: {p.bytes}",
                                f"expires: {p.expires_at}",
                                content_fact(content_digest(p))]
    if p.action == "hardlink":
        title = f"awstorage #{p.id}: hardlink {len(p.members)} duplicate(s) on {p.node}?"
        summary = (f"Replace {len(p.members)} byte-identical copies ({gb:.2f} GB) with "
                   f"hardlinks to {keep}.")
        reversible = ("Reversible: each copy moves to the quarantine and `revert` puts it "
                      "back; bytes are reclaimed only when the quarantine is purged.")
        facts.append(f"keep: {keep}")
        options = ["approve|Approve: hardlink them (reversible)", "reject|Reject: leave them"]
    elif p.action == "quarantine-copy":
        title = f"awstorage #{p.id}: quarantine {len(p.members)} duplicate(s) on {p.node}?"
        summary = f"Quarantine {len(p.members)} copies ({gb:.2f} GB), keeping {keep}."
        reversible = ("Reversible: copies move to the quarantine and `revert` puts them "
                      "back; bytes are reclaimed only when the quarantine is purged.")
        facts.append(f"keep: {keep}")
        options = ["approve|Approve: quarantine the copies (reversible)",
                   "reject|Reject: leave them"]
    elif p.action == "archive":
        spath = p.params.get("strata_path", "")
        title = f"awstorage #{p.id}: archive {Path(p.path).name} to cold?"
        summary = (f"Stream {p.node}:{p.path} ({gb:.2f} GB) to {spath}, read it back, then "
                   "quarantine the local copy. The object is stored PLAINTEXT at rest.")
        reversible = ("Reversible until purge: the local file sits in the quarantine; purge "
                      "happens after the TTL and a second Strata check of size + sha256.")
        facts += [f"path: {p.path}", f"strata: {spath}", "at rest: plaintext"]
        options = ["approve|Approve: archive it (plaintext at rest)",
                   "reject|Reject: keep it local"]
    elif p.action == "share":
        title = f"awstorage #{p.id}: share {p.node}:{Path(p.path).name}?"
        summary = f"Publish {p.node}:{p.path} for {p.owner}."
        reversible = "Reversible: revoking the share deletes the published objects."
        facts += [f"path: {p.path}", f"owner: {p.owner}",
                  f"sealed: {'yes' if p.params.get('seal') else 'no'}",
                  "excluded: " + ", ".join(SHARE_EXCLUDES)]
        options = ["approve|Approve: publish it", "reject|Reject: do not share"]
    else:
        raise ValueError(f"no card for action {p.action!r}")
    return {"title": title, "summary": f"{summary} {reversible}", "facts": facts,
            "options": options, "reversibility": reversible, "kind": "decision",
            "agent": "awstorage"}


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def owner_principals() -> frozenset:
    """The owner principals from ``$AWSTORAGE_MANAGE_OWNERS`` (empty when unset)."""
    raw = os.environ.get(OWNERS_ENV, "")
    return frozenset(x.strip() for x in raw.split(",") if x.strip())


def _nonce_store(catalog: Any) -> Any:
    """The catalog that records receipt nonces: the caller's, else the default one."""
    if catalog is not None:
        return catalog
    from .suggest import default_catalog_path  # noqa: PLC0415

    return default_catalog_path()


def card_decision(card: Any, proposal_id: int, *,
                  owners: Optional[Iterable[str]] = None, catalog: Any = None,
                  pubkey: Optional[str] = None, record_nonce: bool = True
                  ) -> tuple[str, str]:
    """(card id, 'approve'|'reject') for an OWNER answer naming THIS proposal; else refuse.

    The card is an `adk.decisions` DecisionCard (object or dict) read from the
    decision record. It must be answered, carry the exact fact
    ``proposal_id: <id>`` -- a title that merely starts with the id is not enough --
    and carry a SIGNED answer receipt that :func:`awstorage.attest.verify_receipt`
    accepts: the platform's Ed25519 signature (public key from
    the file named by ``$AWSTORAGE_ATTEST_PUBKEY_FILE`` or ``pubkey``)
    over this card id, this answer, these facts, an owner principal and a fresh
    interactive sign-in, with a nonce not seen on another card (recorded in
    ``catalog``; the default catalog when None). ``answered_by``/``answer_attested``
    on the card are never read as proof. ``STORE_ATTESTS_ANSWERER`` False refuses all.
    """
    from . import attest  # noqa: PLC0415

    if card is None:
        raise ApplyRefused("no decision card: manage actions are CARD-ONLY")
    cid = str(_get(card, "id") or _get(card, "card_id") or "")
    status = str(_get(card, "status") or "")
    if status != "answered":
        raise ApplyRefused(f"card {cid or '?'} is {status or 'unanswered'!s}, not answered")
    via = str(_get(card, "answered_via") or _get(card, "via") or "").strip().lower()
    if via in NON_HUMAN_VIAS - {""}:
        raise ApplyRefused(f"card {cid or '?'} was answered via {via!r}, which is never "
                           "a human")
    if not STORE_ATTESTS_ANSWERER:
        raise ApplyRefused(f"card {cid or '?'}: card approvals are switched off "
                           "(STORE_ATTESTS_ANSWERER is False); every answer is refused")
    facts = [re.sub(r"\s+", " ", str(f)).strip() for f in (_get(card, "facts") or [])]
    named = [f for f in facts if _fact_key(f) == "proposal_id"]
    if len(named) > 1:
        raise ApplyRefused(f"card {cid or '?'} carries {len(named)} 'proposal_id' facts: an "
                           "answer must name exactly one proposal")
    if named != [f"proposal_id: {int(proposal_id)}"]:
        raise ApplyRefused(f"card {cid or '?'} does not carry the fact "
                           f"'proposal_id: {int(proposal_id)}'")
    answer = str(_get(card, "answer") or "").strip().lower()
    if answer not in ("approve", "reject"):
        raise ApplyRefused(f"card {cid or '?'} was answered {answer or 'nothing'!r}")
    allowed = frozenset(owners) if owners is not None else owner_principals()
    if not allowed:
        raise ApplyRefused(f"card {cid or '?'}: no owner principal configured "
                           f"(${OWNERS_ENV}); nobody's answer approves anything")
    attest.verify_receipt(card, owners=allowed, pubkey=pubkey,
                          nonce_store=_nonce_store(catalog) if record_nonce else None,
                          record=record_nonce)
    return cid, answer


def verify_card(card: Any, proposal_id: int, *, catalog: Any = None,
                owners: Optional[Iterable[str]] = None,
                pubkey: Optional[str] = None) -> str:
    """Return the card id if `card` is a SIGNED owner `approve` of THIS proposal; else
    refuse. See :func:`card_decision`."""
    cid, answer = card_decision(card, proposal_id, owners=owners, catalog=catalog,
                                pubkey=pubkey)
    if answer != "approve":
        raise ApplyRefused(f"card {cid or '?'} was answered {answer!r}, not approve")
    return cid


# ---------------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------------

class _RefusalError(Exception):
    """A per-member refusal with a short machine reason."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def _is_link(p: Path) -> bool:
    try:
        return p.is_symlink() or bool(getattr(os.lstat(p), "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


def _replace_or_refuse(src: str, dst: str) -> None:
    """ONE os.replace. Cross-volume, a sharing violation or a permission error is a
    refusal -- there is no copy fallback anywhere in manage (A7)."""
    try:
        os.replace(src, dst)
    except PermissionError as exc:
        raise _RefusalError("locked", f"{src}: {exc}") from exc
    except OSError as exc:
        if exc.errno == errno.EXDEV or getattr(exc, "winerror", None) == 17:
            raise _RefusalError("cross-volume", f"{src}: {exc}") from exc
        if getattr(exc, "winerror", None) in (5, 32, 33):
            raise _RefusalError("locked", f"{src}: {exc}") from exc
        raise


def _quarantine_file(target: Path, roots: list[Path], pid: Optional[int], idx: int) -> str:
    """Move one file into the policy quarantine layout (ORIGIN + one payload) with a
    single same-volume os.replace."""
    root = _owning_root(target, roots)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    qdir = root / QUARANTINE_DIRNAME / f"{pid or 'adhoc'}-{idx}-{stamp}-{secrets.token_hex(3)}"
    qdir.mkdir(parents=True, exist_ok=False)
    try:
        same = os.stat(qdir).st_dev == os.stat(target, follow_symlinks=False).st_dev
    except OSError as exc:
        shutil.rmtree(qdir, ignore_errors=True)
        raise _RefusalError("locked", f"{target}: {exc}") from exc
    if not same:
        shutil.rmtree(qdir, ignore_errors=True)
        raise _RefusalError("cross-volume", f"{target} is not on the quarantine's volume")
    (qdir / "ORIGIN").write_text(str(target), encoding="utf-8")
    try:
        _replace_or_refuse(str(target), str(qdir / target.name))
    except BaseException:
        shutil.rmtree(qdir, ignore_errors=True)
        raise
    return str(qdir).replace("\\", "/")


def _check_paths(paths: Iterable[str], roots: list[Path]) -> None:
    for p in paths:
        if not _under_roots(p, roots):
            raise ApplyRefused(f"{p} is outside the declared roots {[str(r) for r in roots]}")
        if QUARANTINE_DIRNAME in Path(p).parts:
            raise ApplyRefused(f"{p} is inside a quarantine; never act on quarantined bytes")
        why = guard_refusal(p)
        if why:
            raise ApplyRefused(f"{p}: {why}; no approval overrides the guards")
        repo = git_refusal(p)
        if repo:
            raise ApplyRefused(f"{p} is inside the git tree {repo}; no approval overrides "
                               "the git refusal")


def _verify_member(m: dict, *, what: str = "member") -> Optional[str]:
    """None when the file still is what the index said; else why it drifted."""
    p = Path(str(m["path"]))
    if _is_link(p) or not p.is_file():
        return f"{what} {p} is missing, a link, or not a regular file"
    st = os.stat(p)
    if m.get("bytes") is not None and int(m["bytes"]) != st.st_size:
        return f"{what} {p} size {st.st_size} != indexed {m['bytes']}"
    if m.get("mtime_ns") is not None and int(m["mtime_ns"]) != st.st_mtime_ns:
        return f"{what} {p} mtime changed since the index"
    if m.get("sha256") and sha256_file(p) != m["sha256"]:
        return f"{what} {p} no longer matches sha256 {str(m['sha256'])[:12]}"
    return None


def _expired(p: ManageProposal) -> bool:
    exp = _parse_ts(p.expires_at)
    return exp is not None and datetime.now(timezone.utc) >= exp


def _authorize(p: ManageProposal, card: Any, catalog: Any = None) -> str:
    if p.action not in CARD_ACTIONS:
        raise ApplyRefused(f"unknown manage action {p.action!r}")
    if (p.tenant or PLATFORM_TENANT) != PLATFORM_TENANT or p.node == WORKSPACE_NODE:
        raise ApplyRefused(f"proposal {p.id} is on tenant node {p.node!r} ({p.tenant}); "
                           "manage is platform-nodes-only until decision-card recipients "
                           "land")
    if p.id is None:
        raise ApplyRefused("proposal was never submitted (no id); submit it, then card it")
    if p.status == "applied":
        raise ApplyRefused(f"proposal {p.id} is already applied")
    if p.status not in ("approved", "executing"):
        raise ApplyRefused(f"proposal {p.id} is {p.status!r}, not approved; only the card "
                           "consumer approves")
    if not p.card_id:
        raise ApplyRefused(f"proposal {p.id} records no approving card")
    if _expired(p):
        raise ApplyRefused(f"proposal {p.id} expired at {p.expires_at}; re-propose")
    cid = verify_card(card, p.id, catalog=catalog)
    if cid != str(p.card_id):
        raise ApplyRefused(f"card {cid or '?'} is not the card that approved proposal "
                           f"{p.id} ({p.card_id})")
    require_content(card, content_digest(p))
    return "card:" + cid


def _ledger_rows(catalog: Any, p: ManageProposal, out: dict) -> None:
    """One row per member plus one proposal row (path = the proposal's own path)."""
    for i, r in enumerate(out.get("results") or []):
        catalog.ledger(proposal_id=p.id, node=p.node, path=str(r.get("path", "")),
                       action=p.action, outcome=str(r.get("result", "")),
                       bytes_=int(r.get("bytes", 0) or 0),
                       detail=json.dumps({"member": r.get("member", i), **r},
                                         sort_keys=True, default=str)[:8000])
    catalog.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
                   outcome=out["outcome"], bytes_=int(out.get("bytes", 0) or 0),
                   detail=json.dumps({"members": len(out.get("results") or []),
                                      "authority": out.get("authority"),
                                      "detail": out.get("detail")}, sort_keys=True)[:8000])


def apply_manage(
    proposal: ManageProposal | int,
    *,
    catalog: Any,
    roots: list[Path | str],
    card: Any = None,
    dry_run: bool = True,
    strata_hook: Optional[StrataHook] = None,
    readback_hook: Optional[ReadbackHook] = None,
    share_hook: Optional[ShareHook] = None,
) -> dict:
    """Carry out one manage proposal, or refuse. Always writes ledger rows.

    Args:
        proposal: a submitted proposal id (reloaded from the catalog -- the row is the
            truth), or a ManageProposal built from a Genesis order on a node
            (``ManageProposal.from_order``) whose catalog is the node's own.
        catalog: the awstorage Catalog (ledger + side tables live there).
        roots: declared roots; every path touched must be under one.
        card: the decision card approving THIS proposal (CARD-ONLY, no exception).
        dry_run: default True -- read and hash, change nothing.
        strata_hook: ``hook(path, *, strata_path, sha256, size, tier) -> {"sha256"}``
            for `archive`: streams with expected size + sha256.
        readback_hook: ``hook(strata_path) -> {"sha256", "size"}`` -- an INDEPENDENT
            read of the stored object for `archive`.
        share_hook: ``hook(path, *, files, excluded, seal, owner, namespace,
            proposal_id) -> handle`` for `share`.

    Returns:
        A ledger-shaped dict: proposal_id, action, outcome, bytes, results, dry_run.
        outcome is applied | noop | dry-run | drifted.

    Raises:
        ApplyRefused: with the reason; a `refused` ledger row is written first.
    """
    store = ManageStore(catalog)
    try:
        if isinstance(proposal, ManageProposal):
            p = proposal
        else:
            p = store.load(int(proposal))
        base = {"proposal_id": p.id, "node": p.node, "path": p.path, "action": p.action,
                "dry_run": dry_run}
        try:
            result = _apply(p, store, [Path(r) for r in roots], card, dry_run,
                            strata_hook, readback_hook, share_hook)
        except ApplyRefused as exc:
            catalog.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
                           outcome="refused", bytes_=0, detail=str(exc))
            raise
        out = {**base, **result}
        _ledger_rows(catalog, p, out)
        if p.id is not None and not dry_run and not isinstance(proposal, ManageProposal):
            if out["outcome"] == "applied":
                store.set_status(p.id, "applied")
            elif out["outcome"] == "drifted":
                store.set_status(p.id, "drifted")
        return out
    finally:
        store.close()


def _apply(p: ManageProposal, store: ManageStore, roots: list[Path], card: Any,
           dry_run: bool, strata_hook: Optional[StrataHook],
           readback_hook: Optional[ReadbackHook],
           share_hook: Optional[ShareHook]) -> dict:
    authority = _authorize(p, card, store.catalog)
    if p.action in ("hardlink", "quarantine-copy"):
        return _apply_dedup(p, store, roots, dry_run, authority)
    if p.action == "archive":
        return _apply_archive(p, store, roots, dry_run, authority, strata_hook, readback_hook)
    return _apply_share(p, store, roots, dry_run, authority, share_hook)


def _apply_dedup(p: ManageProposal, store: ManageStore, roots: list[Path], dry_run: bool,
                 authority: str) -> dict:
    sha = str(p.params.get("sha256") or "")
    keep = dict(p.params.get("keep") or {})
    members = [dict(m) for m in p.members]
    if not _SHA.fullmatch(sha) or not keep.get("path") or not members:
        raise ApplyRefused("dedup proposal lacks sha256/keep/members")
    keep.setdefault("sha256", sha)
    _check_paths([str(keep["path"]), *(str(m["path"]) for m in members)], roots)
    drift = _verify_member(keep, what="keeper")
    if drift:
        return {"outcome": "drifted", "bytes": 0, "authority": authority,
                "detail": drift + "; re-scan",
                "results": [{"member": i, "path": m["path"], "result": "drifted",
                             "detail": "keeper drifted"} for i, m in enumerate(members)]}
    keeper = Path(str(keep["path"]))
    kst = os.stat(keeper)
    hard = p.action == "hardlink"
    results: list[dict] = []
    acted = 0
    reclaimed = 0
    for idx, m in enumerate(members):
        cp = Path(str(m["path"]))
        m.setdefault("sha256", sha)
        row: dict = {"member": idx, "path": str(cp)}
        try:
            if cp.exists() and os.path.samefile(cp, keeper):
                results.append({**row, "result": "already-linked"})
                continue
        except OSError as exc:
            results.append({**row, "result": "refused-locked", "detail": type(exc).__name__})
            continue
        why = _verify_member(m)
        if why:
            results.append({**row, "result": "drifted", "detail": why})
            continue
        mst = os.stat(cp)
        if hard and mst.st_dev != kst.st_dev:
            results.append({**row, "result": "refused-cross-volume"})
            continue
        counts = int(mst.st_nlink) == 1
        if dry_run:
            results.append({**row, "result": "would-hardlink" if hard else "would-quarantine",
                            "bytes": mst.st_size if counts else 0})
            continue
        try:
            if hard:
                tmp = cp.with_name(f"{cp.name}.awstorage-link-{p.id}")
                os.link(str(keeper), str(tmp))
                try:
                    entry = _quarantine_file(cp, roots, p.id, idx)
                except BaseException:
                    tmp.unlink(missing_ok=True)
                    raise
                _replace_or_refuse(str(tmp), str(cp))
                kind = "hardlink"
            else:
                entry = _quarantine_file(cp, roots, p.id, idx)
                kind = "copy"
        except _RefusalError as exc:
            results.append({**row, "result": f"refused-{exc.reason}", "detail": str(exc)})
            continue
        store.record_entry(entry=entry, pid=p.id, kind=kind, origin=str(cp),
                           keeper=str(keeper), sha256=sha)
        b = mst.st_size if counts else 0
        results.append({**row, "result": "hardlinked" if hard else "quarantined",
                        "entry": entry, "bytes": b})
        acted += 1
        reclaimed += b
    if dry_run:
        would = sum(int(r.get("bytes", 0)) for r in results if r["result"].startswith("would-"))
        return {"outcome": "dry-run", "bytes": would, "results": results,
                "authority": authority}
    if acted:
        outcome = "applied"
    elif results and all(r["result"] == "drifted" for r in results):
        outcome = "drifted"
    else:
        outcome = "noop"
    return {"outcome": outcome, "bytes": reclaimed, "results": results,
            "authority": authority,
            "detail": "bytes are reclaimed when the quarantine is purged"}


def _apply_archive(p: ManageProposal, store: ManageStore, roots: list[Path], dry_run: bool,
                   authority: str, strata_hook: Optional[StrataHook],
                   readback_hook: Optional[ReadbackHook]) -> dict:
    m = dict(p.members[0]) if p.members else {"path": p.path,
                                                "sha256": p.params.get("sha256")}
    target = Path(str(m["path"]))
    _check_paths([str(target)], roots)
    if not m.get("sha256"):
        raise ApplyRefused("archive needs the indexed sha256 (re-hashed at apply)")
    why = _verify_member(m)
    if why:
        return {"outcome": "drifted", "bytes": 0, "authority": authority, "detail": why,
                "results": [{"member": 0, "path": str(target), "result": "drifted",
                             "detail": why}]}
    sha = str(m["sha256"])
    size = target.stat().st_size
    spath = str(p.params.get("strata_path") or archive_namespace(p.node, str(target)))
    tier = str(p.params.get("tier") or "cold")
    if strata_hook is None or readback_hook is None:
        raise ApplyRefused("archive needs a Strata write hook AND an independent read-back "
                           "hook")
    if dry_run:
        return {"outcome": "dry-run", "bytes": size, "authority": authority,
                "results": [{"member": 0, "path": str(target), "result": "would-archive",
                             "strata_path": spath, "sha256": sha, "bytes": size}]}
    remote = strata_hook(target, strata_path=spath, sha256=sha, size=size, tier=tier) or {}
    if str(remote.get("sha256") or "") != sha:
        raise ApplyRefused(f"Strata did not confirm sha256 {sha[:12]} for {spath} "
                           f"(got {str(remote.get('sha256') or 'nothing')[:12]}); local kept")
    back = readback_hook(spath) or {}
    if str(back.get("sha256") or "") != sha or int(back.get("size", -1)) != size:
        raise ApplyRefused(f"read-back of {spath} did not match size+sha256; local kept")
    if sha256_file(target) != sha:
        raise ApplyRefused(f"{target} changed during upload; local kept, re-propose")
    try:
        entry = _quarantine_file(target, roots, p.id, 0)
    except _RefusalError as exc:
        return {"outcome": "noop", "bytes": 0, "authority": authority,
                "detail": "archived but the local file could not be quarantined",
                "results": [{"member": 0, "path": str(target),
                             "result": f"refused-{exc.reason}", "strata_path": spath,
                             "detail": str(exc)}]}
    store.record_entry(entry=entry, pid=p.id, kind="archive", origin=str(target),
                       keeper=spath, sha256=sha)
    return {"outcome": "applied", "bytes": size, "authority": authority,
            "results": [{"member": 0, "path": str(target), "result": "archived",
                         "strata_path": spath, "sha256": sha, "entry": entry,
                         "bytes": size}]}


def enumerate_share(path: Path | str) -> tuple[list[Path], list[str]]:
    """(files to publish, excluded names) for a share of `path`.

    Reparse-refusing: never follows a symlink or junction (and never descends into
    one); excludes .git, .env*, sensitive and never paths, and names each exclusion.
    """
    root = Path(path)
    if _is_link(root):
        raise ApplyRefused(f"{root} is a link or junction; shares never follow links")
    if root.is_file():
        return [root], []
    files: list[Path] = []
    excluded: list[str] = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError as exc:
            excluded.append(f"{d}: unreadable ({type(exc).__name__})")
            continue
        for e in entries:
            ep = Path(e.path)
            name = e.name
            if _is_link(ep):
                excluded.append(f"{ep} (link)")
                continue
            if name == ".git" or name.lower().startswith(".env"):
                excluded.append(str(ep))
                continue
            why = guard_refusal(str(ep))
            if why:
                excluded.append(f"{ep} ({why.split(' (')[0]})")
                continue
            if e.is_dir(follow_symlinks=False):
                stack.append(ep)
            elif e.is_file(follow_symlinks=False):
                files.append(ep)
    return sorted(files), excluded


def _apply_share(p: ManageProposal, store: ManageStore, roots: list[Path], dry_run: bool,
                 authority: str, share_hook: Optional[ShareHook]) -> dict:
    target = Path(p.path)
    _check_paths([p.path], roots)
    if _is_link(target) or not target.exists():
        raise ApplyRefused(f"{p.path} is missing or a link")
    want = p.params.get("sha256")
    if want and target.is_file() and sha256_file(target) != want:
        return {"outcome": "drifted", "bytes": 0, "authority": authority,
                "detail": "changed since the proposal",
                "results": [{"member": 0, "path": p.path, "result": "drifted"}]}
    files, excluded = enumerate_share(target)
    if not files:
        raise ApplyRefused(f"{p.path}: nothing shareable after exclusions ({len(excluded)})")
    if share_hook is None:
        raise ApplyRefused("share needs a share hook (e.g. local_awshare_hook)")
    seal = bool(p.params.get("seal"))
    if dry_run:
        return {"outcome": "dry-run", "bytes": 0, "authority": authority,
                "results": [{"member": 0, "path": p.path, "result": "would-share",
                             "seal": seal, "files": len(files), "excluded": excluded}]}
    handle = share_hook(target, files=files, excluded=excluded, seal=seal, owner=p.owner,
                        namespace=p.params.get("namespace"), proposal_id=p.id) or {}
    if not handle:
        raise ApplyRefused("share hook returned no handle; nothing was shared")
    store.record_share(pid=int(p.id), owner=str(p.owner), node=p.node, path=p.path,
                       handle=handle)
    return {"outcome": "applied", "bytes": 0, "authority": authority, "handle": handle,
            "results": [{"member": 0, "path": p.path, "result": "shared", "handle": handle,
                         "files": len(files), "excluded": excluded}]}


# ---------------------------------------------------------------------------------
# Revert and archive purge
# ---------------------------------------------------------------------------------

def _revert_entry(entry: str) -> str:
    """Put one quarantined file back with ONE os.replace (no copy fallback)."""
    q = Path(entry)
    origin_file = q / "ORIGIN"
    if not origin_file.is_file():
        raise ApplyRefused(f"{q} is not a quarantine entry (no ORIGIN file)")
    origin = Path(origin_file.read_text(encoding="utf-8").strip())
    payload = [c for c in q.iterdir() if c.name != "ORIGIN"]
    if len(payload) != 1:
        raise ApplyRefused(f"{q} does not hold exactly one file")
    if os.path.lexists(origin):
        raise ApplyRefused(f"origin {origin} exists again; will not overwrite it")
    origin.parent.mkdir(parents=True, exist_ok=True)
    try:
        _replace_or_refuse(str(payload[0]), str(origin))
    except _RefusalError as exc:
        raise ApplyRefused(f"revert refused ({exc.reason}): {exc}") from exc
    shutil.rmtree(q, ignore_errors=True)
    return str(origin).replace("\\", "/")


def revert_proposal(proposal_id: int, *, catalog: Any,
                    unshare_hook: Optional[UnshareHook] = None,
                    action: Optional[str] = None) -> dict:
    """Undo an applied manage proposal. Ledgered as `reverted` (or `refused`).

    On a node the proposal lives in Genesis, not the node's catalog: pass `action`
    and the quarantine/share records kept by `apply_manage` are enough."""
    store = ManageStore(catalog)
    try:
        if action is None:
            p = store.load(int(proposal_id))
        else:
            p = ManageProposal(node="", action=action, path="", id=int(proposal_id))
        node = p.node or "local"
        try:
            restored = _revert(p, store, unshare_hook)
        except ApplyRefused as exc:
            catalog.ledger(proposal_id=p.id, node=node, path=p.path, action=p.action,
                           outcome="refused", detail=f"revert: {exc}")
            raise
        catalog.ledger(proposal_id=p.id, node=node, path=p.path, action=p.action,
                       outcome="reverted", detail=json.dumps(restored)[:8000])
        return {"proposal_id": p.id, "action": p.action, "outcome": "reverted",
                "restored": restored}
    finally:
        store.close()


def _revert(p: ManageProposal, store: ManageStore,
            unshare_hook: Optional[UnshareHook]) -> list[str]:
    if p.action == "share":
        share = store.get_share(int(p.id))
        if share is None or share.get("revoked_at"):
            raise ApplyRefused(f"proposal {p.id} has no live share")
        if unshare_hook is None:
            raise ApplyRefused("reverting a share needs an unshare hook")
        unshare_hook(share["handle"])
        store.revoke_share(int(p.id))
        return [share["path"]]
    entries = store.entries(int(p.id))
    if not entries:
        raise ApplyRefused(f"proposal {p.id} has nothing in quarantine to revert")
    restored: list[str] = []
    for e in entries:
        origin = Path(e["origin"])
        if e["kind"] == "hardlink" and origin.exists():
            keeper = Path(e["keeper"] or "")
            try:
                same = keeper.exists() and os.path.samefile(origin, keeper)
            except OSError:
                same = False
            if not same:
                raise ApplyRefused(f"{origin} is no longer the hardlink we made; not touching it")
            origin.unlink()
        back = Path(_revert_entry(e["entry"]))
        if e.get("sha256") and sha256_file(back) != e["sha256"]:
            raise ApplyRefused(f"restored {back} does not match sha256 {e['sha256'][:12]}")
        store.mark_reverted(e["entry"])
        restored.append(str(back).replace("\\", "/"))
    return restored


def purge_archived(*, catalog: Any, stat_hook: ReadbackHook, ttl_days: float = 14.0,
                   dry_run: bool = True, now: Optional[float] = None) -> list[dict]:
    """Reclaim quarantined ARCHIVE entries: only past `ttl_days` AND after a second
    Strata stat confirms size + sha256 of the stored object. Anything else is kept."""
    store = ManageStore(catalog)
    out: list[dict] = []
    try:
        for e in store.entries(kind="archive"):
            at = _parse_ts(e["at"])
            age = ((now or time.time()) - at.timestamp()) / 86400.0 if at else 0.0
            row = {"entry": e["entry"], "strata_path": e["keeper"], "age_days": round(age, 2)}
            if age < ttl_days:
                out.append({**row, "outcome": "kept-ttl"})
                continue
            q = Path(e["entry"])
            payload = [c for c in q.iterdir() if c.name != "ORIGIN"] if q.is_dir() else []
            size = payload[0].stat().st_size if len(payload) == 1 else -1
            try:
                st = stat_hook(str(e["keeper"])) or {}
            except Exception as exc:  # noqa: BLE001 -- a failed stat keeps the bytes
                out.append({**row, "outcome": "kept-stat-failed", "detail": str(exc)[:200]})
                continue
            if str(st.get("sha256") or "") != e["sha256"] or int(st.get("size", -2)) != size:
                out.append({**row, "outcome": "kept-stat-mismatch"})
                continue
            if dry_run:
                out.append({**row, "outcome": "would-purge", "bytes": size})
                continue
            shutil.rmtree(q)
            store.mark_reverted(e["entry"], how="purged")
            catalog.ledger(proposal_id=e["proposal_id"], node="local", path=e["origin"],
                           action="archive", outcome="purged", bytes_=size,
                           detail=json.dumps(row))
            out.append({**row, "outcome": "purged", "bytes": size})
    finally:
        store.close()
    return out


# ---------------------------------------------------------------------------------
# The in-package share hook: awshare bundle into a local/mounted directory
# ---------------------------------------------------------------------------------

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def local_awshare_hook(out_root: Path | str) -> tuple[ShareHook, UnshareHook]:
    """(share, unshare) hooks that publish into `<out_root>/<owner>/<name>-<pid>/`.

    Only the enumerated files are staged (never a tree copy that would follow links
    or pick up excluded names); `publish(seal=True)` writes the seal INTO the dir it
    seals, and a share must never modify the thing shared. Transport (Strata
    namespace, Aither Share) is the platform's hook.
    """
    base = Path(out_root)

    def share(path: Path, *, files: Optional[list] = None, excluded: Optional[list] = None,
              seal: bool, owner: Optional[str], namespace: Optional[str],
              proposal_id: Optional[int]) -> dict:
        try:
            import awshare  # noqa: PLC0415 -- optional sibling brick
        except ImportError as exc:
            raise ApplyRefused("share needs the `awshare` package") from exc
        path = Path(path)
        name = _SAFE.sub("_", path.name) or "share"
        out_dir = base / _SAFE.sub("_", owner or "anon") / f"{name}-{proposal_id or 'adhoc'}"
        chosen = [Path(f) for f in (files if files is not None else enumerate_share(path)[0])]
        with tempfile.TemporaryDirectory(prefix="awstorage-share-") as td:
            stage = Path(td) / name
            stage.mkdir()
            src_root = path if path.is_dir() else path.parent
            for f in chosen:
                dest = stage / f.relative_to(src_root)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest, follow_symlinks=False)
            m = awshare.publish(stage, out_dir, name=name, seal=seal,
                                meta={"owner": owner, "namespace": namespace,
                                      "proposal_id": proposal_id})
        return {"kind": "awshare-local", "out_dir": str(out_dir).replace("\\", "/"),
                "manifest": str(out_dir / f"{name}{awshare.MANIFEST_SUFFIX}").replace("\\", "/"),
                "name": m.name, "digest": m.digest, "size": m.size, "sealed": m.sealed,
                "files": len(m.files), "excluded": list(excluded or [])}

    def unshare(handle: dict) -> None:
        out_dir = Path(str(handle.get("out_dir") or ""))
        try:
            out_dir.resolve().relative_to(base.resolve())
        except ValueError as exc:
            raise ApplyRefused(f"{out_dir} is not under the share root {base}") from exc
        shutil.rmtree(out_dir, ignore_errors=True)

    return share, unshare


# ---------------------------------------------------------------------------------
# CLI: python -m awstorage.manage revert|shares
#
# There is no `apply` here: a card read from a FILE is a caller-supplied dict, not a
# decision record. Apply runs only in node_run, with the order and its card fetched
# from Genesis, on a proposal the card consumer already approved.
# ---------------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    """Node-side entry: revert a proposal, list shares (apply is node_run only)."""
    import argparse  # noqa: PLC0415

    from .catalog import Catalog  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog="awstorage.manage")
    ap.add_argument("--db", required=True, help="awstorage catalog path")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("revert")
    r.add_argument("proposal_id", type=int)
    r.add_argument("--share-out")
    s = sub.add_parser("shares")
    s.add_argument("--owner")
    args = ap.parse_args(argv)
    cat = Catalog(args.db)
    try:
        if args.cmd == "shares":
            with ManageStore(cat) as st:
                print(json.dumps(st.list_shares(args.owner), indent=2))
            return 0
        unshare = None
        if getattr(args, "share_out", None):
            _, unshare = local_awshare_hook(args.share_out)
        try:
            out = revert_proposal(args.proposal_id, catalog=cat, unshare_hook=unshare)
        except ApplyRefused as exc:
            print(json.dumps({"outcome": "refused", "reason": str(exc)}))
            return 1
        print(json.dumps(out, indent=2))
        return 0
    finally:
        cat.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
