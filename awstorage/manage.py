"""Manage + share: dedup, archive-to-cold and share proposals over indexed files.

Four action classes ride the SAME pipeline as every other awstorage change --
propose -> decision card -> apply -> ledger -> revert -- and add nothing that can
act on its own:

    dedup.hardlink            replace a byte-identical copy with a hardlink to the
                              keeper (same volume only); the copy is quarantined
    dedup.quarantine_copies   quarantine every copy but the keeper
    archive.to_strata_cold    upload a file to a cold tier through a caller-supplied
                              hook that VERIFIES the remote sha256, then quarantine
                              the local file
    share.awshare             publish a path as an awshare bundle through a
                              caller-supplied hook; the handle is recorded

Rules every action obeys, each pinned by a test:

* **Dry-run is the default.** ``apply_manage(..., dry_run=True)`` reads and hashes,
  never writes outside the catalog.
* **CARD-ONLY approval.** An action runs only with a decision card whose answer is
  ``approve``, which names THIS proposal id, and which a human answered (a card
  answered via ``agent`` or closed by its ``deadline`` is not an approval). The one
  exception is ``share.awshare`` of the caller's OWN workspace files, where the
  caller is the owner and the platform derived that owner from the authenticated
  session -- never from a payload.
* **Re-verify before acting.** sha256 of the keeper and of every copy is recomputed
  at apply time; a file that no longer matches is skipped (``drifted``), a keeper
  that no longer matches refuses the whole proposal.
* **Reversible.** Nothing is deleted. Copies and archived files move into the same
  ``<root>/.awstorage-quarantine/`` layout ``policy.revert`` and
  ``policy.purge_quarantine`` already understand; ``revert_proposal`` puts them back
  (removing the hardlink first) and re-checks the restored bytes. A share is
  reverted through its unshare hook.
* **Ledgered.** Every apply writes a ledger row -- applied, dry-run, noop or refused.

The package stays stdlib-only and speaks to nothing: Strata upload and awshare
publish are HOOKS. ``local_awshare_hook`` is the one in-package hook, and it
imports awshare lazily.

Proposal parameters that do not fit the catalog's ``proposals`` row (keeper,
copies, sha256, strata path, owner) live in a side table in the same SQLite file;
the catalog schema itself is not changed.
"""

from __future__ import annotations

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .policy import QUARANTINE_DIRNAME, ApplyRefused, _owning_root, _under_roots
from .policy import revert as _revert_entry

MANAGE_ACTIONS: dict[str, str] = {
    "dedup.hardlink": "dedup",
    "dedup.quarantine_copies": "dedup",
    "archive.to_strata_cold": "archive",
    "share.awshare": "share",
}

#: `answered_via` values that are NOT a human answering: the agent that raised the
#: card closing it itself, or the store applying the declared default at deadline.
NON_HUMAN_VIAS = frozenset({"agent", "deadline", "timeout", "expired", "steerback", ""})

_SIDE_DDL = """
CREATE TABLE IF NOT EXISTS manage_params (
  proposal_id INTEGER PRIMARY KEY,
  action TEXT NOT NULL,
  params TEXT NOT NULL,
  owner TEXT,
  created_at TEXT NOT NULL
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
"""

ShareHook = Callable[..., dict]
UnshareHook = Callable[[dict], None]
StrataHook = Callable[..., dict]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
# Proposal model + side-table store
# ---------------------------------------------------------------------------------

@dataclass
class ManageProposal:
    """One manage/share action. `path` is the primary path (the first copy, the file
    to archive, the path to share); everything else is in `params`."""

    node: str
    action: str
    path: str
    bytes: int = 0
    params: dict = field(default_factory=dict)
    owner: Optional[str] = None
    status: str = "proposed"
    note: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> dict:
        return {"id": self.id, "node": self.node, "action": self.action, "path": self.path,
                "bytes": self.bytes, "params": dict(self.params), "owner": self.owner,
                "status": self.status, "note": self.note}


class ManageStore:
    """Side tables next to a Catalog. Opens its own connection to the same file."""

    def __init__(self, catalog: Any) -> None:
        self.catalog = catalog
        self._db = sqlite3.connect(str(catalog.path))
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SIDE_DDL)

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
            if p.action not in MANAGE_ACTIONS:
                raise ValueError(f"unknown manage action {p.action!r}")
            [pid] = self.catalog.put_proposals([{
                "node": p.node, "path": p.path, "action": p.action, "bytes": int(p.bytes),
                "cls": MANAGE_ACTIONS[p.action], "policy_rule": f"manage:{p.action}",
                "auto": False, "status": p.status, "note": p.note,
            }])
            with self._db:
                self._db.execute(
                    "INSERT INTO manage_params(proposal_id, action, params, owner, created_at)"
                    " VALUES (?,?,?,?,?)",
                    (pid, p.action, json.dumps(p.params, sort_keys=True), p.owner, _now()))
            p.id = pid
            ids.append(pid)
        return ids

    def load(self, pid: int) -> ManageProposal:
        row = self.catalog.get_proposal(int(pid))
        if row is None:
            raise ApplyRefused(f"no proposal {pid}")
        side = self._db.execute("SELECT * FROM manage_params WHERE proposal_id = ?",
                                (int(pid),)).fetchone()
        if side is None or row["action"] not in MANAGE_ACTIONS:
            raise ApplyRefused(f"proposal {pid} is not a manage proposal")
        return ManageProposal(node=row["node"], action=row["action"], path=row["path"],
                              bytes=int(row["bytes"]), params=json.loads(side["params"]),
                              owner=side["owner"], status=row["status"], note=row["note"],
                              id=int(pid))

    # -- quarantine entries -------------------------------------------------------

    def record_entry(self, *, entry: str, pid: Optional[int], kind: str, origin: str,
                     keeper: Optional[str], sha256: Optional[str]) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO manage_quarantine(entry, proposal_id, kind, origin, keeper, sha256,"
                " at) VALUES (?,?,?,?,?,?,?)",
                (entry, pid, kind, origin, keeper, sha256, _now()))

    def entries(self, pid: int, *, include_reverted: bool = False) -> list[dict]:
        q = "SELECT * FROM manage_quarantine WHERE proposal_id = ?"
        if not include_reverted:
            q += " AND reverted_at IS NULL"
        return [dict(r) for r in self._db.execute(q + " ORDER BY entry", (int(pid),))]

    def mark_reverted(self, entry: str) -> None:
        with self._db:
            self._db.execute("UPDATE manage_quarantine SET reverted_at = ? WHERE entry = ?",
                             (_now(), entry))

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

def _keeper_key(path: str) -> tuple:
    # Deterministic: the shortest path is usually the "original" (not a nested copy),
    # ties broken lexically so two runs over the same group pick the same keeper.
    return (len(path), path)


def propose_dedup(groups: Iterable[dict], *, node: str,
                  action: str = "dedup.quarantine_copies",
                  min_size: int = 1) -> list[ManageProposal]:
    """One proposal per duplicate group on `node`.

    `groups` is the `files dupes` shape: ``{sha256, size, paths: [{node, path}] | [str]}``.
    Paths on other nodes are ignored (a hardlink or quarantine is node-local).
    """
    if action not in ("dedup.hardlink", "dedup.quarantine_copies"):
        raise ValueError(f"not a dedup action: {action!r}")
    out: list[ManageProposal] = []
    for g in groups:
        sha = str(g.get("sha256") or "")
        size = int(g.get("size") or 0)
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or size < max(1, min_size):
            continue
        paths = []
        for p in g.get("paths") or []:
            if isinstance(p, dict):
                if p.get("node", node) != node:
                    continue
                paths.append(str(p["path"]))
            else:
                paths.append(str(p))
        paths = sorted(set(paths), key=_keeper_key)
        if len(paths) < 2:
            continue
        keeper, copies = paths[0], paths[1:]
        verb = "hardlink to" if action == "dedup.hardlink" else "quarantine, keeping"
        out.append(ManageProposal(
            node=node, action=action, path=copies[0], bytes=size * len(copies),
            params={"sha256": sha, "size": size, "keeper": keeper, "copies": copies},
            note=f"{len(copies)} byte-identical copies; {verb} {keeper} [needs approval]",
        ))
    out.sort(key=lambda x: -x.bytes)
    return out


def propose_archive(node: str, path: str, *, strata_path: str, bytes_: int = 0,
                    sha256: Optional[str] = None, tier: str = "cold") -> ManageProposal:
    """Upload one file to a cold Strata tier, then quarantine the local copy."""
    if not strata_path:
        raise ValueError("strata_path is required")
    return ManageProposal(
        node=node, action="archive.to_strata_cold", path=path, bytes=int(bytes_),
        params={"strata_path": strata_path, "tier": tier, "sha256": sha256},
        note=f"upload to {strata_path} ({tier}), verify sha256, then quarantine local "
             "[needs approval]")


def propose_share(node: str, path: str, *, owner: str, seal: bool = False,
                  namespace: Optional[str] = None, bytes_: int = 0,
                  sha256: Optional[str] = None) -> ManageProposal:
    """Publish `path` as an awshare bundle. `owner` MUST come from the authenticated
    caller -- the router derives it; nothing here trusts a payload for it."""
    if not owner:
        raise ValueError("owner is required (derive it from the authenticated caller)")
    return ManageProposal(
        node=node, action="share.awshare", path=path, bytes=int(bytes_), owner=owner,
        params={"seal": bool(seal), "namespace": namespace, "sha256": sha256},
        note=f"publish as an awshare bundle for {owner}" + (" (sealed)" if seal else ""))


# ---------------------------------------------------------------------------------
# Card-only approval
# ---------------------------------------------------------------------------------

def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def card_facts(proposal_id: int) -> list[str]:
    """The fact line a card MUST carry to approve `proposal_id` (plus a readable id)."""
    return [f"proposal_id: {int(proposal_id)}"]


def verify_card(card: Any, proposal_id: int) -> str:
    """Return the card id if `card` is a HUMAN `approve` of THIS proposal; else refuse.

    The card is a `adk.decisions` DecisionCard (object or dict). An approve for a
    different proposal is not an approve; a card answered via `agent` or closed by
    its deadline default is not a human answer.
    """
    if card is None:
        raise ApplyRefused("no decision card: manage actions are CARD-ONLY")
    cid = str(_get(card, "id") or _get(card, "card_id") or "")
    status = str(_get(card, "status") or "")
    if status != "answered":
        raise ApplyRefused(f"card {cid or '?'} is {status or 'unanswered'!s}, not answered")
    answer = str(_get(card, "answer") or "").strip().lower()
    if answer != "approve":
        raise ApplyRefused(f"card {cid or '?'} was answered {answer or 'nothing'!r}, not approve")
    via = str(_get(card, "answered_via") or "").strip().lower()
    if via in NON_HUMAN_VIAS or via.startswith("agent"):
        raise ApplyRefused(f"card {cid or '?'} was answered via {via or 'unknown'!r}; "
                           "only a human answer approves")
    pid = int(proposal_id)
    facts = [str(f).strip() for f in (_get(card, "facts") or [])]
    title = str(_get(card, "title") or "")
    rvars = _get(card, "recipe_vars") or {}
    named = (f"proposal_id: {pid}" in facts
             or re.match(rf"^awstorage #{pid}(?!\d)", title) is not None
             or str(rvars.get("proposal_id", "")) == str(pid))
    if not named:
        raise ApplyRefused(f"card {cid or '?'} does not name proposal {pid}")
    return cid


# ---------------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------------

def _is_link(p: Path) -> bool:
    try:
        return p.is_symlink() or bool(getattr(os.lstat(p), "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


def _quarantine_file(target: Path, roots: list[Path], pid: Optional[int], idx: int) -> str:
    """Move one file into the policy quarantine layout (ORIGIN + one payload)."""
    root = _owning_root(target, roots)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    qdir = root / QUARANTINE_DIRNAME / f"{pid or 'adhoc'}-{idx}-{stamp}-{secrets.token_hex(3)}"
    qdir.mkdir(parents=True, exist_ok=False)
    (qdir / "ORIGIN").write_text(str(target), encoding="utf-8")
    dest = qdir / target.name
    try:
        os.replace(str(target), str(dest))
    except OSError:
        shutil.move(str(target), str(dest))
    return str(qdir).replace("\\", "/")


def _check_paths(paths: Iterable[str], roots: list[Path]) -> None:
    for p in paths:
        if not _under_roots(p, roots):
            raise ApplyRefused(f"{p} is outside the declared roots {[str(r) for r in roots]}")
        if QUARANTINE_DIRNAME in Path(p).parts:
            raise ApplyRefused(f"{p} is inside a quarantine; never act on quarantined bytes")


def apply_manage(
    proposal: ManageProposal | int,
    *,
    catalog: Any,
    roots: list[Path | str],
    card: Any = None,
    self_service_owner: Optional[str] = None,
    dry_run: bool = True,
    strata_hook: Optional[StrataHook] = None,
    share_hook: Optional[ShareHook] = None,
) -> dict:
    """Carry out one manage proposal, or refuse. Always writes a ledger row.

    Args:
        proposal: a submitted ManageProposal or its id.
        catalog: the awstorage Catalog (ledger + proposals live there).
        roots: declared roots; every path touched must be under one.
        card: the decision card approving THIS proposal (CARD-ONLY).
        self_service_owner: the AUTHENTICATED caller's owner id. Accepted in place of a
            card for `share.awshare` of a proposal that caller owns, nothing else.
        dry_run: default True -- read and hash, change nothing.
        strata_hook: ``hook(path, *, strata_path, sha256, size, tier) -> {"sha256": ...}``
            for archive.to_strata_cold; must return the sha256 Strata verified.
        share_hook: ``hook(path, *, seal, owner, namespace, proposal_id) -> handle``.

    Returns:
        A ledger-shaped dict: proposal_id, action, outcome, bytes, results, dry_run.

    Raises:
        ApplyRefused: with the reason; a `refused` ledger row is written first.
    """
    store = ManageStore(catalog)
    try:
        p = proposal if isinstance(proposal, ManageProposal) else store.load(int(proposal))
        if p.id is not None and not isinstance(proposal, int):
            # A caller-held object may be stale; the catalog row is the truth.
            p = store.load(p.id)
        base = {"proposal_id": p.id, "node": p.node, "path": p.path, "action": p.action,
                "dry_run": dry_run}
        try:
            result = _apply(p, store, [Path(r) for r in roots], card, self_service_owner,
                            dry_run, strata_hook, share_hook)
        except ApplyRefused as exc:
            catalog.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
                           outcome="refused", bytes_=0, detail=str(exc))
            raise
        out = {**base, **result}
        catalog.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
                       outcome=out["outcome"], bytes_=int(out.get("bytes", 0)),
                       detail=json.dumps(out.get("results", []), sort_keys=True)[:8000])
        if out["outcome"] == "applied" and p.id is not None:
            catalog.set_status(p.id, "applied")
        return out
    finally:
        store.close()


def _authorize(p: ManageProposal, card: Any, self_service_owner: Optional[str]) -> str:
    if p.action not in MANAGE_ACTIONS:
        raise ApplyRefused(f"unknown manage action {p.action!r}")
    if p.id is None:
        raise ApplyRefused("proposal was never submitted (no id); submit it, then card it")
    if p.status == "applied":
        raise ApplyRefused(f"proposal {p.id} is already applied")
    if p.status not in ("proposed", "approved"):
        raise ApplyRefused(f"proposal {p.id} is {p.status!r}")
    if self_service_owner is not None:
        if p.action != "share.awshare":
            raise ApplyRefused("self-service approval covers share.awshare only")
        if not p.owner or p.owner != self_service_owner:
            raise ApplyRefused("self-service share: the caller does not own this proposal")
        return f"self-service:{self_service_owner}"
    return "card:" + verify_card(card, p.id)


def _apply(p: ManageProposal, store: ManageStore, roots: list[Path], card: Any,
           self_service_owner: Optional[str], dry_run: bool,
           strata_hook: Optional[StrataHook], share_hook: Optional[ShareHook]) -> dict:
    authority = _authorize(p, card, self_service_owner)
    if p.action in ("dedup.hardlink", "dedup.quarantine_copies"):
        return _apply_dedup(p, store, roots, dry_run, authority)
    if p.action == "archive.to_strata_cold":
        return _apply_archive(p, store, roots, dry_run, authority, strata_hook)
    return _apply_share(p, store, roots, dry_run, authority, share_hook)


def _apply_dedup(p: ManageProposal, store: ManageStore, roots: list[Path], dry_run: bool,
                 authority: str) -> dict:
    sha = str(p.params.get("sha256") or "")
    keeper = Path(str(p.params.get("keeper") or ""))
    copies = [str(c) for c in p.params.get("copies") or []]
    if not sha or not str(keeper) or not copies:
        raise ApplyRefused("dedup proposal lacks sha256/keeper/copies")
    _check_paths([str(keeper), *copies], roots)
    if not keeper.is_file() or _is_link(keeper):
        raise ApplyRefused(f"keeper {keeper} is missing or not a regular file")
    if sha256_file(keeper) != sha:
        raise ApplyRefused(f"keeper {keeper} no longer matches sha256 {sha[:12]}; re-scan")
    kst = os.stat(keeper)
    hard = p.action == "dedup.hardlink"
    results: list[dict] = []
    acted = 0
    size = int(p.params.get("size") or kst.st_size)
    for idx, c in enumerate(copies):
        cp = Path(c)
        if not cp.is_file() or _is_link(cp):
            results.append({"path": c, "result": "missing"})
            continue
        try:
            linked = os.path.samefile(cp, keeper)
        except OSError as exc:
            results.append({"path": c, "result": "unreadable", "error": type(exc).__name__})
            continue
        if linked:
            results.append({"path": c, "result": "already-linked"})
            continue
        if sha256_file(cp) != sha:
            results.append({"path": c, "result": "drifted"})
            continue
        if hard and os.stat(cp).st_dev != kst.st_dev:
            results.append({"path": c, "result": "cross-volume"})
            continue
        if dry_run:
            results.append({"path": c, "result": "would-hardlink" if hard else "would-quarantine"})
            continue
        if hard:
            tmp = cp.with_name(f"{cp.name}.awstorage-link-{p.id}")
            os.link(str(keeper), str(tmp))
            try:
                entry = _quarantine_file(cp, roots, p.id, idx)
            except Exception:
                tmp.unlink(missing_ok=True)
                raise
            os.replace(str(tmp), str(cp))
            kind = "hardlink"
        else:
            entry = _quarantine_file(cp, roots, p.id, idx)
            kind = "copy"
        store.record_entry(entry=entry, pid=p.id, kind=kind, origin=str(cp),
                           keeper=str(keeper), sha256=sha)
        results.append({"path": c, "result": "hardlinked" if hard else "quarantined",
                        "entry": entry})
        acted += 1
    if dry_run:
        would = sum(1 for r in results if r["result"].startswith("would-"))
        return {"outcome": "dry-run", "bytes": size * would, "results": results,
                "authority": authority}
    return {"outcome": "applied" if acted else "noop", "bytes": size * acted,
            "results": results, "authority": authority,
            "detail": "bytes are reclaimed when the quarantine is purged"}


def _apply_archive(p: ManageProposal, store: ManageStore, roots: list[Path], dry_run: bool,
                   authority: str, strata_hook: Optional[StrataHook]) -> dict:
    target = Path(p.path)
    _check_paths([p.path], roots)
    if _is_link(target) or not target.is_file():
        raise ApplyRefused(f"{p.path} is not a regular file (archive handles files only)")
    sha = sha256_file(target)
    want = p.params.get("sha256")
    if want and want != sha:
        raise ApplyRefused(f"{p.path} changed since the proposal (sha256 {want[:12]} -> "
                           f"{sha[:12]}); re-scan")
    size = target.stat().st_size
    spath = str(p.params.get("strata_path") or "")
    tier = str(p.params.get("tier") or "cold")
    if strata_hook is None:
        raise ApplyRefused("archive.to_strata_cold needs a Strata hook that verifies sha256")
    if dry_run:
        return {"outcome": "dry-run", "bytes": size, "authority": authority,
                "results": [{"path": p.path, "result": "would-archive", "strata_path": spath,
                             "tier": tier, "sha256": sha}]}
    remote = strata_hook(target, strata_path=spath, sha256=sha, size=size, tier=tier) or {}
    if str(remote.get("sha256") or "") != sha:
        raise ApplyRefused(f"Strata did not confirm sha256 {sha[:12]} for {spath} "
                           f"(got {str(remote.get('sha256') or 'nothing')[:12]}); local kept")
    if sha256_file(target) != sha:
        raise ApplyRefused(f"{p.path} changed during upload; local kept, re-propose")
    entry = _quarantine_file(target, roots, p.id, 0)
    store.record_entry(entry=entry, pid=p.id, kind="archive", origin=str(target),
                       keeper=spath, sha256=sha)
    return {"outcome": "applied", "bytes": size, "authority": authority,
            "results": [{"path": p.path, "result": "archived", "strata_path": spath,
                         "tier": tier, "sha256": sha, "entry": entry}]}


def _apply_share(p: ManageProposal, store: ManageStore, roots: list[Path], dry_run: bool,
                 authority: str, share_hook: Optional[ShareHook]) -> dict:
    target = Path(p.path)
    _check_paths([p.path], roots)
    if _is_link(target) or not target.exists():
        raise ApplyRefused(f"{p.path} is missing or a link")
    want = p.params.get("sha256")
    if want and target.is_file() and sha256_file(target) != want:
        raise ApplyRefused(f"{p.path} changed since the proposal; re-propose")
    if share_hook is None:
        raise ApplyRefused("share.awshare needs a share hook (e.g. local_awshare_hook)")
    seal = bool(p.params.get("seal"))
    if dry_run:
        return {"outcome": "dry-run", "bytes": 0, "authority": authority,
                "results": [{"path": p.path, "result": "would-share", "seal": seal,
                             "owner": p.owner}]}
    handle = share_hook(target, seal=seal, owner=p.owner,
                        namespace=p.params.get("namespace"), proposal_id=p.id) or {}
    if not handle:
        raise ApplyRefused("share hook returned no handle; nothing was shared")
    store.record_share(pid=int(p.id), owner=str(p.owner), node=p.node, path=p.path,
                       handle=handle)
    return {"outcome": "applied", "bytes": 0, "authority": authority, "handle": handle,
            "results": [{"path": p.path, "result": "shared", "handle": handle}]}


# ---------------------------------------------------------------------------------
# Revert
# ---------------------------------------------------------------------------------

def revert_proposal(proposal_id: int, *, catalog: Any,
                    unshare_hook: Optional[UnshareHook] = None) -> dict:
    """Undo an applied manage proposal. Ledgered as `reverted` (or `refused`)."""
    store = ManageStore(catalog)
    try:
        p = store.load(int(proposal_id))
        try:
            restored = _revert(p, store, unshare_hook)
        except ApplyRefused as exc:
            catalog.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
                           outcome="refused", detail=f"revert: {exc}")
            raise
        catalog.ledger(proposal_id=p.id, node=p.node, path=p.path, action=p.action,
                       outcome="reverted", detail=json.dumps(restored)[:8000])
        return {"proposal_id": p.id, "action": p.action, "outcome": "reverted",
                "restored": restored}
    finally:
        store.close()


def _revert(p: ManageProposal, store: ManageStore,
            unshare_hook: Optional[UnshareHook]) -> list[str]:
    if p.action == "share.awshare":
        share = store.get_share(int(p.id))
        if share is None or share.get("revoked_at"):
            raise ApplyRefused(f"proposal {p.id} has no live share")
        if unshare_hook is None:
            raise ApplyRefused("reverting a share needs an unshare hook")
        unshare_hook(share["handle"])
        store.revoke_share(int(p.id))
        return [p.path]
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


# ---------------------------------------------------------------------------------
# The in-package share hook: awshare bundle into a local/mounted directory
# ---------------------------------------------------------------------------------

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def local_awshare_hook(out_root: Path | str) -> tuple[ShareHook, UnshareHook]:
    """(share, unshare) hooks that publish into `<out_root>/<owner>/<name>-<pid>/`.

    The source is COPIED into a staging dir first: `publish(seal=True)` writes the
    seal INTO the directory it seals, and a share must never modify the thing
    shared. Transport (Strata namespace, object store) is the platform's hook.
    """
    base = Path(out_root)

    def share(path: Path, *, seal: bool, owner: Optional[str], namespace: Optional[str],
              proposal_id: Optional[int]) -> dict:
        try:
            import awshare  # noqa: PLC0415 -- optional sibling brick
        except ImportError as exc:
            raise ApplyRefused("share.awshare needs the `awshare` package") from exc
        name = _SAFE.sub("_", path.name) or "share"
        out_dir = base / _SAFE.sub("_", owner or "anon") / f"{name}-{proposal_id or 'adhoc'}"
        with tempfile.TemporaryDirectory(prefix="awstorage-share-") as td:
            stage = Path(td) / name
            if path.is_dir():
                shutil.copytree(path, stage, symlinks=True)
            else:
                stage.mkdir()
                shutil.copy2(path, stage / path.name)
            m = awshare.publish(stage, out_dir, name=name, seal=seal,
                                meta={"owner": owner, "namespace": namespace,
                                      "proposal_id": proposal_id})
        return {"kind": "awshare-local", "out_dir": str(out_dir).replace("\\", "/"),
                "manifest": str(out_dir / f"{name}{awshare.MANIFEST_SUFFIX}").replace("\\", "/"),
                "name": m.name, "digest": m.digest, "size": m.size, "sealed": m.sealed,
                "files": len(m.files)}

    def unshare(handle: dict) -> None:
        out_dir = Path(str(handle.get("out_dir") or ""))
        try:
            out_dir.resolve().relative_to(base.resolve())
        except ValueError as exc:
            raise ApplyRefused(f"{out_dir} is not under the share root {base}") from exc
        shutil.rmtree(out_dir, ignore_errors=True)

    return share, unshare


# ---------------------------------------------------------------------------------
# CLI: python -m awstorage.manage apply|revert|shares
# ---------------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    """Node-side entry: apply a carded proposal, revert one, list shares."""
    import argparse  # noqa: PLC0415

    from .catalog import Catalog  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog="awstorage.manage")
    ap.add_argument("--db", required=True, help="awstorage catalog path")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("apply")
    a.add_argument("proposal_id", type=int)
    a.add_argument("--root", action="append", required=True)
    a.add_argument("--card", required=True, help="decision card JSON file")
    a.add_argument("--yes", action="store_true", help="execute (default: dry-run)")
    a.add_argument("--share-out", help="local awshare output root for share.awshare")
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
        share = unshare = None
        if getattr(args, "share_out", None):
            share, unshare = local_awshare_hook(args.share_out)
        try:
            if args.cmd == "apply":
                card = json.loads(Path(args.card).read_text(encoding="utf-8"))
                out = apply_manage(args.proposal_id, catalog=cat, roots=args.root, card=card,
                                   dry_run=not args.yes, share_hook=share)
            else:
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
