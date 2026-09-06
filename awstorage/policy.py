"""Proposals and the apply gate.

A POLICY is data: a list of rules, each naming a class, an action, and the
thresholds under which the action is PRE-APPROVED (no human needed). Anything a
rule does not pre-approve is still proposed -- as `auto=False`, so a person (or
a decision card upstream) has to flip it to `approved` before `apply` will act.

`apply` refuses -- and ledgers the refusal -- when:
  * the path is not under one of the declared `roots` (a scan of E:/ can never
    produce a delete on C:/),
  * the tree's fingerprint changed since the scan (something wrote to it; the
    proposal is stale),
  * the class is in NEVER_AUTO (service-state, dataset, vm-disk) and the
    proposal is not human-approved,
  * the proposal is not `auto` and not `approved`.

Dry-run is the default. `--yes` is a flag on the CLI, `dry_run=False` here.
"""

from __future__ import annotations

import os
import shutil
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ._fs import fingerprint

NEVER_AUTO = frozenset({"service-state", "dataset", "vm-disk", "backup", "unknown"})
ACTIONS = ("delete", "compress", "backup-then-delete", "review", "prune-engine")


class ApplyRefusedError(Exception):
    """apply() declined to act; the reason is the message and is ledgered."""


# The public name. Short on purpose: a refusal is the tool's normal answer, not
# an error condition, and every caller spells it.
ApplyRefused = ApplyRefusedError


@dataclass
class Proposal:
    node: str
    path: str
    action: str
    bytes: int
    cls: str
    policy_rule: str | None = None
    auto: bool = False
    status: str = "proposed"
    fingerprint: str | None = None
    snapshot_id: int | None = None
    note: str | None = None
    id: int | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("extra", None)
        return d


def default_policy() -> dict:
    """The shipped policy: conservative, and every threshold has a reason."""
    return {
        "version": 1,
        "rules": [
            {"id": "build-temp-3d", "cls": "build-temp", "action": "delete", "auto": True,
             "min_bytes": 512 * 2**20, "older_than_days": 3,
             "why": "build outputs older than the longest build we run are dead weight"},
            {"id": "package-cache-14d", "cls": "package-cache", "action": "delete", "auto": True,
             "min_bytes": 1 * 2**30, "older_than_days": 14,
             "why": "caches refill on the next install; two weeks unused is unused"},
            {"id": "logs-30d", "cls": "logs", "action": "compress", "auto": False,
             "min_bytes": 1 * 2**30, "older_than_days": 30,
             "why": "logs are evidence; compress, never auto-delete"},
            {"id": "container-store", "cls": "container-store", "action": "prune-engine",
             "auto": False, "min_bytes": 5 * 2**30,
             "why": "engine storage is pruned through the engine (dangling only), never rm"},
            {"id": "model-weights-review", "cls": "model-weights", "action": "review",
             "auto": False, "min_bytes": 5 * 2**30,
             "why": "weights are re-fetchable but expensive; a human confirms a mirror holds them"},
            {"id": "repo-review", "cls": "repo", "action": "review", "auto": False,
             "min_bytes": 2 * 2**30, "older_than_days": 60,
             "why": "a clone is cheap; uncommitted work in it is not -- always a human"},
            {"id": "media-review", "cls": "media", "action": "backup-then-delete", "auto": False,
             "min_bytes": 5 * 2**30, "older_than_days": 90,
             "why": "renders are outputs; snapshot before reclaiming"},
        ],
    }


def _age_days(newest_mtime: float, now: float | None = None) -> float:
    if not newest_mtime:
        return 0.0
    return max(0.0, ((now or time.time()) - newest_mtime) / 86400.0)


def propose(snapshot: dict, policy: dict | None = None, *, now: float | None = None,
            snapshot_id: int | None = None) -> list[Proposal]:
    """Match every classified tree against the policy; deepest match wins per path.

    Parents and children can both match (aggregate bytes), so a proposal is only
    emitted for the SHALLOWEST tree whose descendants do not carry a matching
    rule themselves -- otherwise deleting `caches/` and `caches/pip/` would be two
    proposals for the same bytes.
    """
    pol = policy or default_policy()
    rules = pol.get("rules", [])
    trees = snapshot.get("trees", [])
    if not any("cls" in t for t in trees):
        raise ValueError("snapshot is not classified; call classify_snapshot() first")
    matched: dict[str, tuple[dict, dict]] = {}
    for t in trees:
        if t["depth"] == 0:
            continue
        for r in rules:
            if r["cls"] != t.get("cls"):
                continue
            if t["bytes"] < int(r.get("min_bytes", 0)):
                continue
            age = _age_days(t.get("newest_mtime", 0.0), now)
            if "older_than_days" in r and age < r["older_than_days"]:
                continue
            matched[t["path"]] = (t, r)
            break
    # Collapse nested matches onto the shallowest path.
    paths = sorted(matched, key=lambda p: (matched[p][0]["depth"], p))
    keep: list[str] = []
    for p in paths:
        if any(p.startswith(k.rstrip("/") + "/") for k in keep):
            continue
        keep.append(p)
    # Trees the scanner saw a `.git` in. A build output INSIDE a working tree may be
    # tracked content (tenant repos `git add -f` their dist/; measured 2026-09-01 on
    # a tenant repo's dist/), so nothing under one is ever pre-approved.
    repo_roots = [t["path"].rstrip("/") + "/" for t in trees if t.get("git")]
    out: list[Proposal] = []
    for p in keep:
        t, r = matched[p]
        in_repo = any(p.startswith(rr) for rr in repo_roots)
        auto = (bool(r.get("auto")) and t["cls"] not in NEVER_AUTO
                and bool(t.get("refetchable")) and not in_repo)
        note = r.get("why") or ""
        if in_repo:
            note += " [inside a git working tree: may be tracked content]"
        if not auto:
            note += " [needs approval]"
        out.append(Proposal(
            node=snapshot["node"], path=p, action=r["action"], bytes=int(t["bytes"]),
            cls=t["cls"], policy_rule=r["id"], auto=auto, fingerprint=t.get("fingerprint"),
            snapshot_id=snapshot_id, note=note,
        ))
    out.sort(key=lambda x: -x.bytes)
    return out


def _under_roots(path: str, roots: list[Path]) -> bool:
    p = os.path.normcase(os.path.abspath(path))
    for r in roots:
        rr = os.path.normcase(os.path.abspath(str(r)))
        base = rr.rstrip("\\/")
        if p == rr or p.startswith(base + os.sep) or p.startswith(base + "/"):
            return True
    return False


def _current_fingerprint(path: Path) -> str:
    total = 0
    files = 0
    newest = 0.0
    for dirpath, _dirs, filenames in os.walk(path):
        for fn in filenames:
            try:
                st = os.stat(os.path.join(dirpath, fn), follow_symlinks=False)
            except OSError:
                continue
            total += st.st_size
            files += 1
            newest = max(newest, st.st_mtime)
    return fingerprint(total, files, newest)


_last_rm_error: list[str] = []


def _git_ancestor(target: Path, roots: list[Path]) -> Optional[str]:
    """The nearest ancestor of `target` (itself included, up to the owning root) that
    holds a `.git` entry -- i.e. the git working tree the path lives in -- or None.

    Walks the FILESYSTEM at apply time, not the snapshot: a proposal born before the
    scanner recorded `.git` must still be refused here.
    """
    try:
        root = _owning_root(target, roots)
    except ApplyRefused:
        return None
    node = target
    root_abs = os.path.normcase(os.path.abspath(str(root)))
    while True:
        if (node / ".git").exists() and node != root:
            return str(node).replace("\\", "/")
        if os.path.normcase(os.path.abspath(str(node))) == root_abs or node.parent == node:
            return None
        node = node.parent


def _build_in_progress() -> bool:
    """Is a container image build running on THIS node? Fail-CLOSED on doubt.

    Uses `pgrep -f` where it exists (Linux nodes); on hosts without pgrep (Windows)
    there is no podman build to race, so False. If pgrep itself errors, answer True:
    "could not tell" must defer, never reclaim.
    """
    import shutil as _sh
    import subprocess

    if _sh.which("pgrep") is None:
        return False
    try:
        r = subprocess.run(["pgrep", "-f", "buildah|podman build|-working-container"],
                           capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return True
    return r.returncode == 0 and bool(r.stdout.strip())


def _rmtree(path: Path) -> int:
    """Remove a tree, returning bytes removed; clears read-only bits on Windows."""
    removed = 0
    _last_rm_error.clear()

    def onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError as exc:
            # Best effort on the retry: the caller re-stats, so a stubborn file
            # surfaces as bytes that did not go away, never as a silent success.
            _last_rm_error.append(f"{p}: {type(exc).__name__}")

    for dirpath, _d, filenames in os.walk(path):
        for fn in filenames:
            try:
                removed += os.stat(os.path.join(dirpath, fn), follow_symlinks=False).st_size
            except OSError:
                continue
    shutil.rmtree(path, onerror=onerror)
    return removed


def apply(
    proposal: Proposal | dict,
    *,
    roots: list[Path | str],
    dry_run: bool = True,
    approved: bool | None = None,
    backup_hook: Callable[[Path], str] | None = None,
    engine_prune_hook: Callable[[Path], str] | None = None,
    verify_fingerprint: bool = True,
    build_in_progress: Callable[[], bool] | None = None,
) -> dict:
    """Carry out one proposal, or refuse. Returns a ledger-shaped dict.

    `approved` overrides the proposal's own status (True = a human said yes).
    `backup_hook(path) -> str` runs before a backup-then-delete (awrecover's
    snapshot, or anything returning a label). `engine_prune_hook(path) -> str`
    carries out `prune-engine` (e.g. `podman image prune`); without it that action
    is refused, because rm on an engine store corrupts the engine.
    """
    p = proposal if isinstance(proposal, Proposal) else Proposal(**{
        k: v for k, v in proposal.items()
        if k in Proposal.__dataclass_fields__ and k != "extra"})
    root_paths = [Path(r) for r in roots]
    is_ok = approved if approved is not None else (p.status == "approved" or p.auto)
    base = {"proposal_id": p.id, "node": p.node, "path": p.path, "action": p.action,
            "bytes": p.bytes, "dry_run": dry_run}

    def refuse(msg: str) -> dict:
        raise ApplyRefused(msg)

    if p.action not in ACTIONS:
        refuse(f"unknown action {p.action!r}")
    if not _under_roots(p.path, root_paths):
        refuse(f"{p.path} is outside the declared roots {[str(r) for r in root_paths]}")
    if p.cls in NEVER_AUTO and approved is not True and p.status != "approved":
        refuse(f"class {p.cls!r} is never auto-applied; needs explicit approval")
    if not is_ok:
        refuse("proposal is neither pre-approved by policy nor approved by a human")
    target = Path(p.path)
    if not target.exists():
        refuse(f"{p.path} no longer exists")
    human_ok = approved is True or p.status == "approved"
    if p.action in ("delete", "compress", "backup-then-delete") and not human_ok:
        # APPLY-TIME guard, independent of what the proposal's snapshot knew. Measured
        # 2026-09-02: proposals written before the scanner recorded `.git` outlived the
        # rule -- four tenant repos' tracked dist/ trees were quarantined from stale
        # rows while the newer scan had already downgraded them to ASK (all four were
        # reverted byte-for-byte; the quarantine design is why that was possible). The
        # rule must live where the action happens, not only where the proposal is born.
        repo_root = _git_ancestor(target, root_paths)
        if repo_root is not None:
            refuse(f"{p.path} is inside the git working tree {repo_root}; tracked content may "
                   f"live there -- needs explicit human approval")
    if p.action in ("delete", "compress", "backup-then-delete", "prune-engine") and not dry_run:
        # DEFERRED while a container build is in flight on this node. A build's
        # temp dirs and intermediate layers look exactly like reclaimable build-temp
        # and dangling container-store, and a prune landing mid-COMMIT loses the
        # image tag (the restart-storm class). Deferral is a refusal with a reason,
        # so the ledger says why nothing happened and the next pass retries.
        probe = build_in_progress if build_in_progress is not None else _build_in_progress
        if probe():
            refuse("deferred: a container build (buildah/podman build) is in progress on this node")
    if verify_fingerprint and p.fingerprint and target.is_dir():
        now_fp = _current_fingerprint(target)
        if now_fp != p.fingerprint:
            refuse(f"{p.path} changed since the scan (fingerprint {p.fingerprint} -> {now_fp});"
                   " re-scan before applying")
    if p.action == "review":
        return {**base, "outcome": "review-only", "detail": "nothing to apply; a human decides"}
    if p.action == "prune-engine":
        if engine_prune_hook is None:
            refuse("prune-engine needs an engine hook; never rm an engine store")
        if dry_run:
            return {**base, "outcome": "dry-run", "detail": "would call engine prune"}
        return {**base, "outcome": "applied", "detail": engine_prune_hook(target)}
    if p.action == "compress":
        if dry_run:
            return {**base, "outcome": "dry-run", "detail": "would compress in place"}
        archive = shutil.make_archive(str(target) + ".awstorage", "gztar", root_dir=str(target))
        removed = _rmtree(target)
        return {**base, "outcome": "applied", "bytes": removed,
                "detail": f"compressed to {archive}"}
    if p.action == "backup-then-delete":
        if backup_hook is None:
            refuse("backup-then-delete needs a backup hook (e.g. awrecover.snapshot)")
        if dry_run:
            return {**base, "outcome": "dry-run", "detail": "would snapshot, then quarantine"}
        label = backup_hook(target)
        moved, qpath = _quarantine(target, root_paths, p.id)
        return {**base, "outcome": "applied", "bytes": moved,
                "detail": f"backed up as {label}, then quarantined to {qpath}"}
    # delete == QUARANTINE. Two-phase on purpose: the tree is renamed into
    # <root>/.awstorage-quarantine/<proposal-id>/ on the same volume (os.replace,
    # instant, no copy), so `revert` can put it back byte-for-byte. The bytes are
    # reclaimed by `purge_quarantine(older_than_days=N)`, its own pre-approved step.
    # Reversibility beats a drift check: the drift check catches a stale proposal,
    # the quarantine catches a WRONG one.
    if dry_run:
        return {**base, "outcome": "dry-run", "detail": "would quarantine (reversible delete)"}
    moved, qpath = _quarantine(target, root_paths, p.id)
    return {**base, "outcome": "applied", "bytes": moved,
            "detail": f"quarantined to {qpath}; `awstorage revert` restores, purge reclaims"}


QUARANTINE_DIRNAME = ".awstorage-quarantine"


def _owning_root(path: Path, roots: list[Path]) -> Path:
    best = None
    for r in roots:
        if _under_roots(str(path), [r]) and (best is None or len(str(r)) > len(str(best))):
            best = r
    if best is None:
        raise ApplyRefused(f"{path} is outside the declared roots")
    return best


def _tree_bytes(path: Path) -> int:
    total = 0
    for dirpath, _d, filenames in os.walk(path):
        for fn in filenames:
            try:
                total += os.stat(os.path.join(dirpath, fn), follow_symlinks=False).st_size
            except OSError:
                continue
    return total


def _quarantine(target: Path, roots: list[Path], proposal_id: int | None) -> tuple[int, str]:
    root = _owning_root(target, roots)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    qdir = root / QUARANTINE_DIRNAME / f"{proposal_id or 'adhoc'}-{stamp}"
    qdir.mkdir(parents=True, exist_ok=True)
    size = _tree_bytes(target)
    dest = qdir / target.name
    # Record where it came from so revert needs nothing but the quarantine dir.
    (qdir / "ORIGIN").write_text(str(target), encoding="utf-8")
    try:
        os.replace(str(target), str(dest))
    except OSError:
        # Cross-device (a mount point inside the root): fall back to a move.
        shutil.move(str(target), str(dest))
    return size, str(dest).replace("\\", "/")


def revert(quarantine_entry: Path | str) -> str:
    """Put a quarantined tree back where it came from. Refuses if the origin exists."""
    q = Path(quarantine_entry)
    origin_file = q / "ORIGIN"
    if not origin_file.is_file():
        raise ApplyRefused(f"{q} is not a quarantine entry (no ORIGIN file)")
    origin = Path(origin_file.read_text(encoding="utf-8").strip())
    payload = [c for c in q.iterdir() if c.name != "ORIGIN"]
    if len(payload) != 1:
        raise ApplyRefused(f"{q} does not hold exactly one tree")
    if origin.exists():
        raise ApplyRefused(f"origin {origin} exists again; will not overwrite it")
    origin.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(str(payload[0]), str(origin))
    except OSError:
        shutil.move(str(payload[0]), str(origin))
    shutil.rmtree(q, ignore_errors=True)
    return str(origin).replace("\\", "/")


def list_quarantine(roots: list[Path | str]) -> list[dict]:
    out = []
    for r in roots:
        qroot = Path(r) / QUARANTINE_DIRNAME
        if not qroot.is_dir():
            continue
        for entry in sorted(qroot.iterdir()):
            if not entry.is_dir():
                continue
            origin_file = entry / "ORIGIN"
            origin = ""
            if origin_file.is_file():
                origin = origin_file.read_text(encoding="utf-8").strip()
            try:
                age_days = (time.time() - entry.stat().st_mtime) / 86400.0
            except OSError:
                age_days = 0.0
            payload = sum(_tree_bytes(c) if c.is_dir() else c.stat().st_size
                          for c in entry.iterdir() if c.name != "ORIGIN")
            out.append({"entry": str(entry).replace("\\", "/"), "origin": origin,
                        "bytes": payload, "age_days": round(age_days, 1)})
    return out


def purge_quarantine(roots: list[Path | str], *, older_than_days: float = 14.0,
                     dry_run: bool = True) -> list[dict]:
    """Reclaim quarantined trees older than N days. This is the irreversible step."""
    results = []
    for q in list_quarantine(roots):
        if q["age_days"] < older_than_days:
            continue
        if dry_run:
            results.append({**q, "outcome": "dry-run"})
            continue
        removed = _rmtree(Path(q["entry"]))
        results.append({**q, "outcome": "purged", "bytes": removed})
    return results
