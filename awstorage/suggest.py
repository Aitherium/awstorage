"""Suggestions: agents PROPOSE deletions; awstorage decides, applies, and learns.

Measured 2026-09-28: dead agent sessions held 106 GB until a person found them by
hand. The agents that made those trees knew they were dead. This module lets any
agent say so -- and gives it no power beyond saying so:

    suggest -> validate -> lane (auto | card) -> apply (re-validate) -> ledger -> trust

**Validation** runs at suggest time and AGAIN at apply time; every step is a named
entry in ``checks``. A suggestion is REFUSED when the path does not exist or is a
link; sits under the never/sensitive/OS set (``awstorage.guards``), a quarantine, a
volume root, the home dir or a path awstorage itself depends on; is inside a git work
tree that is dirty, has commits no remote holds, or that git cannot judge; had any
file change inside the live window (2 h) or carries a registered live id
(``$AWSTORAGE_LIVE_IDS``); or its evidence contradicts what was measured. A second
open suggestion for the same path is a ``duplicate`` (the first one's id).

**Lanes.** ``auto-approved`` only when ALL hold: the class is regenerable
(``build-temp`` / ``package-cache`` -- agent scratch and temp resolve to
``build-temp`` through the sweep presets), the action is ``quarantine`` (never
delete, never archive), the evidence verifies (at least one checkable claim, none
contradicted), no nested work tree is dirty or unjudged, the suggesting agent's
identity is VERIFIED (see below) and its trust is at or above the threshold.
Everything else is ``pending-card``: a decision
card is raised through the hook set by :func:`set_card_hook` (none by default --
the suggestion then waits, listed by :func:`suggestions`). Approving a card-lane
suggestion requires a card that passes ``awstorage.manage.verify_card`` -- the SAME
function manage uses: a SIGNED answer receipt from the platform's attestation key
(``awstorage.attest``), never the card's own ``answered_by``/``answer_attested``.

**Apply trusts no status.** ``catalog.db`` is a file any local process can edit, so
an ``approved`` row is RE-VERIFIED at apply: the card recorded at resolve (or the live
card, when :func:`set_card_reader` is installed) must pass ``manage.verify_card``
again (signature, owner, fresh sign-in, receipt age, nonce), be the card the row
names, carry the receipt whose digest was recorded at resolve, and carry the
``content_sha256`` fact equal to the digest of the row as it stands now
(:func:`suggestion_content_digest` -- path, action, node, class, size, ...). An
``auto-approved`` row re-checks every lane condition (regenerable class re-classified
from disk, quarantine only, evidence re-verified, identity RE-VERIFIED by the installed
verifier against the proof stored at suggest time, trust). Anything that does not
verify is ``refused`` -- nothing is deleted on a status alone.

**Apply** re-validates everything, refuses on drift (size / file count / newest
mtime changed since the suggestion), harvests first (the sweep's verified harvest;
kept when the shelf's drive is under its floor), then quarantines (or, card-approved,
deletes / archives through a hook), ledgers, and records the OUTCOME. Quarantined
suggestions are purged after ``PURGE_AFTER_S``; until then ``awstorage revert`` or
:func:`revert_suggestion` puts the tree back -- and a revert is the strongest
negative signal an agent can earn.

**Trust** is derived from the suggestion rows (never a separately maintained
counter)::

    trust = (applied - 3 * reverted + 1) / (applied + rejected + 2)

Laplace-smoothed: a new agent scores 1/2 = 0.50, under the default threshold 0.6,
so its first suggestions go to cards. Each applied suggestion raises it, each
rejection lowers it, and one revert of an applied suggestion costs three
applications. It can go negative. The threshold (``$AWSTORAGE_TRUST_THRESHOLD``) is
clamped to at least ``MIN_TRUST_THRESHOLD`` so a brand-new agent can never
auto-approve.

**Identity.** ``suggested_by`` is caller-declared, and every caller of this module is
in-process -- the brick cannot tell an agent from something typing its name. So the
auto lane requires a VERIFIED identity: a verifier installed with
:func:`set_identity_verifier` (``fn(suggested_by, proof) -> bool``, e.g. one that
checks an agent-signed token) accepted the ``identity_proof`` passed to
:func:`suggest`. Without one every suggestion is ``identity: unverified`` and goes to
a card, whatever its trust -- unless the owner sets ``AWSTORAGE_TRUST_INPROCESS=1``
(recorded on the row as ``inprocess-trusted``, and re-checked at apply). The trust
ledger is still kept for every name; it just cannot open the auto lane on its own.
Transports stamp what they know: MCP ``mcp-session:<uid>`` (a session, never "the
owner"), awdk ``agent:<name>``.
"""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from ._fs import is_link, remove_tree_detail
from .guards import Guards
from .policy import QUARANTINE_DIRNAME, ApplyRefused, move_no_follow, revert
from .sweep import (
    DEFAULT_HARVEST,
    DEFAULT_LIVE_WINDOW,
    EMERGENCY_DELETE_CLASSES,
    SweepConfigError,
    _protected,
    expand_path,
    glob_to_regex,
    harvest_item,
    live_path_hit,
    load_live_ids,
    measure,
    parse_duration,
    presets,
    same_volume,
    sample_age,
)

SUGGEST_ACTIONS = ("quarantine", "delete", "archive")
#: Classes whose loss costs a regeneration, never data -- the only auto-lane classes.
REGENERABLE_CLASSES = EMERGENCY_DELETE_CLASSES
OPEN_STATUSES = ("pending-card", "auto-approved", "approved")
STATUSES = ("refused", "pending-card", "auto-approved", "approved", "executing", "rejected",
            "applied", "reverted", "drifted", "failed", "expired")
TRUST_THRESHOLD = 0.6
TRUST_ENV = "AWSTORAGE_TRUST_THRESHOLD"
#: A new agent scores exactly 0.5; the threshold can never be set at or below it.
MIN_TRUST_THRESHOLD = 0.51
CATALOG_ENV = "AWSTORAGE_CATALOG"
LIVE_WINDOW_S = parse_duration(DEFAULT_LIVE_WINDOW)
SUGGEST_MEASURE_CAP_S = 20.0
APPLY_MEASURE_CAP_S = 120.0
PURGE_AFTER_S = 72 * 3600.0
EXECUTING_STALE_S = 3600.0
MAX_TTL_DAYS = 90.0
SHELF_RULE = "suggestions"
QUARANTINE_PREFIX = "suggest-"
_AGENT_RX = re.compile(r"^[A-Za-z0-9_.:@/\-]{1,128}$")

#: Owner opt-in: treat in-process callers' ``suggested_by`` as verified (auto lane).
TRUST_INPROCESS_ENV = "AWSTORAGE_TRUST_INPROCESS"
IDENTITY_VALUES = ("verified", "inprocess-trusted", "unverified")

CardHook = Callable[[dict], Any]
ArchiveHook = Callable[[Path, dict], dict]
IdentityVerifier = Callable[[str, Any], bool]
CardReader = Callable[[str], Any]
_card_hook: CardHook | None = None
_archive_hook: ArchiveHook | None = None
_identity_verifier: IdentityVerifier | None = None
_card_reader: CardReader | None = None


def set_card_hook(fn: CardHook | None) -> None:
    """Install the decision-card raiser: ``fn(card_spec) -> card id`` (or None).

    The platform wires adk.decisions / Genesis here; awstorage imports neither.
    Without a hook a card-lane suggestion stays ``pending-card``.
    """
    global _card_hook
    _card_hook = fn


def set_archive_hook(fn: ArchiveHook | None) -> None:
    """Install the archiver for card-approved ``archive`` suggestions:
    ``fn(path, suggestion) -> {"ok": bool, "detail": str}``. It must copy AND verify
    the tree elsewhere; the local tree is quarantined only after ``ok``. Without a
    hook an approved archive waits (never falls back to delete)."""
    global _archive_hook
    _archive_hook = fn


def set_card_reader(fn: CardReader | None) -> None:
    """Install ``fn(card_id) -> card | None`` that reads a decision card from its store.
    With it, apply re-reads the LIVE card of an approved suggestion; without it, apply
    re-verifies the card recorded at resolve. Either way the receipt must still verify
    and match the digest recorded at resolve."""
    global _card_reader
    _card_reader = fn


def set_identity_verifier(fn: IdentityVerifier | None) -> None:
    """Install the agent-identity verifier: ``fn(suggested_by, proof) -> bool``. Only
    ``True`` (the boolean) verifies; an exception is a refusal. The auto lane is
    closed to every suggestion it has not verified."""
    global _identity_verifier
    _identity_verifier = fn


def _trust_inprocess(env: Mapping[str, str] | None = None) -> bool:
    e = os.environ if env is None else env
    return (e.get(TRUST_INPROCESS_ENV) or "").strip() == "1"


def identity_of(agent: str, proof: Any = None, env: Mapping[str, str] | None = None
                ) -> tuple[str, str]:
    """(identity, detail): ``verified`` | ``inprocess-trusted`` | ``unverified``."""
    if _identity_verifier is not None and proof is not None:
        try:
            ok = _identity_verifier(agent, proof) is True
        except Exception as exc:  # noqa: BLE001 -- a verifier that fails verifies nothing
            return "unverified", f"identity verifier failed: {type(exc).__name__}"
        if ok:
            return "verified", "identity verifier accepted the proof"
        return "unverified", "identity verifier rejected the proof"
    if _trust_inprocess(env):
        return "inprocess-trusted", f"{TRUST_INPROCESS_ENV}=1 (owner opt-in)"
    why = "no identity verifier installed" if _identity_verifier is None else "no proof"
    return "unverified", f"in-process caller, {why}: suggested_by is caller-declared"


def _identity_holds(s: Mapping[str, Any]) -> bool:
    """Re-judge the identity at apply. ``verified`` is NOT read from the row: the
    installed verifier must accept the proof stored at suggest time again (a row edited
    to say ``verified`` without a proof the verifier accepts is not)."""
    ident = str(s.get("identity") or "unverified")
    if ident == "verified":
        proof = s.get("identity_proof")
        if _identity_verifier is None or proof is None:
            return False
        try:
            return _identity_verifier(str(s.get("suggested_by") or ""), proof) is True
        except Exception:  # noqa: BLE001 -- a verifier that fails verifies nothing
            return False
    return ident == "inprocess-trusted" and _trust_inprocess()


def suggestion_content_digest(s: Mapping[str, Any]) -> str:
    """sha256 of WHAT a suggestion card approves: id, node, path (+ key), action,
    suggested_by, class, size, file count, newest mtime, capped. Bound into the card as
    ``content_sha256`` and recomputed from the row at resolve and at apply."""
    import hashlib
    import json

    body = {"v": 1, "kind": "suggestion", "id": int(s["id"]), "node": str(s.get("node")),
            "path": str(s.get("path")), "path_key": str(s.get("path_key")),
            "action": str(s.get("action")), "suggested_by": str(s.get("suggested_by")),
            "cls": s.get("cls"), "size": s.get("size"), "files": s.get("files"),
            "newest_mtime": s.get("newest_mtime"), "capped": bool(s.get("capped"))}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, default=str).encode("utf-8")
                          ).hexdigest()


# -- helpers -------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _norm(p: str) -> str:
    return os.path.abspath(p).replace("\\", "/")


def _key(p: str) -> str:
    return os.path.normcase(os.path.abspath(p)).replace("\\", "/")


def default_catalog_path() -> Path:
    env = os.environ.get(CATALOG_ENV, "").strip()
    if env:
        return Path(os.path.expanduser(env))
    return Path.home() / ".aither" / "awstorage" / "catalog.db"


def _open(catalog: Any):
    """(Catalog, owned) -- a Catalog passes through; a path / None opens one."""
    if catalog is not None and hasattr(catalog, "put_suggestion"):
        return catalog, False
    from .catalog import Catalog
    path = default_catalog_path() if catalog is None else Path(os.path.expanduser(str(catalog)))
    return Catalog(path), True


def trust_threshold(env: Mapping[str, str] | None = None) -> float:
    e = os.environ if env is None else env
    raw = (e.get(TRUST_ENV) or "").strip()
    try:
        v = float(raw) if raw else TRUST_THRESHOLD
    except ValueError:
        v = TRUST_THRESHOLD
    return max(MIN_TRUST_THRESHOLD, v)


def trust_score(applied: int, rejected: int, reverted: int) -> float:
    """(applied - 3*reverted + 1) / (applied + rejected + 2). New agent: 0.5."""
    return (int(applied) - 3 * int(reverted) + 1) / (int(applied) + int(rejected) + 2)


def trust(agent: str | None = None, *, catalog: Any = None) -> list[dict]:
    """The per-agent trust ledger: counts + score + whether it reaches the auto lane."""
    cat, own = _open(catalog)
    try:
        thr = trust_threshold()
        rows = cat.suggestion_counts(agent)
        if agent is not None and not rows:
            rows = [{"agent": agent, "made": 0, "approved": 0, "rejected": 0, "applied": 0,
                     "reverted": 0, "refused": 0, "open": 0, "last_at": None}]
        for r in rows:
            r["trust"] = round(trust_score(r["applied"], r["rejected"], r["reverted"]), 4)
            r["threshold"] = thr
            r["auto_eligible"] = r["trust"] >= thr
        return rows
    finally:
        if own:
            cat.close()


def _agent_trust(cat, agent: str) -> float:
    rows = cat.suggestion_counts(agent)
    if not rows:
        return trust_score(0, 0, 0)
    r = rows[0]
    return trust_score(r["applied"], r["rejected"], r["reverted"])


# -- classification ------------------------------------------------------------------

def classify_path(path: str, env: Mapping[str, str] | None = None) -> dict:
    """The conservative of two verdicts. ``classify.classify_tree`` names the tree; if
    it names a NON-regenerable class (``dataset``, ``repo``, ``service-state`` ...),
    that stands -- a dataset under %TEMP% is still a dataset. Otherwise the sweep
    presets decide (an item of -- or anything under an item of -- a preset glob takes
    the preset's class: agent scratch and temp are ``build-temp``), then the tree
    verdict (``unknown`` when nothing matched)."""
    from .classify import classify_tree

    p = _norm(path)
    v = classify_tree(p)
    if v["cls"] != "unknown" and v["cls"] not in REGENERABLE_CLASSES:
        return {"cls": v["cls"], "reason": v.get("reason", ""),
                "source": v.get("source", "")}
    chain = [p]
    cur = p
    for _ in range(8):
        parent = os.path.dirname(cur.rstrip("/"))
        if not parent or parent == cur:
            break
        chain.append(parent.replace("\\", "/"))
        cur = parent
    for name, rule in presets().items():
        if rule.get("paths_from_policy"):
            continue
        try:
            pats = [glob_to_regex(expand_path(x, env)) for x in rule["paths"]]
            excl = [glob_to_regex(expand_path(x, env)) for x in rule.get("exclude", [])]
        except SweepConfigError:
            continue
        for cand in chain:
            if any(rx.match(cand) for rx in pats) and not any(rx.match(cand) for rx in excl):
                return {"cls": rule["class"], "reason": f"under an item of preset rule {name}",
                        "source": f"preset:{name}"}
    return {"cls": v["cls"], "reason": v.get("reason", ""), "source": v.get("source", "")}


# -- validation ----------------------------------------------------------------------

def _include_rx() -> list:
    return [glob_to_regex(g) for g in DEFAULT_HARVEST["include"]]


def _validate(path: str, *, now: float, env: Mapping[str, str] | None,
              measure_cap_s: float, protect: list[str]) -> dict:
    """Every suggest-time check, in cost order. {ok, why, checks, cls, m, size, files,
    newest_mtime, capped, nested_ok, nested_why}. Stops at the first refusal."""
    checks: list[str] = []
    v: dict[str, Any] = {"ok": False, "why": "", "checks": checks, "cls": None, "m": None,
                         "size": None, "files": None, "newest_mtime": None, "capped": False,
                         "nested_ok": True, "nested_why": ""}

    def refuse(name: str, why: str) -> dict:
        checks.append(f"{name}: REFUSED {why}")
        v["why"] = why
        return v

    p = _norm(path)
    if not os.path.lexists(p):
        return refuse("exists", "path does not exist")
    if is_link(p):
        return refuse("not-link", "path is a symlink/junction (never followed or removed)")
    checks.append("exists: ok")
    checks.append("not-link: ok")
    g = Guards().refusal(p)
    if g:
        return refuse("guards", g)
    if QUARANTINE_DIRNAME in Path(p).parts:
        return refuse("guards", "inside an awstorage quarantine")
    if os.path.dirname(p.rstrip("/")) in ("", p.rstrip("/")) or re.fullmatch(r"[A-Za-z]:/?", p):
        return refuse("guards", "a volume root")
    prot = _protected(p, protect)
    if prot:
        return refuse("guards", f"holds {prot}, which awstorage or this session depends on")
    checks.append("guards: ok")
    live = load_live_ids(env=env)
    segs = [s.lower() for s in p.split("/") if s]
    hit = next((s for s in segs if s in live), None) or live_path_hit(p, live)
    if hit:
        return refuse("live-ids", f"segment {hit!r} is a registered live id")
    checks.append("live-ids: ok")
    c = classify_path(p, env)
    v["cls"] = c["cls"]
    checks.append(f"classify: {c['cls']} ({c['reason']})")

    from .gitcheck import git_state, nested_repos, repo_state
    gs = git_state(p)
    if gs["repo"] is not None and not gs["clean"]:
        return refuse("git", f"inside the work tree {gs['repo']}: {gs['why']}")
    checks.append("git: " + ("not inside a work tree" if gs["repo"] is None
                             else f"{gs['repo']} clean and pushed"))

    cutoff = now - LIVE_WINDOW_S
    cap_deadline = time.monotonic() + max(0.0, float(measure_cap_s))
    m = measure(p, _include_rx(), stop_newer_than=cutoff, cap_deadline=cap_deadline)
    if m["kind"] in ("missing", "special", "link"):
        return refuse("measure", f"{m['kind']} entry")
    if m.get("early") == "fresh":
        return refuse("live-window", "a file inside changed within the live window "
                                     f"({LIVE_WINDOW_S / 3600:g}h)")
    if m.get("early") == "capped":
        smp = sample_age(p, cutoff, _include_rx())
        if smp["fresh"]:
            return refuse("live-window", f"sampled {smp['fresh']} changed within the live "
                                         f"window ({LIVE_WINDOW_S / 3600:g}h)")
        seen = {x[0] for x in m["candidates"]}
        m["candidates"].extend(x for x in smp["candidates"] if x[0] not in seen)
        m["capped"] = True
        m["newest_mtime"] = max(m["newest_mtime"] if m["files"] else 0.0,
                                smp["newest_mtime"])
        v.update(capped=True, size=None, files=None, newest_mtime=m["newest_mtime"])
        checks.append(f"measure: capped at {measure_cap_s:g}s (saw {m['bytes']} bytes); "
                      "size unknown")
    else:
        v.update(size=int(m["bytes"]), files=int(m["files"]),
                 newest_mtime=float(m["newest_mtime"]))
        checks.append(f"measure: {m['bytes']} bytes, {m['files']} file(s)")
    if now - m["newest_mtime"] < LIVE_WINDOW_S:
        return refuse("live-window", f"changed within the live window "
                                     f"({LIVE_WINDOW_S / 3600:g}h)")
    checks.append(f"live-window: idle {(now - m['newest_mtime']) / 3600:.1f}h")
    v["m"] = m

    if m["kind"] == "dir":
        nr = nested_repos(p)
        from .gitcheck import NESTED_MAX_REPOS
        bad = []
        for root, kind in nr["repos"][:NESTED_MAX_REPOS]:
            st = repo_state(root, kind)
            if not st["clean"]:
                bad.append(f"{root}: {st['why']}")
        if len(nr["repos"]) > NESTED_MAX_REPOS:
            bad.append(f"{len(nr['repos'])} nested work trees (> {NESTED_MAX_REPOS} judged)")
        if not nr["complete"]:
            bad.append("nested work-tree scan incomplete")
        if bad:
            v["nested_ok"] = False
            v["nested_why"] = bad[0]
            checks.append(f"nested-git: blocks the auto lane ({bad[0]})")
        else:
            checks.append(f"nested-git: {len(nr['repos'])} nested work tree(s), all clean")
    v["ok"] = True
    return v


def _verify_evidence(evidence: Mapping[str, Any] | None, v: dict, now: float
                     ) -> tuple[str, str]:
    """('verified'|'none'|'mismatch', detail). Checkable claims: bytes, files,
    idle_hours, cls. Unknown keys are kept but prove nothing."""
    if not evidence:
        return "none", "no evidence"
    checked, bad = [], []
    size, capped, m = v["size"], v["capped"], v["m"] or {}
    if "bytes" in evidence:
        try:
            claim = int(evidence["bytes"])
        except (TypeError, ValueError):
            return "mismatch", f"bytes {evidence['bytes']!r} is not an integer"
        if capped:
            seen = int(m.get("bytes") or 0)
            (checked if claim >= seen * 0.95 else bad).append(
                f"bytes {claim} vs >= {seen} seen (capped)")
        else:
            tol = max((size or 0) * 0.05, 2**20)
            (checked if abs(claim - (size or 0)) <= tol else bad).append(
                f"bytes {claim} vs measured {size}")
    if "files" in evidence and not capped:
        try:
            claim = int(evidence["files"])
        except (TypeError, ValueError):
            return "mismatch", f"files {evidence['files']!r} is not an integer"
        nf = v["files"] or 0
        (checked if abs(claim - nf) <= max(nf * 0.05, 2) else bad).append(
            f"files {claim} vs measured {nf}")
    if "idle_hours" in evidence:
        try:
            claim = float(evidence["idle_hours"])
        except (TypeError, ValueError):
            return "mismatch", f"idle_hours {evidence['idle_hours']!r} is not a number"
        idle = (now - float(v["newest_mtime"] or now)) / 3600.0
        (checked if idle >= claim * 0.95 else bad).append(
            f"idle_hours {claim:g} vs measured {idle:.1f}")
    if "cls" in evidence or "class" in evidence:
        claim = str(evidence.get("cls", evidence.get("class")))
        (checked if claim == v["cls"] else bad).append(f"class {claim} vs {v['cls']}")
    if bad:
        return "mismatch", "; ".join(bad)
    if not checked:
        return "none", "no checkable claim (bytes, files, idle_hours, cls)"
    return "verified", "; ".join(checked)


def _protect_list(cat) -> list[str]:
    return [str(x) for x in (getattr(cat, "path", None), Path.home() / ".aither",
                             os.getcwd(), sys.prefix, Path.home()) if x]


# -- cards ---------------------------------------------------------------------------

def card_spec(s: Mapping[str, Any]) -> dict:
    """The decision card that asks a human to approve suggestion `s`. It carries the
    fact ``proposal_id: <id>`` that ``manage.verify_card`` requires."""
    from .manage import card_facts, content_fact

    size = s.get("size")
    gb = f"{int(size) / 2**30:.2f} GB" if size is not None else "size unknown (capped)"
    name = Path(str(s["path"])).name
    title = f"awstorage suggestion #{s['id']}: {s['action']} {name} ({gb}) on {s['node']}?"
    if s["action"] == "quarantine":
        rev = "Reversible: the tree moves to a quarantine; `revert` puts it back until purge."
    elif s["action"] == "archive":
        rev = "Reversible until purge: archived elsewhere, then quarantined locally."
    else:
        rev = "IRREVERSIBLE: deleted after its harvest (reports/notes) is verified."
    facts = card_facts(int(s["id"])) + [
        f"node: {s['node']}", f"path: {s['path']}", f"action: {s['action']}",
        f"class: {s.get('cls')}", f"bytes: {size if size is not None else 'unknown'}",
        f"suggested_by: {s['suggested_by']}", f"expires: {s.get('expires_at')}",
        content_fact(suggestion_content_digest(s))]
    return {"title": title,
            "summary": f"{s['suggested_by']} suggests: {s['reason']} {rev}",
            "facts": facts, "options": ["approve|Approve", "reject|Reject: keep it"],
            "reversibility": rev, "kind": "decision", "agent": "awstorage",
            "checks": list(s.get("checks") or [])}


def _raise_card(cat, sid: int) -> str | None:
    if _card_hook is None:
        return None
    s = cat.get_suggestion(sid)
    try:
        cid = _card_hook(card_spec(s))
    except Exception as exc:  # noqa: BLE001 -- a card hook failure leaves it pending
        cat.update_suggestion(sid, why=f"{s.get('why') or ''} [card hook failed: "
                                        f"{type(exc).__name__}: {exc}]"[:1000])
        return None
    if cid:
        cat.update_suggestion(sid, card_raised=str(cid))
        return str(cid)
    return None


# -- the API -------------------------------------------------------------------------

def suggest(path: str, *, reason: str, suggested_by: str, action: str = "quarantine",
            evidence: dict | None = None, ttl_days: float = 7.0, catalog: Any = None,
            identity_proof: Any = None) -> dict:
    """An agent proposes removing `path`. Never acts; decides the lane.

    Returns ``{id, status, why, class, size, checks}`` (+ ``trust``, ``card_id``):
    status ``auto-approved`` | ``pending-card`` | ``refused`` | ``duplicate``.
    ``size`` is None when the measure was capped. Raises ValueError for malformed
    arguments (unknown action, empty reason/agent, ttl out of range).
    ``identity_proof`` is handed to the verifier set by :func:`set_identity_verifier`;
    without a verified identity the suggestion never takes the auto lane.
    """
    if action not in SUGGEST_ACTIONS:
        raise ValueError(f"action {action!r} not in {SUGGEST_ACTIONS}")
    agent = (suggested_by or "").strip()
    if not _AGENT_RX.match(agent):
        raise ValueError("suggested_by must be 1-128 chars of [A-Za-z0-9_.:@/-]")
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("reason is required (it is what the approving human reads)")
    if not (0 < float(ttl_days) <= MAX_TTL_DAYS):
        raise ValueError(f"ttl_days must be in (0, {MAX_TTL_DAYS:g}]")
    if evidence is not None and not isinstance(evidence, dict):
        raise ValueError("evidence must be a dict")
    from .identity import whoami

    cat, own = _open(catalog)
    try:
        p = _norm(str(os.path.expanduser(path)))
        key = _key(p)
        dup = cat.list_suggestions(list(OPEN_STATUSES), path_key=key, limit=1)
        if dup:
            d = dup[0]
            return {"id": int(d["id"]), "status": "duplicate",
                    "why": f"open suggestion #{d['id']} ({d['status']}) by "
                           f"{d['suggested_by']} already covers this path",
                    "class": d.get("cls"), "size": d.get("size"),
                    "checks": [f"dedupe: open suggestion #{d['id']}"]}
        now = time.time()
        v = _validate(p, now=now, env=None, measure_cap_s=SUGGEST_MEASURE_CAP_S,
                      protect=_protect_list(cat))
        checks = ["dedupe: ok"] + v["checks"]
        tr = _agent_trust(cat, agent)
        thr = trust_threshold()
        ident, ident_detail = identity_of(agent, identity_proof)
        status, why = "refused", v["why"]
        if v["ok"]:
            ev, ev_detail = _verify_evidence(evidence, v, now)
            checks.append(f"evidence: {ev} ({ev_detail})")
            if ev == "mismatch":
                status, why = "refused", f"evidence does not match the path: {ev_detail}"
            else:
                blockers = []
                if v["cls"] not in REGENERABLE_CLASSES:
                    blockers.append(f"class {v['cls']} is not regenerable")
                if action != "quarantine":
                    blockers.append(f"action {action} is never auto-approved")
                if ev != "verified":
                    blockers.append(f"evidence {ev}")
                if not v["nested_ok"]:
                    blockers.append(f"nested work tree: {v['nested_why']}")
                if ident == "unverified":
                    blockers.append(f"identity unverified ({ident_detail})")
                if tr < thr:
                    blockers.append(f"trust {tr:.2f} < {thr:.2f}")
                checks.append(f"identity: {ident} ({ident_detail})")
                checks.append(f"trust: {agent} {tr:.2f} (threshold {thr:.2f})")
                if blockers:
                    status = "pending-card"
                    why = "needs a decision card: " + "; ".join(blockers)
                else:
                    status = "auto-approved"
                    why = (f"regenerable {v['cls']}, quarantine, evidence verified, "
                           f"identity {ident}, trust {tr:.2f} >= {thr:.2f}")
        expires = (datetime.now(timezone.utc) + timedelta(days=float(ttl_days))
                   ).isoformat(timespec="seconds")
        sid = cat.put_suggestion({
            "node": whoami(), "path": p, "path_key": key, "action": action,
            "reason": reason, "suggested_by": agent, "evidence": evidence or {},
            "status": status, "why": why, "cls": v["cls"], "size": v["size"],
            "files": v["files"], "newest_mtime": v["newest_mtime"], "capped": v["capped"],
            "checks": checks, "expires_at": expires, "identity": ident,
            # kept so apply can RE-VERIFY the identity (never read `verified` off the row)
            "identity_proof": identity_proof if ident == "verified" else None})
        card_id = _raise_card(cat, sid) if status == "pending-card" else None
        return {"id": sid, "status": status, "why": why, "class": v["cls"],
                "size": v["size"], "checks": checks, "trust": round(tr, 4),
                "identity": ident, "card_id": card_id}
    finally:
        if own:
            cat.close()


def _expire(cat, rows: list[dict], *, write: bool) -> list[dict]:
    now = datetime.now(timezone.utc)
    out = []
    for r in rows:
        exp = _parse_ts(r.get("expires_at"))
        if r["status"] in OPEN_STATUSES and exp is not None and now >= exp:
            if write:
                cat.update_suggestion(r["id"], expect_status=r["status"], status="expired",
                                      why=f"expired at {r['expires_at']} unresolved")
            r = {**r, "status": "expired"}
        out.append(r)
    return out


def suggestions(status: str | None = None, limit: int = 50, catalog: Any = None
                ) -> list[dict]:
    """Suggestions newest first, optionally one status. Open ones past their ttl are
    reported (and recorded) as ``expired``."""
    if status is not None and status not in STATUSES:
        raise ValueError(f"status {status!r} not in {STATUSES}")
    cat, own = _open(catalog)
    try:
        rows = cat.list_suggestions(None if status == "expired" else status, limit=limit)
        rows = _expire(cat, rows, write=True)
        if status is not None:
            rows = [r for r in rows if r["status"] == status]
        return rows
    finally:
        if own:
            cat.close()


def resolve_suggestion(id: int, decision: str, *, card: dict | None = None,
                       catalog: Any = None) -> dict:
    """A human decision on a suggestion. ``reject`` needs no card (keeping is always
    safe). ``approve`` needs a decision card that passes ``manage.verify_card`` for
    THIS id -- the same signed-receipt check manage applies (the receipt's nonce is
    recorded in this catalog).

    Returns ``{id, ok, status, why}``.
    """
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be 'approve' or 'reject'")
    from . import manage

    cat, own = _open(catalog)
    try:
        s = cat.get_suggestion(int(id))
        if s is None:
            return {"id": int(id), "ok": False, "status": "missing",
                    "why": f"no suggestion {id}"}
        [s] = _expire(cat, [s], write=True)
        if s["status"] not in OPEN_STATUSES:
            return {"id": s["id"], "ok": False, "status": s["status"],
                    "why": f"suggestion {s['id']} is {s['status']}, not open"}
        if decision == "reject":
            cid = ""
            if card is not None:
                try:
                    cid, _ans = manage.card_decision(card, int(s["id"]), catalog=cat)
                except ApplyRefused:
                    cid = ""
            ok = cat.update_suggestion(
                s["id"], expect_status=s["status"], status="rejected",
                resolved_by=f"card:{cid}" if cid else "unattested",
                why=f"rejected ({'card ' + cid if cid else 'no card'})")
            return {"id": s["id"], "ok": ok, "status": "rejected" if ok else s["status"],
                    "why": "rejected" if ok else "changed concurrently; re-read it"}
        if s["status"] in ("approved", "auto-approved"):
            return {"id": s["id"], "ok": True, "status": s["status"],
                    "why": f"already {s['status']}"}
        try:
            cid = manage.verify_card(card, int(s["id"]), catalog=cat)
        except ApplyRefused as exc:
            return {"id": s["id"], "ok": False, "status": s["status"], "why": str(exc)}
        if s.get("card_raised") and str(s["card_raised"]) != cid:
            return {"id": s["id"], "ok": False, "status": s["status"],
                    "why": f"card {cid} is not the card raised for it ({s['card_raised']})"}
        try:
            manage.require_content(card, suggestion_content_digest(s), what="suggestion")
        except ApplyRefused as exc:
            return {"id": s["id"], "ok": False, "status": s["status"], "why": str(exc)}
        from .attest import receipt_digest
        ok = cat.update_suggestion(s["id"], expect_status="pending-card", status="approved",
                                   card_id=cid, approved_at=_now_iso(),
                                   resolved_by=f"card:{cid}", why=f"approved by card {cid}",
                                   card_snapshot=_card_dict(card),
                                   receipt_digest=receipt_digest(
                                       manage._get(card, "answer_receipt")["receipt"]))
        return {"id": s["id"], "ok": ok, "status": "approved" if ok else s["status"],
                "why": f"approved by card {cid}" if ok else "changed concurrently"}
    finally:
        if own:
            cat.close()


_CARD_FIELDS = ("id", "card_id", "status", "answer", "answered_via", "via", "answered_by",
                "answered_at", "created_at", "deadline", "facts", "answer_receipt", "title")


def _card_dict(card: Any) -> dict:
    """A JSON-safe copy of the verified card (a dict, or a DecisionCard object)."""
    import json

    if isinstance(card, Mapping):
        d = dict(card)
    else:
        d = {k: getattr(card, k) for k in _CARD_FIELDS if getattr(card, k, None) is not None}
    return json.loads(json.dumps(d, sort_keys=True, default=str))


def _approval_refusal(cat, s: Mapping[str, Any]) -> str | None:
    """None when an ``approved`` row still carries an owner approval that VERIFIES now;
    else why not. Never trusts ``status``, ``card_id`` or ``receipt_digest`` alone: the
    card must pass ``manage.verify_card`` (signature, owner, fresh sign-in, receipt age,
    nonce) and bind this row's content."""
    from . import manage
    from .attest import receipt_digest

    sid = int(s["id"])
    cid = str(s.get("card_id") or "")
    if not cid:
        return "status says approved but no approving card is recorded"
    want = str(s.get("receipt_digest") or "")
    if not want:
        return "status says approved but no receipt digest was recorded when it was resolved"
    if s.get("card_raised") and str(s["card_raised"]) != cid:
        return f"card {cid} is not the card raised for it ({s['card_raised']})"
    card: Any = None
    if _card_reader is not None:
        try:
            card = _card_reader(cid)
        except Exception as exc:  # noqa: BLE001 -- unreadable = unverifiable
            return f"card {cid} unreadable: {type(exc).__name__}: {exc}"
    if card is None:
        card = s.get("card_snapshot")
    if not card:
        return f"card {cid} is not available to re-verify"
    try:
        got = manage.verify_card(card, sid, catalog=cat)
        if got != cid:
            return f"card {got} is not the recorded approving card {cid}"
        manage.require_content(card, suggestion_content_digest(s), what="suggestion")
        env = manage._get(card, "answer_receipt")
        if receipt_digest(env["receipt"]) != want:
            return f"card {cid} carries a different receipt than the one recorded at approval"
    except ApplyRefused as exc:
        return str(exc)
    except (KeyError, TypeError) as exc:
        return f"card {cid} malformed: {type(exc).__name__}"
    return None


def revert_suggestion(id: int, *, catalog: Any = None) -> dict:
    """Put an applied, quarantined suggestion back; the agent's trust pays for it."""
    cat, own = _open(catalog)
    try:
        s = cat.get_suggestion(int(id))
        if s is None:
            return {"id": int(id), "ok": False, "why": f"no suggestion {id}"}
        if s["status"] != "applied" or not s.get("quarantine") or s.get("purged_at"):
            return {"id": s["id"], "ok": False,
                    "why": f"suggestion {s['id']} is {s['status']}"
                           + (" and purged" if s.get("purged_at") else "")
                           + "; only an applied, unpurged quarantine reverts"}
        try:
            origin = revert(Path(s["quarantine"]))
        except (ApplyRefused, OSError) as exc:
            return {"id": s["id"], "ok": False, "why": f"revert refused: {exc}"}
        cat.update_suggestion(s["id"], status="reverted", reverted_at=_now_iso(),
                              why=f"reverted to {origin}")
        cat.ledger(proposal_id=s["id"], node=s["node"], path=s["path"],
                   action=f"suggest:{s['action']}", outcome="reverted",
                   detail=f"by revert_suggestion; agent {s['suggested_by']}")
        return {"id": s["id"], "ok": True, "why": f"restored {origin}"}
    finally:
        if own:
            cat.close()


# -- apply ---------------------------------------------------------------------------

def _quarantine(item: str, sid: int) -> str:
    """Rename the item into <parent>/.awstorage-quarantine/suggest-<id>-<stamp>/ (the
    policy layout: ORIGIN + one payload, so `awstorage revert` works on it)."""
    parent = os.path.dirname(item.rstrip("/"))
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    qdir = Path(parent) / QUARANTINE_DIRNAME / f"{QUARANTINE_PREFIX}{sid}-{stamp}"
    qdir.mkdir(parents=True, exist_ok=False)
    (qdir / "ORIGIN").write_text(item, encoding="utf-8")
    try:
        move_no_follow(item, qdir / os.path.basename(item.rstrip("/")))
    except BaseException:
        import shutil
        shutil.rmtree(qdir, ignore_errors=True)
        raise
    return str(qdir).replace("\\", "/")


def _drift(s: dict, v: dict) -> str | None:
    rec_newest = s.get("newest_mtime")
    if rec_newest is not None and v["newest_mtime"] is not None and \
            float(v["newest_mtime"]) > float(rec_newest) + 1.0:
        return (f"newest mtime moved {float(v['newest_mtime']) - float(rec_newest):.0f}s "
                "since the suggestion (something wrote to it)")
    if not s.get("capped") and not v["capped"]:
        if s.get("size") is not None and int(s["size"]) != int(v["size"] or 0):
            return f"size {s['size']} -> {v['size']} since the suggestion"
        if s.get("files") is not None and int(s["files"]) != int(v["files"] or 0):
            return f"file count {s['files']} -> {v['files']} since the suggestion"
    return None


def apply_suggestions(*, dry_run: bool = True, harvest_to: Any = None, catalog: Any = None
                      ) -> dict:
    """Act on every approved / auto-approved suggestion. Receipt-shaped; never raises
    for an item problem. Exit code: 0 clean, 1 an item failed (kept, reported), 2 could
    not judge (catalog unreadable, bad floors).

    Per item: re-validate everything (refused -> ``drifted``), compare size / files /
    newest mtime with the suggestion (drift -> ``drifted``), harvest first (verified;
    a shelf drive under its floor keeps the item), then quarantine -- or, only with a
    card approval, delete / archive -- and record the outcome. A demoted auto
    suggestion (the agent's trust fell) goes back to ``pending-card``. Also: detects
    reverts done with ``awstorage revert`` and purges this plane's quarantines older
    than ``PURGE_AFTER_S``.
    """
    from .space import FloorsError, parse_floors, shelf_low

    shelf = Path(os.path.expanduser(str(harvest_to or Path.home() / ".aither" / "harvest")))
    rec: dict[str, Any] = {
        "tool": "awstorage apply-suggestions", "exit_code": 2, "started": _now_iso(),
        "finished": None, "dry_run": bool(dry_run), "items": [], "applied": 0,
        "bytes_freed": 0, "bytes_quarantined": 0, "bytes_harvested": 0,
        "files_harvested": 0, "drifted": 0, "demoted": 0, "harvest_skipped": [],
        "busy": [], "expired": 0, "reverts_detected": 0, "purged": [], "errors": [],
        "refused": 0,
        "warnings": [], "could_not_judge": [], "harvest_to": str(shelf).replace("\\", "/"),
    }
    cat = None
    own = False
    try:
        try:
            floors = parse_floors(None)
        except FloorsError as exc:
            raise SweepConfigError(str(exc)) from exc
        cat, own = _open(catalog)
        write = not dry_run
        now = time.time()
        # 1. housekeeping: stale `executing` (a crashed pass), expiry.
        for r in cat.list_suggestions("executing", limit=1000):
            at = _parse_ts(r.get("updated_at"))
            if at and (datetime.now(timezone.utc) - at).total_seconds() > EXECUTING_STALE_S \
                    and write:
                cat.update_suggestion(r["id"], expect_status="executing",
                                      status=r.get("prev_status") or "approved",
                                      why="recovered from a stale executing state")
        opened = cat.list_suggestions(list(OPEN_STATUSES), limit=10000)
        after = _expire(cat, opened, write=write)
        rec["expired"] = sum(1 for a in after if a["status"] == "expired")
        # 2. reverts done outside this module, and 3. purge of old quarantines.
        for s in cat.list_suggestions("applied", limit=10000):
            q = s.get("quarantine")
            if not q or s.get("purged_at"):
                continue
            if not os.path.isdir(q):
                if os.path.lexists(s["path"]):
                    rec["reverts_detected"] += 1
                    if write:
                        cat.update_suggestion(s["id"], status="reverted",
                                              reverted_at=_now_iso(),
                                              why="its quarantine was reverted")
                        cat.ledger(proposal_id=s["id"], node=s["node"], path=s["path"],
                                   action=f"suggest:{s['action']}", outcome="reverted",
                                   detail=f"detected; agent {s['suggested_by']}")
                elif write:
                    cat.update_suggestion(s["id"], purged_at=_now_iso(),
                                          why="quarantine gone (purged elsewhere)")
                continue
            at = _parse_ts(s.get("applied_at"))
            if at is None or (datetime.now(timezone.utc) - at).total_seconds() < PURGE_AFTER_S:
                continue
            row = {"id": s["id"], "entry": q}
            if write:
                removed, errs, busy = remove_tree_detail(q)
                row.update(bytes=removed, outcome="purged" if not (errs or busy) else
                           ("failed" if errs else "partial-busy"))
                rec["bytes_freed"] += removed
                if not errs and not busy:
                    cat.update_suggestion(s["id"], purged_at=_now_iso())
                if errs:
                    rec["errors"].append(f"purge {q}: {errs[0]}")
                cat.ledger(proposal_id=s["id"], node=s["node"], path=q,
                           action=f"suggest:{s['action']}", outcome=row["outcome"],
                           bytes_=removed, detail="suggestion quarantine purge")
            else:
                row["outcome"] = "dry-run"
            rec["purged"].append(row)
        # 4. act.
        todo = [a for a in after if a["status"] in ("auto-approved", "approved")]
        todo.sort(key=lambda r: r["id"])
        thr = trust_threshold()
        for s in todo:
            _apply_one(rec, cat, s, now=now, write=write, shelf=shelf, floors=floors,
                       thr=thr, shelf_low=shelf_low)
    except SweepConfigError as exc:
        rec["could_not_judge"].append(str(exc))
    except Exception as exc:  # noqa: BLE001 -- the receipt is the answer, always
        rec["could_not_judge"].append(f"internal error: {type(exc).__name__}: {exc}")
    finally:
        rec["exit_code"] = 2 if rec["could_not_judge"] else 1 if rec["errors"] else 0
        rec["finished"] = _now_iso()
        if own and cat is not None:
            cat.close()
    return rec


def _apply_one(rec: dict, cat, s: dict, *, now: float, write: bool, shelf: Path,
               floors: dict, thr: float, shelf_low) -> None:
    sid, item, action = int(s["id"]), s["path"], s["action"]
    row: dict[str, Any] = {"id": sid, "path": item, "action": action,
                           "suggested_by": s["suggested_by"], "lane": s["status"]}
    rec["items"].append(row)

    def ledger(outcome: str, bytes_: int = 0, detail: str = "") -> None:
        if write:
            cat.ledger(proposal_id=sid, node=s["node"], path=item, action=f"suggest:{action}",
                       outcome=outcome, bytes_=bytes_,
                       detail=(f"agent {s['suggested_by']}: " + detail)[:1000])

    def drifted(why: str) -> None:
        row.update(outcome="drifted", reason=why)
        rec["drifted"] += 1
        if write:
            cat.update_suggestion(sid, expect_status=s["status"], status="drifted",
                                  outcome="drifted", why=why[:1000])
        ledger("drifted", detail=why)

    # An approval is re-verified, never read off the row (catalog.db is editable).
    if s["status"] == "approved":
        why = _approval_refusal(cat, s)
        if why:
            row.update(outcome="refused", reason=f"approval does not verify: {why}")
            rec["refused"] += 1
            rec["errors"].append(f"#{sid} {item}: approval does not verify: {why}")
            if write:
                cat.update_suggestion(sid, expect_status="approved", status="refused",
                                      outcome="refused",
                                      why=f"approval does not verify at apply: {why}"[:1000])
            ledger("refused", detail=f"approval does not verify: {why}")
            return
    # An auto approval is only as good as the trust it was granted on.
    if s["status"] == "auto-approved":
        tr = _agent_trust(cat, s["suggested_by"])
        ident_ok = _identity_holds(s)
        if not ident_ok or tr < thr or action != "quarantine" \
                or s.get("cls") not in REGENERABLE_CLASSES:
            why = (f"auto lane withdrawn: identity {s.get('identity') or 'unverified'}"
                   if not ident_ok else
                   f"auto lane withdrawn: trust {tr:.2f} < {thr:.2f}" if tr < thr else
                   "auto lane withdrawn: not a regenerable quarantine")
            row.update(outcome="demoted", reason=why)
            rec["demoted"] += 1
            if write:
                cat.update_suggestion(sid, expect_status="auto-approved",
                                      status="pending-card", approved_at=None, why=why)
                _raise_card(cat, sid)
            return
    v = _validate(item, now=now, env=None, measure_cap_s=APPLY_MEASURE_CAP_S,
                  protect=_protect_list(cat) + [str(shelf)])
    if not v["ok"]:
        return drifted(f"re-validation refused: {v['why']}")
    if s["status"] == "auto-approved" and v["cls"] not in REGENERABLE_CLASSES:
        return drifted(f"class is now {v['cls']}, not regenerable")
    if s["status"] == "auto-approved" and not v["nested_ok"]:
        return drifted(f"nested work tree: {v['nested_why']}")
    if s["status"] == "auto-approved":
        ev, ev_detail = _verify_evidence(s.get("evidence"), v, now)
        if ev != "verified":
            return drifted(f"evidence no longer verifies ({ev}: {ev_detail})")
    d = _drift(s, v)
    if d:
        return drifted(d)
    m = v["m"]
    rule = {"name": SHELF_RULE, "harvest": dict(DEFAULT_HARVEST)}
    low = shelf_low(shelf, floors)
    if low and not (action == "delete" and same_volume(str(shelf), item)):
        plan = harvest_item(item, rule, m, shelf, write=False, now=now)
        if plan["dir"]:
            rec["harvest_skipped"].append({"id": sid, "path": item, "why": low})
            row.update(outcome="harvest-skipped", reason=f"harvest-skipped: {low}; kept")
            ledger("harvest-skipped", detail=low)
            return
    if action == "archive" and _archive_hook is None:
        row.update(outcome="waiting", reason="archive needs an archive hook "
                                             "(set_archive_hook); kept, still approved")
        return
    if not write:
        h = harvest_item(item, rule, m, shelf, write=False, now=now)
        row.update(outcome="dry-run", reason=f"would harvest {len(h['harvested'])} file(s), "
                                             f"then {action}", bytes=m["bytes"])
        return
    if not cat.update_suggestion(sid, expect_status=s["status"], status="executing",
                                 prev_status=s["status"]):
        row.update(outcome="skipped", reason="changed concurrently")
        return
    h = harvest_item(item, rule, m, shelf, write=True, now=now)
    row["harvest"] = {"files": len(h["harvested"]), "bytes": h["bytes"], "dir": h["dir"],
                      "withheld": h["withheld"]}
    if not h["ok"]:
        cat.update_suggestion(sid, status=s["status"], why=f"harvest failed: {h['error']}")
        row.update(outcome="failed", reason=f"harvest: {h['error']}; kept")
        rec["errors"].append(f"#{sid} {item}: harvest: {h['error']}")
        ledger("failed", detail=f"harvest: {h['error']}")
        return
    rec["bytes_harvested"] += h["bytes"]
    rec["files_harvested"] += len(h["harvested"])
    size = int(m["bytes"])
    try:
        if action == "quarantine" or action == "archive":
            detail = ""
            if action == "archive":
                a = _archive_hook(Path(item), dict(s)) if _archive_hook else {}
                if not a.get("ok"):
                    raise ApplyRefused(f"archive hook: {a.get('detail') or 'not ok'}")
                detail = f"archived ({a.get('detail', '')}); "
            q = _quarantine(item, sid)
            rec["bytes_quarantined"] += size
            outcome, freed = "applied", 0
            detail += f"quarantined to {q}"
            fields = {"quarantine": q}
        else:  # delete -- only ever reached from a card approval (auto lane quarantines)
            removed, errs, busy = remove_tree_detail(item)
            rec["bytes_freed"] += removed
            if errs:
                raise OSError(f"delete incomplete: {len(errs)} error(s), first {errs[0]}")
            outcome = "partial-busy" if busy else "applied"
            if busy:
                rec["busy"].append({"id": sid, "path": item, "bytes_freed": removed,
                                    "first": busy[0]})
            freed, q = removed, None
            detail = f"deleted {removed} bytes" + (f"; busy: {busy[0]}" if busy else "")
            fields = {}
    except (OSError, ApplyRefused) as exc:
        from ._fs import is_busy_error
        if isinstance(exc, OSError) and is_busy_error(exc):
            cat.update_suggestion(sid, status=s["status"], why="in use; retried next pass")
            rec["busy"].append({"id": sid, "path": item, "bytes_freed": 0,
                                "first": type(exc).__name__})
            row.update(outcome="skipped-busy", reason=f"in use ({type(exc).__name__})")
            ledger("skipped-busy", detail=type(exc).__name__)
            return
        cat.update_suggestion(sid, status="failed", outcome="failed",
                              why=f"{type(exc).__name__}: {exc}"[:1000])
        row.update(outcome="failed", reason=f"{type(exc).__name__}: {exc}")
        rec["errors"].append(f"#{sid} {item}: {exc}")
        ledger("failed", detail=str(exc))
        return
    cat.update_suggestion(sid, status="applied", applied_at=_now_iso(), outcome=outcome,
                          bytes_freed=freed, harvest=row["harvest"], why=detail[:1000],
                          **fields)
    rec["applied"] += 1
    row.update(outcome=outcome, reason=detail, bytes=size)
    ledger(outcome, size, detail)


__all__ = [
    "MIN_TRUST_THRESHOLD",
    "OPEN_STATUSES",
    "REGENERABLE_CLASSES",
    "SUGGEST_ACTIONS",
    "TRUST_INPROCESS_ENV",
    "TRUST_THRESHOLD",
    "apply_suggestions",
    "card_spec",
    "classify_path",
    "identity_of",
    "resolve_suggestion",
    "revert_suggestion",
    "set_archive_hook",
    "set_card_hook",
    "set_card_reader",
    "set_identity_verifier",
    "suggest",
    "suggestion_content_digest",
    "suggestions",
    "trust",
    "trust_score",
    "trust_threshold",
]
