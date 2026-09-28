"""Retention sweep: the half of awstorage that runs unattended.

`scan -> propose -> apply` needs a person between the steps, which is right for
a 4 TB data drive and useless for the thing that actually filled drive C: on
2026-09-27: 173 GB of per-session agent scratchpads under
%LOCALAPPDATA%\\Temp\\claude\\<project>\\<session>\\ that nothing ever reaped (one
dead session alone held 106 GB of review-tree copies), plus ~19k stale top-level
Temp entries. The drive reached 122 MB free and corrupted a WSL root fs mid-boot.

A sweep is one pass of:

    expand rules -> measure -> guard -> harvest -> remove -> ledger -> receipt

and every stage exists because leaving it out loses something:

* A RULE names what may be swept (a glob; one match = one item), how idle it
  must be, and what to do with it. Presets ship, but nothing is swept unless a
  rule is NAMED -- a sweeper that sweeps by default is the next incident.
* AGE is the newest mtime anywhere INSIDE the item, never the item's own entry:
  a directory's mtime moves only when its direct children are renamed, so a
  session writing deep inside `tasks/` would read as idle for days.
* The LIVE GUARD skips an item that changed inside the live window or whose name
  a running agent registered (AWSTORAGE_LIVE_IDS / --live-ids) -- the scratchpad
  of the session running the sweep is the first thing a naive sweeper deletes.
* HARVEST copies the small text that outlives a session (reports, evals, results,
  notes) to a shelf BEFORE removal, verifies every copy by size and sha256, and
  keeps the item when any of that fails. Files matching a credential pattern are
  withheld and listed by name only -- a harvest shelf must not become the place
  secrets go to live forever.
* REMOVAL never follows a symlink or junction (`_fs.remove_tree`), quarantines by
  default (revert works), and deletes only when the rule says `delete` AND the
  caller said yes. A quarantine is reclaimed after the rule's `purge_after`.
* Every decision is LEDGERED (catalog) and optionally AUDITED (awdit), and the
  RECEIPT is written on every exit path -- a scheduled sweep whose failure leaves
  no receipt is indistinguishable from one that never ran.

Stdlib only. The couplings (awdit, awseal, awshare, awm, awrecover) live in
`integrations.py` and are imported lazily, each answering "unavailable" honestly.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ._fs import is_link, long_path, remove_tree, walk_no_follow
from .classify import CLASSES
from .policy import NEVER_AUTO, QUARANTINE_DIRNAME, ApplyRefused, list_quarantine, move_no_follow

LIVE_IDS_ENV = "AWSTORAGE_LIVE_IDS"
SWEEP_ACTIONS = ("quarantine", "delete")
SWEEP_PREFIX = "sweep-"
MANIFEST_NAME = "manifest.json"
# Root-level names the shelf writes itself; a harvested file must not overwrite them.
RESERVED_NAMES = frozenset({MANIFEST_NAME, "awseal.json"})

DEFAULT_HARVEST: dict[str, Any] = {
    "include": ["**/*.md", "**/*.json", "**/*report*", "**/*eval*/**", "**/results/**"],
    "max_file_kb": 512,
    "max_total_mb": 20,
    # An item that yielded nothing still gets a manifest (what it held, its largest
    # subdirs) when it was at least this big -- the 106 GB tree deserves a record;
    # 19k empty temp stubs a day do not deserve 19k shelf dirs.
    "manifest_min_mb": 64,
}
DEFAULT_LIVE_WINDOW = "2h"
BINARY_SNIFF_BYTES = 8192
TOP_SUBDIRS = 20
MAX_SKIPPED_LISTED = 2000

# Credential shapes. Deliberately broad: a withheld report costs a re-read of the
# live item, a harvested key costs a rotation. The MATCH is never written anywhere.
_SECRET_RX = re.compile(
    r"(?:"
    r"\bsk-[A-Za-z0-9_\-]{16,}"                       # openai / anthropic (sk-ant-, sk-proj-)
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}"                  # github tokens (ghp_, ghs_, ...)
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bAKIA[0-9A-Z]{16}\b"                          # aws access key id
    r"|\bxox[bpas]-[A-Za-z0-9\-]{10,}"                # slack
    r"|\b[sp]k_live_[A-Za-z0-9]{10,}"                 # stripe
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"|\b(?:password|passwd|pwd|api[_\-]?key|secret[_\-]?key|client[_\-]?secret)"
    r"\s*[:=]\s*['\"]?[^\s'\"<>{}]{4,}"
    r")",
    re.IGNORECASE,
)


class SweepConfigError(ValueError):
    """A rule or policy that cannot be judged. The sweep exits 2, acting on nothing."""


# -- rules -------------------------------------------------------------------------

_DUR_RX = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$", re.I)
_DUR_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}


def parse_duration(v: str | float | int) -> float:
    """'12h' / '3d' / '90m' / '45' (seconds) -> seconds."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if v < 0:
            raise SweepConfigError(f"negative duration {v!r}")
        return float(v)
    m = _DUR_RX.match(str(v))
    if not m:
        raise SweepConfigError(f"cannot parse duration {v!r} (want e.g. '12h', '3d')")
    return float(m.group(1)) * _DUR_UNIT[m.group(2).lower()]


def human_duration(seconds: float) -> str:
    s = float(seconds)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{s / n:.1f}{unit}".replace(".0" + unit, unit)
    return f"{int(s)}s"


_PCT_VAR = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")
_DOLLAR_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _env_value(name: str, env: Mapping[str, str]) -> str:
    v = env.get(name)
    if v:
        return v
    # TMPDIR is unset on most Linux boxes; the platform temp dir IS what it means.
    if name.upper() in ("TMPDIR", "TEMP", "TMP"):
        return tempfile.gettempdir()
    raise SweepConfigError(f"variable {name} is not set; the rule path cannot be resolved")


def expand_path(pattern: str, env: Mapping[str, str] | None = None) -> str:
    """Expand %VAR%, $VAR, ${VAR} and ~ on any OS; forward slashes out.

    An unset variable is a config error, never an empty string: `%LOCALAPPDATA%/Temp/*`
    silently becoming `/Temp/*` is the kind of expansion a sweeper must not guess at.
    """
    e = os.environ if env is None else env
    s = _PCT_VAR.sub(lambda m: _env_value(m.group(1), e), pattern)
    s = _DOLLAR_VAR.sub(lambda m: _env_value(m.group(1) or m.group(2), e), s)
    s = os.path.expanduser(s)
    return s.replace("\\", "/")


def static_base(pattern: str) -> str:
    """The longest leading directory of an expanded glob that holds no wildcard."""
    parts = pattern.split("/")
    out: list[str] = []
    for p in parts:
        if any(c in p for c in "*?["):
            break
        out.append(p)
    if len(out) == len(parts):  # no wildcard at all: the item's parent is the base
        out = out[:-1]
    base = "/".join(out)
    if re.fullmatch(r"[A-Za-z]:", base):
        base += "/"
    return base or "/"


def glob_to_regex(pattern: str) -> re.Pattern:
    """`**/` = zero or more directories, `*`/`?` stay inside one segment.

    fnmatch lets `*` cross `/`, which makes `*.md` match every file in a tree and
    `**/results/**` impossible to spell; harvest globs need the gitignore meaning.
    Case-insensitive always: over-matching a harvest or an exclude is the safe side.
    """
    pat = pattern.replace("\\", "/")
    i, out = 0, []
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out.append("(?:/.*)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$", re.I)


def presets() -> dict[str, dict]:
    """The shipped retention rules. Opt-in BY NAME; `default_policy()` enables none."""
    if os.name == "nt":
        temp = "%LOCALAPPDATA%/Temp"
    else:
        temp = "$TMPDIR"
    return {
        "agent-scratch": {
            "name": "agent-scratch",
            "paths": [f"{temp}/claude/*/*"],
            "class": "build-temp",
            "max_idle": "12h",
            "action": "quarantine",
            "purge_after": "24h",
            "harvest": dict(DEFAULT_HARVEST),
            "live_guard": {"window": DEFAULT_LIVE_WINDOW},
            "why": "per-session agent scratchpads + task outputs; 173 GB unreaped on "
                   "2026-09-27. 12h idle outlives any session we run; harvest keeps the "
                   "reports, the quarantine keeps a day to change your mind",
        },
        "temp-toplevel": {
            "name": "temp-toplevel",
            "paths": [f"{temp}/*"],
            "exclude": [f"{temp}/claude"],
            "class": "build-temp",
            "max_idle": "3d",
            "action": "quarantine",
            "purge_after": "3d",
            "harvest": dict(DEFAULT_HARVEST),
            "live_guard": {"window": DEFAULT_LIVE_WINDOW},
            "why": "installer/extractor leftovers; ~19k stale entries measured 2026-09-27. "
                   "The agent-scratch tree has its own rule and is excluded here",
        },
    }


def validate_rule(rule: Mapping[str, Any]) -> dict:
    """Normalise one rule or raise SweepConfigError naming the field."""
    if not isinstance(rule, Mapping):
        raise SweepConfigError(f"a rule must be a mapping, got {type(rule).__name__}")
    name = str(rule.get("name") or "").strip()
    if not name or not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        raise SweepConfigError(f"rule name {name!r} must be [A-Za-z0-9_.-]+ (it names dirs)")
    paths = rule.get("paths")
    if isinstance(paths, str):
        paths = [paths]
    if not paths or not all(isinstance(p, str) and p.strip() for p in paths):
        raise SweepConfigError(f"rule {name}: `paths` must be a non-empty list of globs")
    cls = rule.get("class", rule.get("cls", "build-temp"))
    if cls not in CLASSES:
        raise SweepConfigError(f"rule {name}: class {cls!r} is not one of {CLASSES}")
    if cls in NEVER_AUTO:
        # The same wall `apply` keeps: an unattended sweep is the most auto thing here.
        raise SweepConfigError(f"rule {name}: class {cls!r} is never auto-applied, so no "
                               "retention rule may sweep it")
    action = rule.get("action", "quarantine")
    if action not in SWEEP_ACTIONS:
        raise SweepConfigError(f"rule {name}: action {action!r} not in {SWEEP_ACTIONS}")
    if "max_idle" not in rule:
        raise SweepConfigError(f"rule {name}: `max_idle` is required (e.g. '12h')")
    max_idle = parse_duration(rule["max_idle"])
    purge_after = rule.get("purge_after")
    harvest = rule.get("harvest", DEFAULT_HARVEST)
    if harvest in (None, True):
        harvest = DEFAULT_HARVEST
    if harvest is not False:
        if not isinstance(harvest, Mapping):
            raise SweepConfigError(f"rule {name}: `harvest` must be a mapping or false")
        harvest = {**DEFAULT_HARVEST, **harvest}
        if not isinstance(harvest["include"], list):
            raise SweepConfigError(f"rule {name}: harvest.include must be a list")
    live = rule.get("live_guard")
    if live is True:
        live = {}
    if live is not None and not isinstance(live, Mapping):
        raise SweepConfigError(f"rule {name}: `live_guard` must be a mapping")
    snap = rule.get("snapshot", False)
    if snap not in (True, False) and not isinstance(snap, Mapping):
        raise SweepConfigError(f"rule {name}: `snapshot` must be true/false or a mapping")
    return {
        "name": name,
        "paths": list(paths),
        "exclude": list(rule.get("exclude") or []),
        "class": cls,
        "max_idle": max_idle,
        "action": action,
        "purge_after": None if purge_after is None else parse_duration(purge_after),
        "harvest": harvest,
        "live_guard": None if live is None else {
            "window": parse_duration(live.get("window", DEFAULT_LIVE_WINDOW)),
            "ids": [str(x) for x in (live.get("ids") or [])],
        },
        "snapshot": snap,
        "why": str(rule.get("why", "")),
    }


def resolve_rules(names: Iterable[str] | None, policy: Mapping[str, Any] | None = None
                  ) -> list[dict]:
    """Names -> validated rules: the policy's `retention` list first, then presets.

    With no names, the policy's own retention rules run (a policy file you wrote is
    itself the act of naming them); with neither, nothing does -- that is an error,
    not an empty success.
    """
    declared = {}
    for r in (policy or {}).get("retention", []) or []:
        if isinstance(r, Mapping) and r.get("name"):
            declared[str(r["name"])] = r
    wanted = [n.strip() for n in (names or []) if n and n.strip()]
    if not wanted:
        wanted = list(declared)
    if not wanted:
        raise SweepConfigError("no retention rule named; presets: "
                               + ", ".join(sorted(presets())))
    out, pre = [], presets()
    for n in wanted:
        src = declared.get(n) or pre.get(n)
        if src is None:
            raise SweepConfigError(f"unknown rule {n!r}; declared: {sorted(declared)}, "
                                   f"presets: {sorted(pre)}")
        out.append(validate_rule({"name": n, **src}))
    return out


# -- volumes -----------------------------------------------------------------------

def _existing_ancestor(p: str) -> str:
    cur = os.path.abspath(p)
    while not os.path.exists(cur):
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return cur


def volume_key(p: str) -> str:
    """Drive letter on Windows, st_dev elsewhere -- the unit disk space is freed in."""
    anc = _existing_ancestor(p)
    if os.name == "nt":
        drive = os.path.splitdrive(anc)[0]
        return drive.upper() if drive else anc
    try:
        return f"dev:{os.stat(anc).st_dev}"
    except OSError:
        return anc


def same_volume(a: str, b: str) -> bool:
    return volume_key(a) == volume_key(b)


def _disk_free(p: str) -> int:
    return int(shutil.disk_usage(_existing_ancestor(p)).free)


# -- measure -----------------------------------------------------------------------

def measure(path: str, include: list[re.Pattern] | None = None, *,
            stop_newer_than: float | None = None, deadline: float | None = None) -> dict:
    """Bytes, counts, newest mtime INSIDE the item, largest subdirs, harvest candidates.

    `stop_newer_than` (epoch): the walk stops at the first file newer than this and
    sets early="fresh" -- such an item cannot be eligible, and walking the rest of a
    live 100 GB scratch tree to learn that is what made the first real dry run
    overrun 15 minutes. `deadline` (monotonic): stop and set early="budget".

    Newest mtime covers the FILES below the item, never the item's own
    entry (its mtime says only that a direct child was renamed). A tree with no
    files falls back to its subdirectories' and links' mtimes, then to its own -- there is
    nothing else to judge by.
    """
    p = long_path(path)
    out = {"bytes": 0, "files": 0, "dirs": 0, "links": 0, "newest_mtime": 0.0,
           "kind": "dir", "top_subdirs": [], "candidates": [], "errors": 0}
    try:
        st = os.lstat(p)
    except OSError:
        out["errors"] = 1
        out["kind"] = "missing"
        return out
    if is_link(p):
        out.update(kind="link", links=1, newest_mtime=st.st_mtime)
        return out
    if not stat.S_ISDIR(st.st_mode):
        if not stat.S_ISREG(st.st_mode):
            out.update(kind="special", newest_mtime=st.st_mtime)
            return out
        out.update(kind="file", bytes=int(st.st_size), files=1, newest_mtime=st.st_mtime)
        name = os.path.basename(path.rstrip("/\\"))
        if include and any(rx.match(name) for rx in include):
            out["candidates"].append((name, int(st.st_size), p, False))
        return out
    sub: dict[str, int] = {}
    newest = 0.0
    newest_dir = 0.0
    for d, dirs, files, links in walk_no_follow(p):
        if deadline is not None and time.monotonic() >= deadline:
            out["early"] = "budget"
            break
        rel_d = os.path.relpath(d, p).replace("\\", "/")
        rel_d = "" if rel_d == "." else rel_d
        segs = rel_d.split("/") if rel_d else []
        keys = ["/".join(segs[:k]) for k in (1, 2) if len(segs) >= k]
        for e in dirs:
            out["dirs"] += 1
            try:
                newest_dir = max(newest_dir, e.stat(follow_symlinks=False).st_mtime)
            except OSError:
                out["errors"] += 1
        for e in links:
            out["links"] += 1
            try:
                # A link's own mtime is when it was MADE, not when anything was
                # written; it counts like a directory, only when no file speaks.
                newest_dir = max(newest_dir, e.stat(follow_symlinks=False).st_mtime)
            except OSError:
                out["errors"] += 1
            if include:
                rel = f"{rel_d}/{e.name}" if rel_d else e.name
                if any(rx.match(rel) for rx in include):
                    out["candidates"].append((rel, 0, e.path, True))
        for e in files:
            try:
                fst = e.stat(follow_symlinks=False)
            except OSError:
                out["errors"] += 1
                continue
            size = int(fst.st_size)
            out["files"] += 1
            out["bytes"] += size
            newest = max(newest, fst.st_mtime)
            if stop_newer_than is not None and fst.st_mtime > stop_newer_than:
                out["early"] = "fresh"
            for k in keys:
                sub[k] = sub.get(k, 0) + size
            if include:
                rel = f"{rel_d}/{e.name}" if rel_d else e.name
                if any(rx.match(rel) for rx in include):
                    out["candidates"].append((rel, size, e.path, False))
            if out.get("early"):
                break
        if out.get("early"):
            break
    out["newest_mtime"] = newest or newest_dir or st.st_mtime
    out["top_subdirs"] = [{"path": k, "bytes": v} for k, v in
                          sorted(sub.items(), key=lambda kv: -kv[1])[:TOP_SUBDIRS]]
    return out


# -- harvest -----------------------------------------------------------------------

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(p: str) -> tuple[int, str]:
    h = hashlib.sha256()
    n = 0
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def _item_shelf_dir(day_dir: Path, name: str, origin: str) -> Path:
    """<day>/<item-name>, suffixed when a DIFFERENT origin already owns that name."""
    cand = day_dir / name
    n = 1
    while (cand / MANIFEST_NAME).is_file():
        try:
            prev = json.loads((cand / MANIFEST_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prev = {}
        if prev.get("item") == origin:
            return cand
        n += 1
        cand = day_dir / f"{name}-{n}"
    return cand


def harvest_item(item: str, rule: dict, m: dict, shelf: Path, *, write: bool,
                 offdrive: bool = False, now: float | None = None) -> dict:
    """Copy an item's small text files to the shelf and PROVE every copy.

    Returns {"ok", "dir", "harvested", "skipped", "bytes", "error"}. `ok` False means
    the item must be kept. With write=False this is the plan: files are selected,
    sniffed and screened, nothing is written.
    """
    cfg = rule["harvest"]
    res: dict[str, Any] = {"ok": True, "dir": None, "harvested": [], "skipped": [],
                           "withheld": 0, "bytes": 0, "error": None}
    if cfg is False:
        return res
    if offdrive and same_volume(str(shelf), item):
        res.update(ok=False, error=f"harvest shelf {shelf} is on the same drive as {item} "
                                   "and --harvest-offdrive is set")
        return res
    max_file = int(cfg["max_file_kb"]) * 1024
    budget = int(float(cfg["max_total_mb"]) * 1024 * 1024)
    name = os.path.basename(item.rstrip("/\\")) or "item"
    day = time.strftime("%Y-%m-%d", time.localtime(now or time.time()))
    day_dir = shelf / rule["name"] / day
    dest_dir = _item_shelf_dir(day_dir, name, item) if write else day_dir / name
    res["dir"] = str(dest_dir).replace("\\", "/")
    total = 0
    skipped = res["skipped"]

    def skip(rel: str, why: str) -> None:
        if len(skipped) < MAX_SKIPPED_LISTED:
            skipped.append({"path": rel, "reason": why})

    for rel, size, src, linked in sorted(m["candidates"]):
        if linked:
            skip(rel, "link (not followed)")
            continue
        if rel.lower() in RESERVED_NAMES:
            skip(rel, "reserved name (the shelf's own manifest/seal)")
            continue
        if size > max_file:
            skip(rel, "too-large")
            continue
        if total + size > budget:
            skip(rel, "budget")
            continue
        try:
            with open(src, "rb") as f:
                data = f.read(max_file + 1)
        except OSError as exc:
            skip(rel, f"unreadable: {type(exc).__name__}")
            continue
        if len(data) > max_file:
            skip(rel, "too-large")
            continue
        if b"\x00" in data[:BINARY_SNIFF_BYTES]:
            skip(rel, "binary")
            continue
        if _SECRET_RX.search(data.decode("utf-8", errors="replace")):
            skip(rel, "withheld: secret-pattern")
            res["withheld"] += 1
            continue
        digest = _sha256_bytes(data)
        if write:
            # The bytes written are the bytes screened: one read, no second open
            # of the source for a file that may be changing under us.
            dest = dest_dir / rel
            try:
                os.makedirs(long_path(dest.parent), exist_ok=True)
                with open(long_path(dest), "wb") as f:
                    f.write(data)
            except OSError as exc:
                res.update(ok=False, error=f"copy failed for {rel}: {type(exc).__name__}: {exc}")
                return res
        res["harvested"].append({"path": rel, "bytes": len(data), "sha256": digest})
        total += len(data)
    res["bytes"] = total
    manifest = {
        "schema": 1,
        "item": item,
        "rule": rule["name"],
        "harvested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "node": socket.gethostname(),
        "total_bytes": m["bytes"],
        "file_count": m["files"],
        "top_subdirs": m["top_subdirs"],
        "harvested": res["harvested"],
        "skipped": skipped,
    }
    res["manifest"] = manifest
    if (not res["harvested"] and not res["withheld"]
            and m["bytes"] < float(cfg.get("manifest_min_mb", 64)) * 2**20):
        res["dir"] = None  # nothing worth a shelf entry; the ledger/audit keep the record
        return res
    if not write:
        return res
    # VERIFY before the caller may remove anything: size AND sha256 of every copy.
    for h in res["harvested"]:
        try:
            n, d = _sha256_file(long_path(dest_dir / h["path"]))
        except OSError as exc:
            res.update(ok=False, error=f"verify failed for {h['path']}: {type(exc).__name__}")
            return res
        if n != h["bytes"] or d != h["sha256"]:
            res.update(ok=False, error=f"verify failed for {h['path']}: shelf copy differs")
            return res
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        mp = dest_dir / MANIFEST_NAME
        text = json.dumps(manifest, indent=1, sort_keys=True)
        mp.write_text(text, encoding="utf-8")
        if mp.read_text(encoding="utf-8") != text:
            raise OSError("manifest read-back differs")
    except OSError as exc:
        res.update(ok=False, error=f"manifest write failed: {type(exc).__name__}: {exc}")
    return res


# -- live ids ----------------------------------------------------------------------

def load_live_ids(ids: Iterable[str] = (), ids_file: str | None = None,
                  env: Mapping[str, str] | None = None) -> set[str]:
    """Names a running agent registered as live: env list + file + explicit ids.

    The contract for an agent runtime (awdk registers its session scratch here):
    AWSTORAGE_LIVE_IDS is comma/semicolon/whitespace separated; the file holds one
    id per line, `#` comments allowed. An id matches an item's BASENAME,
    case-insensitively -- e.g. the session-id directory of a scratchpad.
    An unreadable --live-ids file raises: guessing "nobody is live" deletes live work.
    """
    e = os.environ if env is None else env
    out = {i.strip().lower() for i in ids if i and i.strip()}
    raw = e.get("AWSTORAGE_LIVE_IDS", "")
    out.update(t.lower() for t in re.split(r"[,;\s]+", raw) if t)
    if ids_file:
        try:
            text = Path(ids_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise SweepConfigError(f"cannot read --live-ids file {ids_file}: {exc}") from exc
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(line.lower())
    return out


# -- removal -----------------------------------------------------------------------

def _is_busy(exc: OSError) -> bool:
    # Windows sharing violation / access denied on a rename = something holds a
    # handle inside: the item is in use, which is a live signal, not a failure.
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in (5, 32, 33)


def _quarantine_item(item: str, base: str, rule_name: str, seq: int) -> tuple[str, str]:
    """Rename the item into <base>/.awstorage-quarantine/sweep-<rule>-<stamp>-<n>/.

    Same layout as `apply`'s quarantine (ORIGIN file + one payload), so
    `awstorage revert` and `list_quarantine` work on it unchanged. Returns
    (entry dir, payload path). Raises OSError; the caller maps busy vs failed.
    """
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    qdir = Path(base) / QUARANTINE_DIRNAME / f"{SWEEP_PREFIX}{rule_name}-{stamp}-{seq}"
    qdir.mkdir(parents=True, exist_ok=False)
    dest = qdir / os.path.basename(item.rstrip("/\\"))
    (qdir / "ORIGIN").write_text(item, encoding="utf-8")
    try:
        move_no_follow(item, dest)
    except BaseException:
        shutil.rmtree(qdir, ignore_errors=True)
        raise
    return str(qdir).replace("\\", "/"), str(dest).replace("\\", "/")


def _protected(item: str, protect: list[str]) -> str | None:
    """A path the sweep itself depends on (shelf, receipt, catalog, cwd, python)."""
    it = os.path.normcase(os.path.abspath(item)).rstrip("\\/")
    for p in protect:
        pp = os.path.normcase(os.path.abspath(p)).rstrip("\\/")
        if pp == it or pp.startswith(it + os.sep) or pp.startswith(it + "/"):
            return p
    return None


# -- the sweep ---------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_receipt(path: str | Path, receipt: dict) -> None:
    """Atomic: a reader never sees half a receipt, a crash never leaves a stale one
    that reads as this run."""
    p = Path(os.path.expanduser(str(path)))
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(receipt, indent=1, sort_keys=True, default=str),
                   encoding="utf-8")
    os.replace(tmp, p)


def sweep(
    rules: Iterable[str] | None = None,
    *,
    policy: Mapping[str, Any] | None = None,
    dry_run: bool = True,
    harvest_to: str | Path | None = None,
    harvest_offdrive: bool = False,
    emergency_free_gb: float | None = None,
    receipt: str | Path | None = None,
    catalog: Any = None,
    live_ids: Iterable[str] = (),
    live_ids_file: str | None = None,
    audit_log: str | Path | None = None,
    require_audit: bool = False,
    seal_key: str | Path | None = None,
    seal: bool = True,
    publish_to: str | Path | None = None,
    land_to_awm: str | None = None,
    awm_db: str | Path | None = None,
    snapshot_store: str | Path | None = None,
    now: float | None = None,
    env: Mapping[str, str] | None = None,
    disk_free: Callable[[str], int] | None = None,
    node: str | None = None,
    time_budget_s: float | None = None,
    strata_url: str | None = None,
    strata_insecure_http_for_tests: bool = False,
    strata_staging: str | Path | None = None,
) -> dict:
    """One retention pass. Returns the receipt dict (also written to `receipt`).

    Never raises for a sweep problem: every failure lands in the receipt with an
    exit_code -- 0 clean, 1 an item failed (kept, reported), 2 could not judge
    (bad rule, unreadable root, required audit unavailable; nothing removed).
    `catalog` is a Catalog or a path (ledger rows); None skips the ledger.
    `disk_free(path) -> bytes` and `now` exist so emergency mode is testable.
    `harvest_to="strata:<tier>"` ships each verified harvest to AitherStrata (see
    awstorage.strata); the local copy is staged under ~/.aither/awstorage/strata-staging
    and dropped once every object is verified remotely.
    `time_budget_s` stops the pass cleanly (receipt `truncated: true`, exit code
    unaffected) so a scheduler's hard timeout never kills it before the receipt lands.
    """
    from . import integrations as ig  # lazy: its siblings are all optional

    t_now = time.time() if now is None else float(now)
    free_fn = disk_free or _disk_free
    from .strata import StrataTarget, parse_spec

    strata = None
    strata_err = None
    try:
        tier = parse_spec(harvest_to)
    except ValueError as exc:
        tier, strata_err = None, str(exc)
    if tier:
        strata = StrataTarget(tier, url=strata_url, env=env,
                              insecure_http_for_tests=strata_insecure_http_for_tests)
        shelf = Path(os.path.expanduser(str(
            strata_staging or Path.home() / ".aither" / "awstorage" / "strata-staging")))
        harvest_offdrive = False  # the shelf is remote; the staging copy is transient
    else:
        shelf = Path(os.path.expanduser(str(harvest_to or Path.home() / ".aither" / "harvest")))
    rec: dict[str, Any] = {
        "tool": "awstorage sweep", "exit_code": 2, "started": _now_iso(), "finished": None,
        "dry_run": bool(dry_run), "rules": [], "items_seen": 0, "items_eligible": 0,
        "items_removed": 0, "bytes_freed": 0, "bytes_quarantined": 0, "bytes_harvested": 0,
        "files_harvested": 0, "withheld_secret": 0, "skipped_live": [], "skipped_busy": [],
        "kept_fresh": 0, "errors": [], "could_not_judge": [], "warnings": [], "notes": [],
        "emergency": [], "free_before": {}, "free_after": {}, "items": [], "purged": [],
        "harvest_to": (f"strata:{strata.tier}" if strata else str(shelf).replace("\\", "/")),
        "audit": None, "publish": [], "strata": None,
        "node": node or socket.gethostname(), "truncated": False, "resume_first": [],
    }
    cat = None
    own_cat = False
    try:
        if catalog is not None:
            if hasattr(catalog, "ledger"):
                cat = catalog
            else:
                from .catalog import Catalog
                cat = Catalog(os.path.expanduser(str(catalog)))
                own_cat = True
        _run(rec, rules=rules, policy=policy, dry_run=dry_run, shelf=shelf,
             harvest_offdrive=harvest_offdrive, emergency_free_gb=emergency_free_gb,
             cat=cat, live_ids=live_ids, live_ids_file=live_ids_file, audit_log=audit_log,
             require_audit=require_audit, seal_key=seal_key, seal=seal,
             publish_to=publish_to,
             land_to_awm=land_to_awm, awm_db=awm_db, snapshot_store=snapshot_store,
             t_now=t_now, env=env, free_fn=free_fn, ig=ig, time_budget_s=time_budget_s,
             strata=strata, strata_err=strata_err, receipt=receipt,
             protect=[str(p) for p in (receipt, getattr(cat, "path", None), audit_log,
                                       awm_db, snapshot_store) if p])
    except SweepConfigError as exc:
        rec["could_not_judge"].append(str(exc))
    except Exception as exc:  # noqa: BLE001 -- the receipt must be written regardless
        rec["could_not_judge"].append(f"internal error: {type(exc).__name__}: {exc}")
        rec["traceback"] = traceback.format_exc(limit=8)
    finally:
        if rec["could_not_judge"]:
            rec["exit_code"] = 2
        elif rec["errors"]:
            rec["exit_code"] = 1
        else:
            rec["exit_code"] = 0
        rec["finished"] = _now_iso()
        if own_cat and cat is not None:
            cat.close()
        if receipt:
            try:
                write_receipt(receipt, rec)
            except OSError as exc:
                rec["could_not_judge"].append(f"receipt not written: {exc}")
                rec["exit_code"] = 2
    return rec


def _run(rec: dict, *, rules, policy, dry_run, shelf: Path, harvest_offdrive,
         emergency_free_gb, cat, live_ids, live_ids_file, audit_log, require_audit,
         seal_key, seal, publish_to, land_to_awm, awm_db, snapshot_store, t_now, env,
         free_fn, ig, protect: list, time_budget_s: float | None, strata, strata_err,
         receipt=None) -> None:
    node = rec["node"]
    # An item the last pass ran out of budget on goes FIRST this time. Measured
    # 2026-09-27: a 25 GB session tree was cut at the 300 s mark; in sorted order it
    # would be reached late on every pass and never finish.
    resume: set = set()
    if receipt:
        try:
            prev = json.loads(Path(os.path.expanduser(str(receipt))).read_text(
                encoding="utf-8"))
            resume = {os.path.normcase(x) for x in prev.get("resume_first", []) or []}
        except (OSError, ValueError, AttributeError):
            resume = set()
    if strata_err:
        raise SweepConfigError(strata_err)
    deadline = (time.monotonic() + float(time_budget_s)) if time_budget_s else None
    if policy and policy.get("_error"):
        raise SweepConfigError(str(policy["_error"]))
    resolved = resolve_rules(rules, policy)
    rec["rules"] = [{"name": r["name"], "action": r["action"],
                     "max_idle": human_duration(r["max_idle"])} for r in resolved]
    live = load_live_ids(live_ids, live_ids_file, env)

    audit_on = audit_log is not None
    if audit_on:
        avail = ig.audit_available()
        rec["audit"] = {"log": str(audit_log), "available": avail["available"],
                        "reason": avail.get("reason")}
        if not avail["available"]:
            if require_audit:
                raise SweepConfigError("--require-audit is set and awdit is unavailable ("
                                       f"{avail.get('reason')}); refusing to remove anything")
            rec["warnings"].append(f"audit unavailable: {avail.get('reason')}")
            audit_on = False
    elif require_audit:
        raise SweepConfigError("--require-audit is set but no audit log is configured")
    if land_to_awm:
        ig.check_awm_scope(land_to_awm)  # a bad scope is a config error, up front
    if strata is not None:
        from .strata import StrataUnavailableError
        rec["strata"] = {"tier": strata.tier, "url": strata.url, "uploaded": 0,
                         "available": False}
        try:
            strata.check()
        except StrataUnavailableError as exc:
            # Nothing may be removed on the promise of a shelf that is not there.
            raise SweepConfigError(f"strata target unavailable: {exc}") from exc
        rec["strata"]["available"] = True

    def audit(event: str, **fields) -> bool:
        if not audit_on:
            return not require_audit
        r = ig.audit_append(audit_log, event, **fields)
        if not r.get("ok"):
            rec["warnings"].append(f"audit append failed: {r.get('reason')}")
        return bool(r.get("ok"))

    def ledger(path: str, rule: dict, outcome: str, bytes_: int = 0, detail: str = "") -> None:
        if cat is None:
            return
        cat.ledger(proposal_id=None, node=node, path=path,
                   action=f"sweep:{rule['name']}:{rule['action']}", outcome=outcome,
                   bytes_=bytes_, detail=detail[:1000] if detail else None)

    protect = list(protect) + [str(shelf), os.getcwd(), sys.prefix]
    seen: set[str] = set()
    vol_free: dict[str, int] = {}
    vol_label: dict[str, str] = {}
    emergency_vols: dict[tuple, bool] = {}
    touched_days: set[Path] = set()
    seq = 0

    def free_of(p: str) -> tuple[str, int]:
        k = volume_key(p)
        if k not in vol_free:
            vol_free[k] = int(free_fn(p))
            vol_label.setdefault(k, p)
        return k, vol_free[k]

    # Resolve EVERY rule's bases before touching any item: an unreadable root in the
    # second rule must stop the pass before the first rule has removed anything.
    plan: list[tuple[dict, list[tuple[str, str]]]] = []
    for rule in resolved:
        pats: list[tuple[str, str]] = []
        for pat in rule["paths"]:
            exp = expand_path(pat, env)
            base = static_base(exp)
            if not os.path.exists(base):
                rec["notes"].append(f"{rule['name']}: {base} does not exist; nothing to sweep")
                continue
            try:
                with os.scandir(base):
                    pass
            except OSError as exc:
                raise SweepConfigError(f"{rule['name']}: cannot read {base}: "
                                       f"{type(exc).__name__}") from exc
            pats.append((exp, base))
        plan.append((rule, pats))

    for rule, pats in plan:
        exclude_rx = [glob_to_regex(expand_path(x, env)) for x in rule["exclude"]]
        include_rx = ([glob_to_regex(g) for g in rule["harvest"]["include"]]
                      if rule["harvest"] is not False else None)
        live_rule = rule["live_guard"]
        rule_live = live | {i.lower() for i in (live_rule or {}).get("ids", [])}
        bases: list[str] = []
        for exp, base in pats:
            bases.append(base)
            k, f = free_of(base)
            rec["free_before"].setdefault(k, f)
            found = sorted(glob.glob(exp))
            found.sort(key=lambda x: os.path.normcase(x.replace("\\", "/")) not in resume)
            for raw in found:
                if deadline is not None and time.monotonic() >= deadline:
                    rec["truncated"] = True
                    break
                if rec["strata"] and not rec["strata"]["available"]:
                    break  # the shelf went away mid-pass: nothing more may be removed
                item = raw.replace("\\", "/")
                key = os.path.normcase(os.path.abspath(item))
                if key in seen:
                    continue
                seen.add(key)
                seq += 1
                _one_item(rec, item=item, base=base, rule=rule, include_rx=include_rx,
                          exclude_rx=exclude_rx, rule_live=rule_live, live_rule=live_rule,
                          dry_run=dry_run, shelf=shelf, harvest_offdrive=harvest_offdrive,
                          emergency_free_gb=emergency_free_gb, t_now=t_now, seq=seq,
                          protect=protect, free_of=free_of, emergency_vols=emergency_vols,
                          audit=audit, ledger=ledger, ig=ig, seal_key=seal_key, seal=seal,
                          land_to_awm=land_to_awm, awm_db=awm_db,
                          snapshot_store=snapshot_store, touched_days=touched_days,
                          deadline=deadline, strata=strata)
        if rec["truncated"]:
            rec["notes"].append(f"time budget of {human_duration(time_budget_s or 0)} "
                                "reached; remaining items and purges wait for the next pass")
            break
        _purge(rec, rule, bases, dry_run=dry_run, t_now=t_now, free_of=free_of,
               emergency_free_gb=emergency_free_gb, audit=audit, ledger=ledger)

    for k in vol_free:
        try:
            rec["free_after"][k] = int(free_fn(vol_label[k]))
        except OSError:
            rec["free_after"][k] = None
    if publish_to and not dry_run:
        for day in sorted(touched_days):
            r = ig.publish_day(day, Path(os.path.expanduser(str(publish_to))), seal_key=seal_key)
            rec["publish"].append(r)
            if r.get("available") and not r.get("ok"):
                rec["errors"].append(f"publish {day}: {r.get('reason')}")
            elif not r.get("available"):
                rec["warnings"].append(f"publish unavailable: {r.get('reason')}")


def _one_item(rec: dict, *, item: str, base: str, rule: dict, include_rx, exclude_rx,
              rule_live: set, live_rule, dry_run: bool, shelf: Path, harvest_offdrive: bool,
              emergency_free_gb, t_now: float, seq: int, protect: list, free_of,
              emergency_vols: dict, audit, ledger, ig, seal_key, seal, land_to_awm, awm_db,
              snapshot_store, touched_days: set, deadline: float | None, strata=None
              ) -> None:
    rec["items_seen"] += 1
    name = os.path.basename(item.rstrip("/"))
    row: dict[str, Any] = {"path": item, "rule": rule["name"], "action": rule["action"]}

    def keep(outcome: str, reason: str, *, error: bool = False, listed: bool = True) -> None:
        row.update(outcome=outcome, reason=reason)
        if listed:
            rec["items"].append(row)
        if error:
            rec["errors"].append(f"{item}: {reason}")

    if name == QUARANTINE_DIRNAME or f"/{QUARANTINE_DIRNAME}/" in item + "/":
        return keep("skipped", "quarantine dir", listed=False)
    if any(rx.match(item) for rx in exclude_rx):
        return keep("skipped", "excluded by rule", listed=False)
    prot = _protected(item, protect)
    if prot:
        return keep("skipped", f"protected: holds {prot}")
    if name.lower() in rule_live:
        rec["skipped_live"].append(item)
        audit("skipped-live", path=item, rule=rule["name"], why="registered live id")
        ledger(item, rule, "skipped-live", detail="registered live id")
        return keep("skipped-live", "registered live id")

    max_idle = rule["max_idle"]
    if emergency_free_gb is not None:
        vk, free = free_of(item)
        if free < float(emergency_free_gb) * 2**30:
            max_idle = max_idle / 2.0
            if (vk, rule["name"]) not in emergency_vols:
                emergency_vols[(vk, rule["name"])] = True
                msg = (f"EMERGENCY: {vk} has {free / 2**30:.1f} GB free < "
                       f"{float(emergency_free_gb):g} GB; rule {rule['name']} max_idle "
                       f"{human_duration(rule['max_idle'])} -> {human_duration(max_idle)}")
                rec["emergency"].append({"volume": vk, "free_bytes": free,
                                         "threshold_gb": float(emergency_free_gb),
                                         "rule": rule["name"], "max_idle_s": max_idle,
                                         "message": msg})
    window = live_rule["window"] if live_rule else 0.0
    # Stop walking at the first file too new to be eligible (or to be judged live).
    m = measure(item, include_rx, stop_newer_than=t_now - max(max_idle, window),
                deadline=deadline)
    row.update(bytes=m["bytes"], files=m["files"], kind=m["kind"],
               age_h=round((t_now - m["newest_mtime"]) / 3600.0, 2))
    if m.get("early") == "budget":
        rec["truncated"] = True
        rec["resume_first"].append(item)
        return keep("skipped", "time budget exhausted while measuring; next pass resumes")
    if m.get("early") == "fresh":
        row["partial"] = True  # bytes/files counted only up to the fresh file
    if m["kind"] in ("missing", "special"):
        return keep("skipped", f"{m['kind']} entry", listed=False)
    idle = t_now - m["newest_mtime"]
    if live_rule and idle < window:
        rec["skipped_live"].append(item)
        why = (f"changed {human_duration(max(idle, 0))} ago (< live window "
               f"{human_duration(window)})")
        audit("skipped-live", path=item, rule=rule["name"], why=why)
        ledger(item, rule, "skipped-live", detail=why)
        return keep("skipped-live", why)
    row["max_idle_h"] = round(max_idle / 3600.0, 2)
    if idle < max_idle:
        rec["kept_fresh"] += 1
        return
    rec["items_eligible"] += 1

    # HARVEST first. In a dry run this is the plan (selected + screened, not written).
    h = harvest_item(item, rule, m, shelf, write=not dry_run, offdrive=harvest_offdrive,
                     now=t_now)
    row["harvest"] = {"files": len(h["harvested"]), "bytes": h["bytes"],
                      "withheld": h["withheld"], "dir": h["dir"]}
    if not h["ok"]:
        audit("failed", path=item, rule=rule["name"], stage="harvest", why=h["error"])
        ledger(item, rule, "failed", detail=f"harvest: {h['error']}")
        return keep("failed", f"harvest: {h['error']}; item kept", error=True)
    for s in h["skipped"]:
        if s["reason"] == "withheld: secret-pattern":
            audit("withheld-secret", path=item, file=s["path"], rule=rule["name"])
    rec["withheld_secret"] += h["withheld"]
    if dry_run:
        ledger(item, rule, "dry-run", m["bytes"], f"would {rule['action']}")
        return keep("dry-run", f"would harvest {len(h['harvested'])} file(s), then "
                               f"{rule['action']}")

    rec["bytes_harvested"] += h["bytes"]
    rec["files_harvested"] += len(h["harvested"])
    if h["dir"]:
        touched_days.add(Path(h["dir"]).parent)
        if h["harvested"]:
            audit("harvested", path=item, rule=rule["name"], shelf=h["dir"],
                  files=len(h["harvested"]), bytes=h["bytes"])
        s = (ig.seal_dir(Path(h["dir"]), seal_key) if seal
             else {"ok": False, "reason": "sealing disabled"})
        row["harvest"]["seal"] = s.get("seal") if s.get("ok") else f"unsealed: {s.get('reason')}"
        if seal and seal_key and not s.get("ok"):
            # An EXPLICIT key means the caller wants a sealed shelf; an unsealed one
            # is a harvest failure, so the item stays.
            ledger(item, rule, "failed", detail=f"seal: {s.get('reason')}")
            return keep("failed", f"seal: {s.get('reason')}; item kept", error=True)
        if land_to_awm and h["harvested"]:
            where = h["dir"]
            if strata is not None:  # the staging dir is dropped after upload
                hd = Path(h["dir"])
                where = strata.virtual_path(f"awstorage/harvest/{rec['node']}/"
                                            f"{rule['name']}/{hd.parent.name}/{hd.name}")
            r = ig.land_to_awm(land_to_awm, h["manifest"], where, db=awm_db)
            row["harvest"]["awm"] = r.get("key") if r.get("ok") else r.get("reason")
            if not r.get("ok"):
                rec["warnings"].append(f"awm landing for {item}: {r.get('reason')}")

    if strata is not None and h["dir"]:
        from .strata import StrataUnavailableError
        try:
            n_up = _ship_to_strata(strata, Path(h["dir"]), rec["node"], rule["name"])
        except StrataUnavailableError as exc:
            rec["strata"]["available"] = False
            rec["could_not_judge"].append(f"strata target unavailable: {exc}")
            ledger(item, rule, "refused", detail=f"strata unavailable: {exc}")
            return keep("failed", f"strata target unavailable: {exc}; item kept")
        except (RuntimeError, OSError) as exc:
            audit("failed", path=item, rule=rule["name"], stage="strata", why=str(exc))
            ledger(item, rule, "failed", detail=f"strata: {exc}")
            return keep("failed", f"strata: {exc}; item kept", error=True)
        rec["strata"]["uploaded"] += n_up
        row["harvest"]["strata"] = n_up
        remove_tree(h["dir"])  # Strata is the shelf now; the staging copy is spent

    if rule["snapshot"]:
        store = (rule["snapshot"].get("store") if isinstance(rule["snapshot"], Mapping)
                 else None) or snapshot_store or Path.home() / ".aither" / "awstorage" / "snaps"
        label = re.sub(r"[^A-Za-z0-9_.\-]", "_", f"{rule['name']}-{name}-{int(t_now)}")
        r = ig.snapshot_item(Path(item), Path(os.path.expanduser(str(store))), label)
        if not r.get("ok"):
            why = f"snapshot required by rule but {r.get('reason')}"
            audit("failed", path=item, rule=rule["name"], stage="snapshot", why=why)
            ledger(item, rule, "refused", detail=why)
            return keep("failed", why + "; item kept", error=True)
        row["snapshot"] = label

    # Record the decision BEFORE acting: a removal with no audit record is the exact
    # failure awdit exists for, so under --require-audit a failed append stops it.
    event = "deleted" if rule["action"] == "delete" else "quarantined"
    if not audit(f"{event}-begin", path=item, rule=rule["name"], bytes=m["bytes"]):
        ledger(item, rule, "refused", detail="audit append failed under --require-audit")
        return keep("failed", "audit append failed under --require-audit; item kept",
                    error=True)
    try:
        if rule["action"] == "delete":
            removed, errs = remove_tree(item)
            if errs:
                audit("failed", path=item, rule=rule["name"], stage="delete", why=errs[0])
                ledger(item, rule, "failed", removed, f"{len(errs)} error(s): {errs[0]}")
                rec["bytes_freed"] += removed
                return keep("failed", f"delete incomplete: {len(errs)} error(s), first "
                                      f"{errs[0]}", error=True)
            rec["bytes_freed"] += removed
            detail = f"deleted {removed} bytes"
        else:
            qdir, _dest = _quarantine_item(item, base, rule["name"], seq)
            rec["bytes_quarantined"] += m["bytes"]
            detail = f"quarantined to {qdir}"
            row["quarantine"] = qdir
    except (OSError, ApplyRefused) as exc:
        if isinstance(exc, OSError) and _is_busy(exc):
            rec["skipped_busy"].append(item)
            ledger(item, rule, "skipped-busy", detail=type(exc).__name__)
            audit("skipped-busy", path=item, rule=rule["name"], why=type(exc).__name__)
            return keep("skipped-busy", f"in use ({type(exc).__name__}); untouched")
        audit("failed", path=item, rule=rule["name"], stage=rule["action"], why=str(exc))
        ledger(item, rule, "failed", detail=f"{type(exc).__name__}: {exc}")
        return keep("failed", f"{rule['action']}: {type(exc).__name__}: {exc}", error=True)
    rec["items_removed"] += 1
    audit(event, path=item, rule=rule["name"], bytes=m["bytes"], detail=detail)
    ledger(item, rule, "applied", m["bytes"], detail)
    keep("applied", detail)


def _ship_to_strata(strata, item_dir: Path, node: str, rule_name: str) -> int:
    """Upload every file of a staged item dir (harvest + manifest + seal), verified."""
    day = item_dir.parent.name
    n = 0
    for d, _dirs, files, _links in walk_no_follow(long_path(item_dir)):
        for e in files:
            rel = os.path.relpath(e.path, long_path(item_dir)).replace("\\", "/")
            with open(e.path, "rb") as f:
                data = f.read()
            remote = f"awstorage/harvest/{node}/{rule_name}/{day}/{item_dir.name}/{rel}"
            strata.upload_verified(remote, data, _sha256_bytes(data),
                                   metadata={"producer": "awstorage sweep", "rule": rule_name})
            n += 1
    return n


def _purge(rec: dict, rule: dict, bases: list[str], *, dry_run: bool, t_now: float,
           free_of, emergency_free_gb, audit, ledger) -> None:
    """Reclaim this rule's quarantine entries older than `purge_after`."""
    if rule["purge_after"] is None:
        return
    prefix = f"{SWEEP_PREFIX}{rule['name']}-"
    for base in bases:
        after = rule["purge_after"]
        if emergency_free_gb is not None:
            _k, free = free_of(base)
            if free < float(emergency_free_gb) * 2**30:
                after = after / 2.0
        for q in list_quarantine([base]):
            entry = q["entry"]
            if not os.path.basename(entry).startswith(prefix):
                continue
            if q["age_days"] * 86400.0 < after:
                continue
            row = {"entry": entry, "origin": q["origin"], "bytes": q["bytes"]}
            if dry_run:
                row["outcome"] = "dry-run"
                rec["purged"].append(row)
                continue
            if not audit("purged-begin", path=entry, rule=rule["name"], origin=q["origin"]):
                row["outcome"] = "refused: audit"
                rec["purged"].append(row)
                rec["errors"].append(f"{entry}: purge refused, audit append failed")
                continue
            removed, errs = remove_tree(entry)
            rec["bytes_freed"] += removed
            row.update(outcome="purged" if not errs else "failed", bytes=removed)
            rec["purged"].append(row)
            ledger(entry, rule, "purged" if not errs else "failed", removed,
                   f"quarantine purge (origin {q['origin']})" + (f"; {errs[0]}" if errs else ""))
            audit("purged", path=entry, rule=rule["name"], bytes=removed, errors=len(errs))
            if errs:
                rec["errors"].append(f"{entry}: purge incomplete: {errs[0]}")


__all__ = [
    "DEFAULT_HARVEST",
    "LIVE_IDS_ENV",
    "SweepConfigError",
    "expand_path",
    "glob_to_regex",
    "harvest_item",
    "load_live_ids",
    "measure",
    "parse_duration",
    "presets",
    "resolve_rules",
    "static_base",
    "sweep",
    "validate_rule",
    "write_receipt",
]
