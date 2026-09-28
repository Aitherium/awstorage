"""Free-space floors: the fast guard (watch), the placement check (place), shelf rotation.

Measured 2026-09-28, the day these exist for: D: reached 0 bytes at 12:15; C: fell
124 -> 18 GB inside one hour while the retention sweep runs every 3 h; a peer moved
89 GB onto the nearly-full C:; the harvest shelf sat on E: at 99 %.

* A FLOOR is the free space (GB) a drive must keep: ``C:=40,D:=60,E:=30``. A key is
  a drive letter on Windows or any path on POSIX (its volume is what is floored).
  ``$AWSTORAGE_FLOORS`` holds the same spelling for callers that pass none.
* ``watch`` is ONE ``shutil.disk_usage`` per floored drive. With every drive above
  its floor it walks no tree and returns in milliseconds -- it is meant to run every
  5 minutes. Under a floor it runs the emergency sweep of the preset rules on THAT
  drive only, appends an alert to ``~/.aither/awstorage/alerts.jsonl`` and, when
  ``$AWSTORAGE_ALERT_CMD`` is set, runs it with the alert JSON as its last argv
  (awrelay / Pulse plug in without being imported).
* ``place`` answers "where may these N GB go" BEFORE the move: every drive ranked by
  its free space after the move, and any target that would end under its floor
  REFUSED. Run it before moving data between drives.
* ``prune_shelf`` rotates the harvest shelf (``<shelf>/<rule>/<YYYY-MM-DD>/...``).

Stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ._fs import remove_tree_detail

FLOORS_ENV = "AWSTORAGE_FLOORS"
ALERT_CMD_ENV = "AWSTORAGE_ALERT_CMD"
DEFAULT_FLOOR_GB = 20.0
ALERT_CMD_TIMEOUT_S = 30.0
GB = 2**30

_SIZE_RX = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgtp]?)(?:i?b)?\s*$", re.I)
_SIZE_UNIT = {"": 1, "k": 2**10, "m": 2**20, "g": 2**30, "t": 2**40, "p": 2**50}


class FloorsError(ValueError):
    """A floors spec that cannot be judged (exit 2)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_size(v: str | int | float) -> int:
    """'90GB' / '1.5T' / '500M' / '4096' -> bytes (binary units)."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if v < 0:
            raise FloorsError(f"negative size {v!r}")
        return int(v)
    m = _SIZE_RX.match(str(v))
    if not m:
        raise FloorsError(f"cannot parse size {v!r} (want e.g. 90GB, 1.5T, 500M)")
    return int(float(m.group(1)) * _SIZE_UNIT[m.group(2).lower()])


def _drive_path(key: str) -> str:
    """A floor key -> a path disk_usage can read ('C:' -> 'C:/')."""
    k = key.strip()
    if re.fullmatch(r"[A-Za-z]:?", k):
        return k[0].upper() + ":/"
    return k


def drive_label(path: str) -> str:
    """Drive letter on Windows ('C:'), the path itself elsewhere."""
    drive = os.path.splitdrive(os.path.abspath(path))[0]
    return drive.upper() if drive else path


def parse_floors(spec: str | Mapping[str, Any] | None, *, env: Mapping[str, str] | None = None
                 ) -> dict[str, float]:
    """'C:=40,D:=60' (or a mapping, or None -> $AWSTORAGE_FLOORS) -> {'C:': 40.0, ...}.

    GB per drive. A bare letter is a Windows drive; anything else is a path whose
    volume is floored. A malformed entry raises FloorsError -- a guard must never
    silently drop the drive it was asked to guard.
    """
    if spec is None:
        spec = (os.environ if env is None else env).get(FLOORS_ENV, "")
    if isinstance(spec, Mapping):
        items = [(str(k), v) for k, v in spec.items()]
    else:
        items = []
        for part in re.split(r"[,;]", str(spec)):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise FloorsError(f"floor {part!r} is not DRIVE=GB (e.g. C:=40)")
            k, v = part.rsplit("=", 1)
            items.append((k.strip(), v.strip()))
    out: dict[str, float] = {}
    for k, v in items:
        if not k:
            raise FloorsError("a floor has an empty drive")
        try:
            gb = float(str(v).lower().rstrip("gb").strip()) if isinstance(v, str) else float(v)
        except ValueError as exc:
            raise FloorsError(f"floor {k}={v!r}: not a number of GB") from exc
        if gb < 0:
            raise FloorsError(f"floor {k}={v!r} is negative")
        key = drive_label(_drive_path(k)) if re.fullmatch(r"[A-Za-z]:?", k.strip()) else k
        out[key] = gb
    return out


def _vol(p: str) -> str:
    from .sweep import volume_key  # lazy: sweep imports this module's helpers too
    return volume_key(p)


def floor_for(path: str, floors: Mapping[str, float]) -> float | None:
    """The floor (GB) of the volume `path` is on, or None when that volume has none."""
    vk = _vol(path)
    for k, gb in floors.items():
        if _vol(_drive_path(k)) == vk:
            return float(gb)
    return None


def _free(path: str, disk_free: Callable[[str], int] | None) -> int:
    if disk_free is not None:
        return int(disk_free(path))
    return int(shutil.disk_usage(path).free)


def shelf_low(shelf: str | os.PathLike, floors: Mapping[str, float], *,
              disk_free: Callable[[str], int] | None = None) -> str | None:
    """Why the harvest shelf must not be written to, or None when it may be."""
    if not floors:
        return None
    from .sweep import _existing_ancestor
    anc = _existing_ancestor(str(shelf))
    fl = floor_for(anc, floors)
    if fl is None:
        return None
    try:
        free = _free(anc, disk_free)
    except OSError as exc:
        return f"shelf drive free space unreadable ({type(exc).__name__})"
    if free < fl * GB:
        return (f"shelf drive low: {drive_label(anc)} has {free / GB:.1f} GB free < floor "
                f"{fl:g} GB")
    return None


# -- place ---------------------------------------------------------------------------

def _candidate_drives(floors: Mapping[str, float]) -> list[str]:
    out = [_drive_path(k) for k in floors]
    try:
        from .identity import list_volumes
        for v in list_volumes():
            if v.get("kind") in ("fixed", "removable") and v.get("mount"):
                out.append(str(v["mount"]))
    except Exception:  # noqa: BLE001 -- the floored drives are still judged
        pass
    seen, uniq = set(), []
    for d in out:
        k = _vol(d)
        if k not in seen:
            seen.add(k)
            uniq.append(d)
    return uniq


def place(size: int | str, floors: Mapping[str, float] | str | None = None, *,
          source: str | None = None, drives: Iterable[str] | None = None,
          default_floor_gb: float = DEFAULT_FLOOR_GB,
          disk_free: Callable[[str], int] | None = None) -> list[dict]:
    """Rank drives for a move of `size` bytes; REFUSE any that would end under its floor.

    Returns one row per candidate drive, best first (most free after the move):
    ``{drive, free, floor_gb, free_after, ok, why}``. A drive with no floor uses
    `default_floor_gb`. The source drive (`source`'s volume) is never a target --
    moving within a drive frees nothing -- and is listed with ``ok: False``.
    Run this BEFORE moving data between drives (2026-09-28: 89 GB moved onto a
    nearly-full C:).
    """
    n = parse_size(size)
    fl = parse_floors(floors) if not isinstance(floors, Mapping) else dict(floors)
    cands = list(drives) if drives is not None else _candidate_drives(fl)
    src_vol = _vol(source) if source else None
    rows = []
    for d in cands:
        dp = _drive_path(d)
        f_gb = floor_for(dp, fl)
        floor_gb = default_floor_gb if f_gb is None else f_gb
        try:
            free = _free(dp, disk_free)
        except OSError as exc:
            rows.append({"drive": drive_label(dp), "free": None, "floor_gb": floor_gb,
                         "free_after": None, "ok": False,
                         "why": f"unreadable: {type(exc).__name__}"})
            continue
        after = free - n
        row = {"drive": drive_label(dp), "free": free, "floor_gb": floor_gb,
               "free_after": after, "ok": True, "why": "ok"}
        if src_vol is not None and _vol(dp) == src_vol:
            row.update(ok=False, free_after=free + n,
                       why="source drive (moving within a drive frees nothing)")
        elif after < floor_gb * GB:
            row.update(ok=False, why=(f"REFUSED: would end at {after / GB:.1f} GB free, "
                                      f"under its floor {floor_gb:g} GB"))
        rows.append(row)
    rows.sort(key=lambda r: (not r["ok"], -(r["free_after"] or 0)))
    return rows


# -- alerts --------------------------------------------------------------------------

def default_alerts_path() -> Path:
    return Path.home() / ".aither" / "awstorage" / "alerts.jsonl"


def _alert_argv(raw: str) -> list[str]:
    raw = raw.strip()
    if raw.startswith("["):
        v = json.loads(raw)
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v) or not v:
            raise ValueError("a JSON alert command must be a non-empty list of strings")
        return v
    return shlex.split(raw)


def send_alert(alert: dict, *, alerts_path: str | os.PathLike | None = None,
               env: Mapping[str, str] | None = None) -> dict:
    """Append `alert` to the alerts log; run $AWSTORAGE_ALERT_CMD with it as last argv.

    The command is a JSON list (``["awrelay", "send", "#agents"]``, the spelling for
    Windows paths) or a shell-like string (split with shlex, never run by a shell).
    Returns {"logged": path|None, "cmd": {...}|None, "errors": [...]}.
    """
    e = os.environ if env is None else env
    res: dict[str, Any] = {"logged": None, "cmd": None, "errors": []}
    p = Path(os.path.expanduser(str(alerts_path or default_alerts_path())))
    line = json.dumps(alert, sort_keys=True, default=str)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        res["logged"] = str(p).replace("\\", "/")
    except OSError as exc:
        res["errors"].append(f"alert log {p}: {type(exc).__name__}: {exc}")
    raw = e.get(ALERT_CMD_ENV, "")
    if raw.strip():
        try:
            argv = _alert_argv(raw) + [line]
            r = subprocess.run(argv, capture_output=True, text=True, check=False,
                               timeout=ALERT_CMD_TIMEOUT_S)
            res["cmd"] = {"argv0": argv[0], "exit_code": r.returncode,
                          "stderr": (r.stderr or "")[-300:]}
            if r.returncode != 0:
                res["errors"].append(f"alert command exit {r.returncode}")
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            res["cmd"] = {"error": f"{type(exc).__name__}: {exc}"}
            res["errors"].append(f"alert command: {type(exc).__name__}: {exc}")
    return res


# -- watch ---------------------------------------------------------------------------

def _rules_on_drive(drive_path: str, names: Iterable[str],
                    policy: Mapping[str, Any] | None, env: Mapping[str, str] | None
                    ) -> list[dict]:
    """The named rules (policy first, then presets), each narrowed to the paths whose
    static base is on `drive_path`'s volume; rules with none there are dropped."""
    from .sweep import SweepConfigError, expand_path, presets, static_base

    declared = {str(r.get("name")): r for r in (policy or {}).get("retention", []) or []
                if isinstance(r, Mapping) and r.get("name")}
    pre = presets()
    vk = _vol(drive_path)
    out = []
    for n in names:
        src = declared.get(n) or pre.get(n)
        if src is None:
            raise SweepConfigError(f"unknown rule {n!r}")
        src = dict(src)
        if pre.get(n, {}).get("paths_from_policy") and n in declared:
            src = {**pre[n], **declared[n]}
        paths = src.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        keep = []
        for pat in paths:
            try:
                base = static_base(expand_path(pat, env))
            except SweepConfigError:
                continue
            if _vol(base) == vk:
                keep.append(pat)
        if keep:
            src["paths"] = keep
            src["name"] = n
            out.append(src)
    return out


def watch_once(floors: Mapping[str, float] | str | None, *,
               yes: bool = False,
               rules: Iterable[str] = ("agent-scratch", "temp-toplevel"),
               policy: Mapping[str, Any] | None = None,
               harvest_to: str | os.PathLike | None = None,
               catalog: Any = None,
               alerts_path: str | os.PathLike | None = None,
               receipt: str | os.PathLike | None = None,
               disk_free: Callable[[str], int] | None = None,
               env: Mapping[str, str] | None = None,
               sweep_fn: Callable[..., dict] | None = None,
               time_budget_s: float = 240.0,
               measure_cap_s: float = 30.0) -> dict:
    """One watch pass. Fast path: one disk_usage per floored drive, no tree walks.

    Under a floor: the emergency sweep of `rules` on THAT drive only (acting only when
    `yes`; otherwise the plan), an alert (log + $AWSTORAGE_ALERT_CMD), and per-drive
    before/after in the receipt. Exit codes: 0 every drive at/above its floor, 1 a
    drive still under its floor after the pass, 2 could not judge (bad floors, a drive
    whose free space cannot be read).
    """
    from .sweep import SweepConfigError, sweep, write_receipt

    t0 = time.monotonic()
    rec: dict[str, Any] = {"tool": "awstorage watch", "exit_code": 2, "started": _now_iso(),
                           "finished": None, "dry_run": not yes, "node": socket.gethostname(),
                           "drives": {}, "under": [], "alerts": [], "errors": [],
                           "could_not_judge": [], "elapsed_s": None}
    try:
        fl = parse_floors(floors, env=env) if not isinstance(floors, Mapping) else dict(floors)
        if not fl:
            raise FloorsError(f"no floors given (--floors C:=40,... or ${FLOORS_ENV})")
        for key, gb in fl.items():
            dp = _drive_path(key)
            try:
                free = _free(dp, disk_free)
            except OSError as exc:
                rec["could_not_judge"].append(f"{key}: free space unreadable: "
                                              f"{type(exc).__name__}: {exc}")
                continue
            under = free < gb * GB
            rec["drives"][key] = {"floor_gb": gb, "free_before": free, "free_after": free,
                                  "under_before": under, "under_after": under,
                                  "sweep": None}
            if under:
                rec["under"].append(key)
        for key in list(rec["under"]):
            d = rec["drives"][key]
            dp = _drive_path(key)
            try:
                drive_rules = _rules_on_drive(dp, rules, policy, env)
            except SweepConfigError as exc:
                rec["could_not_judge"].append(f"{key}: {exc}")
                drive_rules = []
            sw_summary: dict[str, Any] = {"rules": [r["name"] for r in drive_rules]}
            if drive_rules:
                fn = sweep_fn or sweep
                r = fn([r["name"] for r in drive_rules],
                       policy={"retention": drive_rules}, dry_run=not yes,
                       harvest_to=harvest_to, emergency_free_gb=d["floor_gb"],
                       catalog=catalog, env=env, disk_free=disk_free,
                       time_budget_s=time_budget_s, measure_cap_s=measure_cap_s,
                       floors=fl)
                sw_summary.update({k: r.get(k) for k in (
                    "exit_code", "items_seen", "items_eligible", "items_removed",
                    "bytes_freed", "bytes_quarantined", "emergency_deleted",
                    "harvest_skipped", "truncated")})
                if r.get("could_not_judge"):
                    sw_summary["could_not_judge"] = r["could_not_judge"][:5]
                if r.get("exit_code") == 1:
                    rec["errors"].append(f"{key}: emergency sweep had failed items")
            else:
                sw_summary["note"] = "no preset rule has a path on this drive"
            d["sweep"] = sw_summary
            try:
                d["free_after"] = _free(dp, disk_free)
            except OSError:
                d["free_after"] = None
            d["under_after"] = d["free_after"] is None or d["free_after"] < d["floor_gb"] * GB
            alert = {"kind": "awstorage.floor", "at": _now_iso(), "node": rec["node"],
                     "drive": key, "floor_gb": d["floor_gb"],
                     "free_gb_before": round(d["free_before"] / GB, 2),
                     "free_gb_after": (None if d["free_after"] is None
                                       else round(d["free_after"] / GB, 2)),
                     "still_under": d["under_after"], "acted": bool(yes),
                     "freed_bytes": int(sw_summary.get("bytes_freed") or 0),
                     "harvest_skipped": len(sw_summary.get("harvest_skipped") or []),
                     "message": (f"{key} under its floor: {d['free_before'] / GB:.1f} GB free"
                                 f" < {d['floor_gb']:g} GB"
                                 + ("" if yes else " (plan only: re-run with --yes to act)"))}
            a = send_alert(alert, alerts_path=alerts_path, env=env)
            rec["alerts"].append({"drive": key, **a})
            rec["errors"].extend(a["errors"])
    except FloorsError as exc:
        rec["could_not_judge"].append(str(exc))
    finally:
        still = [k for k, d in rec["drives"].items() if d["under_after"]]
        rec["still_under"] = still
        if rec["could_not_judge"]:
            rec["exit_code"] = 2
        elif still:
            rec["exit_code"] = 1
        else:
            rec["exit_code"] = 0
        rec["finished"] = _now_iso()
        rec["elapsed_s"] = round(time.monotonic() - t0, 3)
        if receipt:
            try:
                write_receipt(receipt, rec)
            except OSError as exc:
                rec["could_not_judge"].append(f"receipt not written: {exc}")
                rec["exit_code"] = 2
    return rec


# -- shelf rotation ------------------------------------------------------------------

_DAY_RX = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def prune_shelf(shelf: str | os.PathLike, *, older_than_s: float, dry_run: bool = True,
                now: float | None = None) -> dict:
    """Remove harvest day dirs (``<shelf>/<rule>/<YYYY-MM-DD>``) older than N seconds.

    Only dirs whose NAME is a date are touched; the date in the name, not an mtime,
    decides the age (a re-sealed day dir must not live forever). Links are never
    followed. Returns {"removed": [...], "kept": n, "bytes_freed": n, "errors": [...]}.
    """
    root = Path(os.path.expanduser(str(shelf)))
    t_now = time.time() if now is None else float(now)
    out: dict[str, Any] = {"shelf": str(root).replace("\\", "/"), "dry_run": dry_run,
                           "removed": [], "kept": 0, "bytes_freed": 0, "errors": [],
                           "busy": []}
    if not root.is_dir():
        out["errors"].append(f"{root} is not a directory")
        return out
    from ._fs import is_link
    for rule_dir in sorted(root.iterdir()):
        if not rule_dir.is_dir() or is_link(rule_dir):
            continue
        for day in sorted(rule_dir.iterdir()):
            if not _DAY_RX.match(day.name) or is_link(day) or not day.is_dir():
                continue
            try:
                t = datetime.strptime(day.name, "%Y-%m-%d").timestamp()
            except ValueError:
                continue
            age = t_now - (t + 86400)  # a day dir is "as old as" the END of its day
            if age < older_than_s:
                out["kept"] += 1
                continue
            row = {"dir": str(day).replace("\\", "/"), "age_days": round(age / 86400, 1)}
            if not dry_run:
                removed, errs, busy = remove_tree_detail(day)
                row["bytes"] = removed
                out["bytes_freed"] += removed
                if errs:
                    out["errors"].append(f"{day}: {errs[0]}")
                if busy:
                    out["busy"].append(f"{day}: {busy[0]}")
            out["removed"].append(row)
    return out


__all__ = [
    "ALERT_CMD_ENV",
    "DEFAULT_FLOOR_GB",
    "FLOORS_ENV",
    "FloorsError",
    "default_alerts_path",
    "drive_label",
    "floor_for",
    "parse_floors",
    "parse_size",
    "place",
    "prune_shelf",
    "send_alert",
    "shelf_low",
    "watch_once",
]
