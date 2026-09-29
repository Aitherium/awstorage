"""Relocation: move a cold tree to another drive, planned against EVERY drive's floor.

Measured 2026-09-28: an agent moved 88 GB D: -> C: by hand (robocopy /MOVE + a
junction). Nothing checked the destination, and C: fell from 124 GB to 18 GB free --
the day after C: at 0 bytes had corrupted the fleet's root fs. The copy was not the
failure; the missing PLAN was. So a relocation here is three separate acts:

1. **plan** (:func:`plan_relocation`, pure and injectable) -- measure each source
   (bytes, files, newest mtime, nested reparse points), gather cold evidence (open
   handles through psutil when it is installed, container mounts when the caller
   passes them), and PROJECT every drive the plan touches: the source drive gains the
   logical bytes, the destination loses the NTFS cost (cluster-rounded files plus an
   MFT record per entry) ``* 1.02``. A projection that takes a drive below its floor
   (``storage-topology.yaml`` ``drive_floors_gb``) is a refusal, and a plan with any
   refusal has ``ok: false`` -- it can never be approved or applied. Sources are
   canonicalised (junctions, short names) before any protection check, and a tree
   holding a VM disk, a credential or a never-set path is refused.
2. **approve** (:func:`approve_plan`) -- RE-JUDGES the plan file (its own ``ok`` is
   never authority) and writes ``approved/<plan_id>.json`` with the plan's digest.
   Only the card consumer or the owner's explicit CLI flag call it.
3. **apply** (:func:`apply_plan`) -- refuses without the approval (and when the plan
   changed after it), re-runs the static checks, RE-MEASURES the source (hot since the
   plan? open handles?) and RE-CHECKS the floor immediately before each move (free
   space moves between approval and execution), journals the move, runs
   ``robocopy /MOVE``, verifies the source is empty and the destination holds exactly
   the measured file count and bytes, links the old path to the new one with a
   junction, and on ANY failure moves the tree back without overwriting a newer source
   file. A journal left by an apply that died mid-move is recovered on the next run.
   Every attempted move lands one ledger row, one awrelay line and one Pulse event; a
   failure to post is recorded in the result and logged, never fatal and never silent.

Files (``AWSTORAGE_RELOCATE_DIR`` overrides the base, for tests):
``~/.aither/storage/relocate/{plans,approved,results,journal}/<plan_id>.json``.

Stdlib only. GB here is GiB (1024**3), the unit check_disk_pressure.py floors use.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .guards import Guards, is_sensitive, load_topology, norm

logger = logging.getLogger(__name__)

GIB = 1024 ** 3
#: On top of the allocation model below, the destination is charged this much more:
#: directory index growth, robocopy's in-flight temp, the $LogFile.
OVERHEAD = 1.02
#: Each file costs ceil(size / cluster) * cluster plus one MFT record; each directory
#: one MFT record. Logical bytes alone undercount a small-file tree several-fold
#: (1.5M x 1.5 KiB files = 2.1 GiB logical, ~7.2 GiB on NTFS).
DEFAULT_CLUSTER = 4096
MFT_RECORD = 1024
#: Files no relocation may carry inside a tree, whatever path they sit under: a VM
#: disk's NTFS mtime can look cold while vmcompute holds it (psutil cannot see that).
VM_DISK_SUFFIXES = (".vhdx", ".vhd", ".avhdx", ".vmdk", ".qcow2")
DEFAULT_FLOORS: Dict[str, float] = {"C:": 40.0, "D:": 50.0, "E:": 30.0, "default": 30.0}
COLD_MIN_DAYS = 14
#: A source with more files than this is refused, not estimated: the floor projection
#: needs the REAL byte count, and a walk that stopped early reports a floor, not a sum.
MAX_FILES = 2_000_000
ROBOCOPY_FLAGS = ("/MOVE", "/COPY:DAT", "/DCOPY:DAT", "/R:1", "/W:1", "/MT:16")
#: The move BACK never overwrites a file that exists at the source: robocopy's default
#: selection copies an OLDER file over a newer one, and a file written after the
#: forward copy is exactly the one a rollback must not clobber.
ROLLBACK_EXTRA = ("/XO", "/XN", "/XC")
#: robocopy exit codes 0-7 are success bit-sets (1 copied, 2 extra, 4 mismatched);
#: 8 and above mean at least one file or directory could not be copied.
ROBOCOPY_FAIL_RC = 8
_REPARSE = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
_LOCK_STALE_S = 12 * 3600

Runner = Callable[[Sequence[str]], Tuple[int, str]]
FreeSpaceFn = Callable[[str], int]
Notifier = Callable[[Dict[str, Any]], List[Dict[str, Any]]]


class RelocateError(Exception):
    """The command could not run or could not judge (exit 2)."""


class RelocateRefusedError(Exception):
    """The answer is no (exit 1)."""


# ── locations ─────────────────────────────────────────────────────────────────

def relocate_dir() -> Path:
    env = (os.environ.get("AWSTORAGE_RELOCATE_DIR") or "").strip()
    if env:
        return Path(os.path.expanduser(env))
    return Path.home() / ".aither" / "storage" / "relocate"


def maintenance_marker() -> Path:
    return Path.home() / ".aither" / "maintenance.marker"


def default_catalog() -> Path:
    return Path.home() / ".aither" / "awstorage" / "catalog.db"


def _sub(base: Optional[Path], name: str) -> Path:
    return Path(base or relocate_dir()) / name


def _now(now: Optional[datetime] = None) -> datetime:
    return now or datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise RelocateError(f"cannot read {path}: {type(exc).__name__}: {exc}") from exc


def plan_digest(plan: Dict[str, Any]) -> str:
    """sha256 of the plan's canonical JSON -- what an approval is bound to."""
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


# ── drives and floors ─────────────────────────────────────────────────────────

def norm_drive(d: str) -> str:
    """'e', 'E:', 'e:\\' -> 'E:'. Raises RelocateError on anything else."""
    m = re.fullmatch(r"\s*([A-Za-z]):?[\\/]?\s*", str(d or ""))
    if not m:
        raise RelocateError(f"not a drive letter: {d!r}")
    return m.group(1).upper() + ":"


def drive_of(path: str) -> Optional[str]:
    m = re.match(r"^([A-Za-z]):", str(path))
    return m.group(1).upper() + ":" if m else None


def _floor_key(k: Any) -> str:
    s = str(k).strip()
    if s.lower() == "default":
        return "default"
    # YAML reads a bare `C:` key as "C" and a quoted one as "C:"; both mean the drive.
    return s.rstrip(":").upper() + ":"


def floors_from_topology(topo: Optional[Dict[str, Any]]) -> Optional[Dict[str, float]]:
    raw = (topo or {}).get("drive_floors_gb")
    if not isinstance(raw, dict) or not raw:
        return None
    out: Dict[str, float] = {}
    for k, v in raw.items():
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise RelocateError(f"drive_floors_gb.{k} is not a number: {v!r}")
        out[_floor_key(k)] = float(v)
    out.setdefault("default", DEFAULT_FLOORS["default"])
    return out


def floor_for(floors: Dict[str, float], drive: str) -> float:
    return float(floors.get(drive, floors.get("default", DEFAULT_FLOORS["default"])))


def _mini_topology(text: str) -> Dict[str, Any]:
    """The two keys relocation reads, for a box without pyyaml (the full box is the
    one most likely to have a bare interpreter). Flat blocks only, by design."""
    out: Dict[str, Any] = {}
    key = None
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            key = line.split(":", 1)[0].strip()
            key = key if key in ("drive_floors_gb", "relocate_do_not_move") else None
            continue
        if key == "drive_floors_gb":
            m = re.match(r'^\s+["\']?([A-Za-z]:?|default)["\']?\s*:\s*([0-9.]+)\s*$', line)
            if m:
                out.setdefault(key, {})[m.group(1)] = float(m.group(2))
        elif key == "relocate_do_not_move":
            m = re.match(r'^\s+-\s+["\']?([^"\']+)["\']?\s*$', line)
            if m:
                out.setdefault(key, []).append(m.group(1).strip())
    return out


def find_topology(explicit: Optional[str] = None) -> Optional[Path]:
    """--topology, then $AWSTORAGE_TOPOLOGY, then the nearest checkout above the cwd
    or above this package (the brick ships inside AitherOS/packages/)."""
    for cand in (explicit, os.environ.get("AWSTORAGE_TOPOLOGY")):
        if cand:
            p = Path(os.path.expanduser(cand))
            if p.is_file():
                return p
            raise RelocateError(f"topology file {p} does not exist")
    rel = Path("AitherOS") / "config" / "storage-topology.yaml"
    for start in (Path.cwd(), Path(__file__).resolve().parent):
        for d in (start, *start.parents):
            for p in (d / rel, d / "config" / "storage-topology.yaml"):
                if p.is_file():
                    return p
    return None


def load_relocate_topology(explicit: Optional[str] = None
                           ) -> Tuple[Optional[Dict[str, Any]], Dict[str, float], str]:
    """(topology, floors, where the floors came from)."""
    path = find_topology(explicit)
    if path is None:
        return None, dict(DEFAULT_FLOORS), "built-in defaults (no storage-topology.yaml found)"
    topo = load_topology(path)
    if topo is None:
        topo = _mini_topology(path.read_text(encoding="utf-8"))
    floors = floors_from_topology(topo)
    if floors is None:
        return topo, dict(DEFAULT_FLOORS), f"built-in defaults ({path} has no drive_floors_gb)"
    return topo, floors, str(path)


def do_not_move_roots(topo: Optional[Dict[str, Any]]) -> List[str]:
    """`relocate_do_not_move` paths, plus any allowed_roots entry written as a mapping
    with ``do_not_move: true`` ({name: X, do_not_move: true} under a drive)."""
    out: List[str] = []
    t = topo or {}
    for p in t.get("relocate_do_not_move") or []:
        if isinstance(p, str) and p.strip():
            out.append(norm(p.strip()))
    for letter, entries in (t.get("allowed_roots") or {}).items():
        for e in entries or []:
            if isinstance(e, dict) and e.get("do_not_move") and e.get("name"):
                out.append(norm(f"{_floor_key(letter)}/{e['name']}"))
    return sorted(set(out))


def _alloc(size: int, cluster: int) -> int:
    return -(-int(size) // cluster) * cluster + MFT_RECORD


def default_cluster_size(drive: str) -> int:
    """Bytes per cluster on `drive` (GetDiskFreeSpaceW), never below DEFAULT_CLUSTER."""
    try:
        import ctypes  # noqa: PLC0415

        spc, bps, fc, tc = (ctypes.c_ulong() for _ in range(4))
        ok = ctypes.windll.kernel32.GetDiskFreeSpaceW(  # type: ignore[attr-defined]
            ctypes.c_wchar_p(drive + "\\"), ctypes.byref(spc), ctypes.byref(bps),
            ctypes.byref(fc), ctypes.byref(tc))
        if ok:
            return max(int(spc.value) * int(bps.value), DEFAULT_CLUSTER)
    except Exception:  # noqa: BLE001 -- not Windows, or no such drive: be conservative
        logger.debug("relocate: non-fatal", exc_info=True)
    return DEFAULT_CLUSTER


def _under(child: str, parent: str) -> bool:
    c, p = norm(child).lower(), norm(parent).lower()
    return c == p or c.startswith(p if p.endswith("/") else p + "/")


def _overlaps(a: str, b: str) -> bool:
    return _under(a, b) or _under(b, a)


# ── the host filesystem (injectable) ──────────────────────────────────────────

class HostFS:
    """Every filesystem question relocation asks, in one place a test can replace."""

    def drive_of(self, path: str) -> Optional[str]:
        return drive_of(path)

    def exists(self, path: str) -> bool:
        return os.path.lexists(path)

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def canon(self, path: str) -> str:
        """The path with every junction, symlinked parent and 8.3 short name resolved --
        what every protection check compares, since a string compare of an alias
        passes a protected tree reached through it."""
        return os.path.realpath(os.path.abspath(path))

    def is_reparse(self, path: str) -> bool:
        try:
            st = os.lstat(path)
        except OSError:
            return False
        if getattr(st, "st_file_attributes", 0) & _REPARSE:
            return True
        return os.path.islink(path)

    def stats(self, path: str, max_files: int = MAX_FILES, *,
              guards: Optional[Guards] = None, cluster: int = DEFAULT_CLUSTER
              ) -> Dict[str, Any]:
        """files, bytes, alloc_bytes (NTFS cost on a `cluster` volume), newest (epoch),
        reparse (nested links, not followed), truncated (the walk hit max_files),
        errors, guarded (entries `guards` refuses, or VM disks) + guarded_example."""
        out: Dict[str, Any] = {"files": 0, "bytes": 0, "alloc_bytes": 0, "newest": None,
                               "reparse": 0, "truncated": False, "errors": 0,
                               "guarded": 0, "guarded_example": None}

        def guarded(p: str, is_file: bool) -> bool:
            hit = (is_file and p.lower().endswith(VM_DISK_SUFFIXES)) or bool(
                guards is not None and guards.refusal(p))
            if hit:
                out["guarded"] += 1
                out["guarded_example"] = out["guarded_example"] or p
            return hit

        stack = [path]
        while stack:
            d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                out["errors"] += 1
                continue
            with it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                        link = e.is_symlink() or bool(
                            getattr(st, "st_file_attributes", 0) & _REPARSE)
                        if link:
                            out["reparse"] += 1
                        elif e.is_dir(follow_symlinks=False):
                            out["alloc_bytes"] += MFT_RECORD
                            if not guarded(e.path, False):
                                stack.append(e.path)
                        else:
                            guarded(e.path, True)
                            out["files"] += 1
                            out["bytes"] += int(st.st_size)
                            out["alloc_bytes"] += _alloc(st.st_size, cluster)
                            if out["newest"] is None or st.st_mtime > out["newest"]:
                                out["newest"] = float(st.st_mtime)
                            if out["files"] > max_files:
                                out["truncated"] = True
                                return out
                    except OSError:
                        out["errors"] += 1
        return out

    def remove_empty_tree(self, path: str) -> None:
        """rmdir bottom-up. Raises on the first non-empty directory -- never deletes
        a file, so it is safe to call after a move that should have left nothing."""
        if not os.path.isdir(path) or self.is_reparse(path):
            return
        for dirpath, _dirs, files in os.walk(path, topdown=False):
            if files:
                raise OSError(f"{dirpath} still holds {len(files)} file(s)")
            os.rmdir(dirpath)

    def make_junction(self, link: str, target: str, runner: Optional[Runner] = None) -> None:
        try:
            import _winapi  # type: ignore[import-not-found]
            create = getattr(_winapi, "CreateJunction", None)
        except ImportError:
            create = None
        if create is not None:
            create(str(target), str(link))
            return
        if os.name != "nt":
            raise OSError("junctions exist only on Windows")
        rc, out = (runner or default_runner)(["cmd", "/c", "mklink", "/J", str(link),
                                              str(target)])
        if rc != 0:
            raise OSError(f"mklink /J exited {rc}: {out.strip()[:300]}")

    def remove_junction(self, link: str) -> None:
        # os.rmdir on a junction removes the LINK, never the target's contents.
        os.rmdir(link)

    def reconcile_back(self, dst: str, src: str) -> List[str]:
        """After the move back: delete each file left at `dst` whose `src` counterpart is
        byte-identical (a copy the forward move could not delete, which the rollback's
        /XO /XN /XC rightly skipped), and return every other file still at `dst` -- a
        conflict, left where it is for a human."""
        import filecmp  # noqa: PLC0415

        conflicts: List[str] = []
        if not os.path.isdir(dst) or self.is_reparse(dst):
            return conflicts
        for dirpath, _dirs, files in os.walk(dst):
            for name in files:
                d = os.path.join(dirpath, name)
                s = os.path.join(src, os.path.relpath(d, dst))
                try:
                    same = os.path.isfile(s) and filecmp.cmp(s, d, shallow=False)
                    if same:
                        os.remove(d)
                        continue
                except OSError:
                    logger.debug("relocate: non-fatal", exc_info=True)
                conflicts.append(d)
        return conflicts


def default_runner(argv: Sequence[str]) -> Tuple[int, str]:
    r = subprocess.run(list(argv), capture_output=True, text=True, encoding="utf-8",
                       errors="replace", check=False)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def default_free_space(drive: str) -> int:
    return int(shutil.disk_usage(drive + "\\").free)


def open_handles(path: str) -> Optional[int]:
    """Open file handles under `path` across the processes psutil can see; None when
    psutil is absent or the probe itself failed (unknown is not zero)."""
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        return None
    root = os.path.normcase(os.path.abspath(path))
    prefix = root.rstrip("\\/") + os.sep
    n = 0
    try:
        for proc in psutil.process_iter():
            try:
                files = proc.open_files()
            except Exception:  # noqa: BLE001 -- access denied / gone: best effort
                continue
            for f in files:
                p = os.path.normcase(str(getattr(f, "path", "")))
                if p == root or p.startswith(prefix):
                    n += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("open-handle probe failed for %s: %s", path, exc)
        return None
    return n


# ── plan ──────────────────────────────────────────────────────────────────────

def _dest_for(src: str, dest_drive: str, dest_root: Optional[str]) -> str:
    rest = re.sub(r"^[A-Za-z]:", "", src).lstrip("\\/")
    if dest_root:
        return os.path.join(dest_root, rest)
    return dest_drive + os.sep + rest if os.sep == "\\" else dest_drive + "/" + rest


def _gb(n: float) -> float:
    return round(n / GIB, 2)


class Protection:
    """Every root a relocation may not touch, each in its written AND its resolved form
    (a junction or a short name in the topology file must not open a hole either)."""

    def __init__(self, topology: Optional[Dict[str, Any]], fs: HostFS) -> None:
        self.fs = fs
        self.guards = Guards(topology)
        # ~/.aither holds this tree, apply.lock, the maintenance marker, catalog.db and
        # the session bearer: moving it (or a parent of it) breaks the mover itself.
        own = [str(Path.home() / ".aither"), str(relocate_dir())]
        self.protected = self._both(list(do_not_move_roots(topology)) + own)
        self.never = self._both(self.guards.never_roots)

    def _both(self, roots: Iterable[str]) -> List[str]:
        out = set()
        for r in roots:
            out.add(norm(r))
            try:
                out.add(norm(self.fs.canon(r)))
            except (OSError, ValueError):
                logger.debug("relocate: non-fatal", exc_info=True)
        return sorted(out)


def validate_move(source: str, dest: str, prot: Protection, *,
                  dest_drive: Optional[str] = None, as_written: Optional[str] = None
                  ) -> List[str]:
    """The static refusals for one move -- the planner, approve_plan and _apply_move
    all call this, so a hand-written plan file gets the planner's judgement too.

    `source` must already be canonical (a plan records the resolved path); a source
    that no longer resolves to itself is refused. `as_written` is what the caller
    typed, checked as well (an alias can only add refusals)."""
    fs, guards = prot.fs, prot.guards
    why: List[str] = []
    real = fs.canon(source)
    if os.path.normcase(real) != os.path.normcase(os.path.abspath(source)):
        why.append(f"resolves to {real} (a junction, symlinked parent or short name);"
                   " plan the real path")
    rdest = fs.canon(dest) if dest else ""
    sdrive = fs.drive_of(real)
    ddrive = fs.drive_of(rdest) if rdest else None
    if sdrive is None:
        why.append("is not on a Windows drive letter")
    if ddrive is None:
        why.append(f"destination {dest or '(none)'} is not on a Windows drive letter")
    elif dest_drive is not None and ddrive != dest_drive:
        why.append(f"destination {dest} is not on {dest_drive}"
                   + (f" (it resolves to {rdest})" if rdest != dest else ""))
    if sdrive is not None and sdrive in (ddrive, dest_drive):
        why.append(f"is already on {sdrive}")
    if re.fullmatch(r"[A-Za-z]:[\\/]?", real):
        why.append("is a drive root")
    forms = [real] + ([as_written] if as_written and as_written != real else [])
    if any(guards.is_never(f) for f in forms):
        why.append("is in the never set (live state, source, OS tree or node_modules)")
    if any(is_sensitive(f) for f in forms):
        why.append("is a sensitive path (credential or key material, ~/.aither)")
    for root in prot.never:
        if any(_under(root, f) and norm(root).lower() != norm(f).lower() for f in forms):
            why.append(f"contains never-set root {root}")
            break
    for root in prot.protected:
        if any(_overlaps(f, root) for f in forms):
            why.append(f"overlaps do-not-move root {root}")
            break
    if rdest:
        if _overlaps(real, rdest) or _overlaps(real, dest):
            why.append(f"destination {dest} overlaps the source")
        if guards.refusal(rdest) or any(_overlaps(rdest, r) for r in prot.protected):
            why.append(f"destination {dest} is protected (never set, sensitive or"
                       " do-not-move)")
    return why


def plan_problems(plan: Dict[str, Any], prot: Protection, *,
                  check_moves: bool = True) -> List[str]:
    """Why a plan FILE may not be approved or applied, judged afresh -- never from its
    own `ok` field (anything that can write plans/ could write that). With
    ``check_moves=False`` the per-move static validation is skipped (apply runs it per
    move, right before the move, when earlier moves' sources are already junctions)."""
    out: List[str] = []
    if not plan.get("ok") or plan.get("refusals"):
        out.append("the plan records refusals: "
                   + "; ".join(plan.get("refusals") or ["ok is false"]))
    for drive, pr in (plan.get("projection") or {}).items():
        if not isinstance(pr, dict) or not pr.get("ok"):
            out.append(f"the projection for {drive} is not ok")
    moves = plan.get("moves")
    if not isinstance(moves, list) or not moves:
        return out + ["the plan has no moves"]
    ids: List[str] = []
    seen: List[str] = []
    for mv in moves:
        if not isinstance(mv, dict):
            out.append("a move is not an object")
            continue
        mid, src, dst = str(mv.get("id") or ""), mv.get("source"), mv.get("dest")
        if not mid or mid in ids:
            out.append(f"move id {mid!r} is missing or repeated")
        ids.append(mid)
        if mv.get("link", "junction") not in ("junction", "none"):
            out.append(f"{mid} link {mv.get('link')!r} is not junction|none")
        if not isinstance(src, str) or not isinstance(dst, str) \
                or not os.path.isabs(src) or not os.path.isabs(dst):
            out.append(f"{mid} source/dest must be absolute paths")
            continue
        if check_moves:
            out += [f"{mid} {src} {w}" for w in validate_move(src, dst, prot)]
        for other in seen:
            if _overlaps(src, other) or _overlaps(dst, other):
                out.append(f"{mid} {src} overlaps another path in this plan ({other})")
        seen += [src, dst]
    return out


def plan_relocation(
    sources: Iterable[str],
    dest_drive: str,
    floors: Optional[Dict[str, float]],
    free_space_fn: FreeSpaceFn,
    now: Optional[datetime] = None,
    *,
    fs: Optional[HostFS] = None,
    dest_root: Optional[str] = None,
    topology: Optional[Dict[str, Any]] = None,
    mounts: Optional[Sequence[str]] = None,
    handles_fn: Optional[Callable[[str], Optional[int]]] = open_handles,
    cold_min_days: float = COLD_MIN_DAYS,
    max_files: int = MAX_FILES,
    link: str = "junction",
    plan_id: Optional[str] = None,
    cluster_fn: Optional[Callable[[str], int]] = default_cluster_size,
) -> Dict[str, Any]:
    """Build a relocation plan. Pure given its injections; writes nothing.

    ``free_space_fn(drive)`` answers free BYTES for "X:". ``mounts`` is the list of
    host paths containers bind (None = not checked -> ``container_mounted: null``).
    The plan's ``ok`` is True only when there is no refusal at all. Every source is
    canonicalised (junctions, symlinked parents, 8.3 names) and the RESOLVED path is
    what the plan records and every check compares. A source with a protection
    refusal is not walked at all (a parent of ~/.aither or of a never root).
    """
    fs = fs or HostFS()
    floors = dict(floors or DEFAULT_FLOORS)
    now = _now(now)
    dest_drive = norm_drive(dest_drive)
    if link not in ("junction", "none"):
        raise RelocateError(f"link must be 'junction' or 'none', not {link!r}")
    prot = Protection(topology, fs)
    guards = prot.guards
    cluster = int(cluster_fn(dest_drive)) if cluster_fn else DEFAULT_CLUSTER
    refusals: List[str] = []
    moves: List[Dict[str, Any]] = []
    delta: Dict[str, float] = {dest_drive: 0.0}
    seen: List[str] = []
    srcs = [str(s) for s in sources]
    if not srcs:
        raise RelocateError("no --source given")
    for i, raw in enumerate(srcs, 1):
        mid = f"m{i}"
        src = fs.canon(raw)
        dest = _dest_for(src, dest_drive, dest_root)
        why: List[str] = []
        move: Dict[str, Any] = {
            "id": mid, "source": src, "dest": dest, "bytes": 0, "files": 0,
            "newest_mtime": None,
            "evidence": {"cold_days": 0, "open_handles": None, "container_mounted": None},
            "link": link,
        }
        moves.append(move)
        sdrive = fs.drive_of(src)
        typed = os.path.abspath(raw)
        if not fs.exists(typed):
            why.append("does not exist")
        elif fs.is_reparse(typed) or fs.is_reparse(src):
            why.append("is a reparse point (junction/symlink) -- already relocated, or not"
                       " the real tree")
        elif not fs.is_dir(src):
            why.append("is not a directory")
        static = validate_move(src, dest, prot, dest_drive=dest_drive, as_written=typed)
        why += static
        for other in seen:
            if _overlaps(src, other):
                why.append(f"overlaps another source in this plan ({other})")
        seen.append(src)
        if fs.drive_of(dest) == dest_drive and fs.exists(dest):
            why.append(f"destination {dest} already exists")
        measurable = (not static and fs.exists(src) and fs.is_dir(src)
                      and not fs.is_reparse(src) and not fs.is_reparse(typed))
        if measurable:
            st = fs.stats(src, max_files, guards=guards, cluster=cluster)
            move["bytes"], move["files"] = int(st["bytes"]), int(st["files"])
            if st["newest"] is not None:
                newest = datetime.fromtimestamp(st["newest"], timezone.utc)
                move["newest_mtime"] = _iso(newest)
                age_days = (now - newest).total_seconds() / 86400.0
                move["evidence"]["cold_days"] = max(0, int(age_days))
                if age_days < cold_min_days:
                    why.append(f"is HOT: newest file modified {age_days:.1f} day(s) ago"
                               f" (cold_min_days {cold_min_days:g})")
            if st["truncated"]:
                why.append(f"has more than {max_files} files; the byte count is unknown")
            if st["reparse"]:
                why.append(f"contains {st['reparse']} nested reparse point(s); robocopy"
                           " would follow them")
            if st["errors"]:
                why.append(f"{st['errors']} entr(y/ies) could not be read; the byte count"
                           " is unknown")
            if not st["files"]:
                why.append("holds no files")
            if st["guarded"]:
                why.append(f"contains {st['guarded']} protected entr(y/ies) (VM disk,"
                           f" credential, never-set path), e.g. {st['guarded_example']}")
            if handles_fn is not None:
                h = handles_fn(src)
                move["evidence"]["open_handles"] = h
                if h:
                    why.append(f"has {h} open file handle(s)")
            if mounts is not None:
                hit = [m for m in mounts if _overlaps(src, m)]
                move["evidence"]["container_mounted"] = bool(hit)
                if hit:
                    why.append(f"is bind-mounted into a container ({hit[0]})")
            if sdrive:
                delta[sdrive] = delta.get(sdrive, 0.0) + move["bytes"]
            delta[dest_drive] -= int(st["alloc_bytes"]) * OVERHEAD
        refusals += [f"{mid} {src} {w}" for w in why]

    projection: Dict[str, Dict[str, Any]] = {}
    for drive in sorted(delta):
        floor = floor_for(floors, drive)
        try:
            before = float(free_space_fn(drive))
        except Exception as exc:  # noqa: BLE001 -- an unreadable drive is not a pass
            refusals.append(f"cannot read free space on {drive}: {type(exc).__name__}: {exc}")
            projection[drive] = {"free_before_gb": None, "free_after_gb": None,
                                 "floor_gb": floor, "ok": False}
            continue
        after = before + delta[drive]
        # A drive the plan only GAINS on is never the plan's fault, even if it is
        # already under its floor -- relocating OFF a full drive is the point.
        ok = after >= floor * GIB or after >= before
        projection[drive] = {"free_before_gb": _gb(before), "free_after_gb": _gb(after),
                             "floor_gb": floor, "ok": ok}
        if not ok:
            refusals.append(
                f"{drive} would fall to {_gb(after):.1f} GB free, below its {floor:g} GB"
                f" floor (free now {_gb(before):.1f} GB, incoming"
                f" {_gb(-delta[drive]):.1f} GB on disk: {cluster}-byte clusters, one MFT"
                f" record per entry, +{int((OVERHEAD - 1) * 100)}%)")
    pid = plan_id or f"rel-{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
    return {"plan_id": pid, "created_at": _iso(now), "moves": moves,
            "projection": projection, "ok": not refusals, "refusals": refusals}


def save_plan(plan: Dict[str, Any], base: Optional[Path] = None) -> Path:
    p = _sub(base, "plans") / f"{plan['plan_id']}.json"
    _write_json(p, plan)
    return p


def _safe_id(plan_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(plan_id or "")):
        raise RelocateError(f"not a plan id: {plan_id!r}")
    return plan_id


def load_plan(plan_id: str, base: Optional[Path] = None) -> Dict[str, Any]:
    plan = _read_json(_sub(base, "plans") / f"{_safe_id(plan_id)}.json")
    if plan is None:
        raise RelocateError(f"no plan {plan_id} under {_sub(base, 'plans')}")
    return plan


def load_approval(plan_id: str, base: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    return _read_json(_sub(base, "approved") / f"{_safe_id(plan_id)}.json")


def load_result(plan_id: str, base: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    return _read_json(_sub(base, "results") / f"{_safe_id(plan_id)}.json")


# ── approve ───────────────────────────────────────────────────────────────────

def approve_plan(plan_id: str, *, approved_by: str, via: str, base: Optional[Path] = None,
                 card_id: Optional[str] = None, note: Optional[str] = None,
                 now: Optional[datetime] = None, topology: Optional[Dict[str, Any]] = None,
                 fs: Optional[HostFS] = None) -> Dict[str, Any]:
    """Write approved/<plan_id>.json, bound to the plan's digest.

    The CALLER is the authority (the card consumer after an owner's answer, or the
    owner's own --i-am-the-owner); this refuses only what no approval can make safe.
    The plan FILE is re-judged here -- every move through :func:`validate_move`
    against the topology (``topology=None`` loads the repo's) -- and its own ``ok`` is
    never taken as authority. A plan already applied is refused; re-approving the same
    bytes is a no-op.
    """
    plan = load_plan(plan_id, base)
    if str(plan.get("plan_id") or "") != plan_id:
        raise RelocateRefusedError(f"plans/{plan_id}.json names plan"
                                   f" {plan.get('plan_id')!r}")
    if topology is None:
        topology = load_relocate_topology()[0]
    probs = plan_problems(plan, Protection(topology, fs or HostFS()))
    if probs:
        raise RelocateRefusedError(f"plan {plan_id} cannot be approved: " + "; ".join(probs))
    if load_result(plan_id, base) is not None:
        raise RelocateRefusedError(f"plan {plan_id} already has a result; plan again")
    prior = load_approval(plan_id, base)
    digest = plan_digest(plan)
    if prior and prior.get("plan_sha256") == digest:
        return prior
    rec = {"plan_id": plan_id, "approved_at": _iso(_now(now)), "approved_by": approved_by,
           "via": via, "card_id": card_id, "note": note, "plan_sha256": digest}
    _write_json(_sub(base, "approved") / f"{plan_id}.json", rec)
    return rec


# ── notify ────────────────────────────────────────────────────────────────────

def _benign(ev: Dict[str, Any]) -> bool:
    """An applied move that neither recovered a crash nor left its drive under a floor."""
    return ev["outcome"] == "applied" and not ev.get("recovered") \
        and not ev.get("floor_breach")


def _relay_text(ev: Dict[str, Any]) -> str:
    return (f"awstorage relocate {ev['outcome']}: {ev['source']} -> {ev['dest']}"
            f" ({_gb(ev.get('bytes') or 0):.1f} GB, {ev.get('files', 0)} files,"
            f" plan {ev['plan_id']}/{ev['move_id']})"
            + (f" -- {ev['reason']}" if ev.get("reason") else ""))


def post_awrelay(ev: Dict[str, Any]) -> Dict[str, Any]:
    """One #agents line through the awrelay CLI (it owns the bearer and the outbox)."""
    kind = "finding" if _benign(ev) else "alert"
    argv = [sys.executable, "-m", "awrelay", "send", "#agents", _relay_text(ev),
            "--kind", kind]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60, check=False)
    except Exception as exc:  # noqa: BLE001
        return {"channel": "awrelay", "ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    if r.returncode != 0:
        return {"channel": "awrelay", "ok": False,
                "reason": f"exit {r.returncode}: {(r.stderr or r.stdout).strip()[:300]}"}
    return {"channel": "awrelay", "ok": True, "reason": None}


def post_pulse(ev: Dict[str, Any]) -> Dict[str, Any]:
    """One Alertmanager-shaped event to Pulse (/alerts/webhook), internal CA.

    URL: $AWSTORAGE_PULSE_URL (default https://127.0.0.1:8081/alerts/webhook -- Pulse's
    port in config/services.yaml). CA: $AWSTORAGE_PULSE_CA, else the system store;
    verification is never switched off.
    """
    url = os.environ.get("AWSTORAGE_PULSE_URL") or "https://127.0.0.1:8081/alerts/webhook"
    ok_move = _benign(ev)
    body = {"alerts": [{
        "status": "resolved" if ok_move else "firing",
        "labels": {"alertname": "StorageRelocated" if ok_move else "StorageRelocateFailed",
                   "severity": "info" if ok_move else "warning",
                   "service": "awstorage", "source": "awstorage.relocate",
                   "plan_id": ev["plan_id"], "move_id": ev["move_id"]},
        "annotations": {"summary": _relay_text(ev)[:200],
                        "description": json.dumps(ev, sort_keys=True)[:1000]},
    }]}
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("AITHER_INTERNAL_KEY")
    if key:
        headers["X-Internal-Key"] = key
    try:
        ctx = ssl.create_default_context(cafile=os.environ.get("AWSTORAGE_PULSE_CA") or None)
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:  # noqa: S310
            code = int(resp.status)
    except Exception as exc:  # noqa: BLE001
        return {"channel": "pulse", "ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    if code >= 300:
        return {"channel": "pulse", "ok": False, "reason": f"HTTP {code}"}
    return {"channel": "pulse", "ok": True, "reason": None}


def default_notifier(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [post_awrelay(ev), post_pulse(ev)]


# ── apply ─────────────────────────────────────────────────────────────────────

class _Lock:
    """One apply at a time per relocate dir (the wake is one-in-flight; a hand run of
    `apply` beside it is not)."""

    def __init__(self, base: Optional[Path]) -> None:
        self.path = Path(base or relocate_dir()) / "apply.lock"
        self.held = False

    def __enter__(self) -> "_Lock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    stale = time.time() - self.path.stat().st_mtime > _LOCK_STALE_S
                except OSError:
                    stale = True
                if stale:
                    try:
                        self.path.unlink()
                    except OSError:
                        logger.debug("relocate: non-fatal", exc_info=True)
                    continue
                raise RelocateError(f"another apply holds {self.path}")
            with os.fdopen(fd, "w") as fh:
                fh.write(f"{os.getpid()} {socket.gethostname()}\n")
            self.held = True
            return self
        raise RelocateError(f"cannot take {self.path}")

    def __exit__(self, *_exc: Any) -> None:
        if self.held:
            try:
                self.path.unlink()
            except OSError:
                logger.debug("relocate: non-fatal", exc_info=True)


def _robocopy(src: str, dst: str) -> List[str]:
    return ["robocopy", src, dst, "/E", *ROBOCOPY_FLAGS, "/NP", "/NFL", "/NDL"]


def _robocopy_back(dst: str, src: str) -> List[str]:
    return ["robocopy", dst, src, "/E", *ROBOCOPY_FLAGS, *ROLLBACK_EXTRA, "/NP", "/NFL",
            "/NDL"]


def journal_path(plan_id: str, base: Optional[Path] = None) -> Path:
    return _sub(base, "journal") / f"{_safe_id(plan_id)}.json"


def _parse_iso(v: Any) -> Optional[datetime]:
    try:
        return datetime.strptime(str(v), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _roll_up(outcomes: Sequence[str]) -> Tuple[str, int]:
    """The plan-level outcome. rollback-failed outranks everything: bytes may be split
    between source and destination, and a top-level 'partial' would hide that."""
    if outcomes and all(o == "applied" for o in outcomes):
        return "applied", 0
    if any(o == "rollback-failed" for o in outcomes):
        return "rollback-failed", 1
    if any(o == "applied" for o in outcomes):
        return "partial", 1
    if any(o in ("failed", "rolled-back") for o in outcomes):
        return "failed", 1
    return "refused", 1


def _node() -> str:
    try:
        from .identity import whoami  # noqa: PLC0415

        return whoami()
    except Exception:  # noqa: BLE001
        return socket.gethostname()


def _ledger(catalog: Any, node: str, plan_id: str, row: Dict[str, Any]) -> Optional[str]:
    """One awstorage ledger row per attempted move. Returns an error string or None."""
    if catalog is False:
        return None
    try:
        from .catalog import Catalog  # noqa: PLC0415

        own = not hasattr(catalog, "ledger")
        cat = Catalog(str(catalog or default_catalog())) if own else catalog
        try:
            cat.ledger(proposal_id=None, node=node, path=row["source"], action="relocate",
                       outcome=row["outcome"], bytes_=int(row.get("bytes") or 0),
                       detail=json.dumps({"plan_id": plan_id, "move_id": row["id"],
                                          "dest": row["dest"], "files": row.get("files"),
                                          "reason": row.get("reason"),
                                          "rolled_back": row.get("rolled_back")},
                                         sort_keys=True))
        finally:
            if own:
                cat.close()
    except Exception as exc:  # noqa: BLE001 -- recorded in the result, never fatal
        logger.error("relocate ledger append failed for %s: %s", row.get("source"), exc)
        return f"{type(exc).__name__}: {exc}"
    return None


def _refuse(plan_id: str, reason: str, code: int = 1) -> Dict[str, Any]:
    return {"plan_id": plan_id, "outcome": "refused", "reason": reason, "moves": [],
            "exit_code": code, "written": False}


def _notify_row(notify: Notifier, pid: str, node: str, row: Dict[str, Any]) -> None:
    ev = {"plan_id": pid, "move_id": row["id"], "outcome": row["outcome"],
          "source": row["source"], "dest": row["dest"], "bytes": row["bytes"],
          "files": row["files"], "reason": row["reason"], "node": node,
          "recovered": bool(row.get("recovered")), "floor_breach": row.get("floor_breach")}
    try:
        row["notifications"] = list(notify(ev))
    except Exception as exc:  # noqa: BLE001 -- never fatal, never silent
        row["notifications"] = [{"channel": "notify", "ok": False,
                                 "reason": f"{type(exc).__name__}: {exc}"}]
    for n in row["notifications"]:
        if not n.get("ok"):
            logger.error("relocate %s/%s: %s post failed: %s", pid, row["id"],
                         n.get("channel"), n.get("reason"))


def apply_plan(
    plan: Dict[str, Any],
    runner: Optional[Runner] = None,
    fs: Optional[HostFS] = None,
    now: Optional[datetime] = None,
    *,
    base: Optional[Path] = None,
    free_space_fn: Optional[FreeSpaceFn] = None,
    floors: Optional[Dict[str, float]] = None,
    catalog: Any = None,
    notify: Optional[Notifier] = None,
    node: Optional[str] = None,
    topology: Optional[Dict[str, Any]] = None,
    handles_fn: Optional[Callable[[str], Optional[int]]] = open_handles,
    cluster_fn: Optional[Callable[[str], int]] = default_cluster_size,
) -> Dict[str, Any]:
    """Carry out an APPROVED plan, one move at a time. Returns the result dict (also
    written to results/<plan_id>.json once any move was attempted), with exit_code.

    ``catalog``: a Catalog, a path, None (the default catalog) or False (no ledger).
    ``floors``/``topology`` None load the repo's storage-topology.yaml.

    Before each robocopy, journal/<plan_id>.json names the move and its measured
    ``before``; it is rewritten as each move finishes and removed once the result is
    written. A journal found here means the previous apply DIED mid-move: that move is
    recovered first (finished if it had linked and verifies, otherwise moved back), and
    the recovery is announced like any other move.
    """
    runner = runner or default_runner
    fs = fs or HostFS()
    free_space_fn = free_space_fn or default_free_space
    notify = notify or default_notifier
    pid = _safe_id(str(plan.get("plan_id") or ""))
    approval = load_approval(pid, base)
    if approval is None:
        return _refuse(pid, f"plan {pid} is not approved (no {_sub(base, 'approved')}"
                            f"/{pid}.json)")
    if approval.get("plan_sha256") != plan_digest(plan):
        return _refuse(pid, f"plan {pid} changed after it was approved (digest mismatch)")
    jpath = journal_path(pid, base)
    prior = load_result(pid, base)
    if prior is not None:
        if jpath.exists():  # died between writing the result and dropping the journal
            try:
                jpath.unlink()
            except OSError:
                logger.debug("relocate: non-fatal", exc_info=True)
        code = int(prior.get("exit_code", 0 if prior.get("ok") else 1))
        if not prior.get("ok"):
            code = max(code, 1)
        return dict(prior, note="already recorded; not re-applied", exit_code=code,
                    written=False)
    if floors is None or topology is None:
        topo, fl, _where = load_relocate_topology()
        floors = fl if floors is None else floors
        topology = topo if topology is None else topology
    prot = Protection(topology, fs)
    node = node or _node()
    started = _iso(_now(now))
    rows: List[Dict[str, Any]] = []
    with _Lock(base):
        journal = _read_json(jpath) or {}
        probs = plan_problems(plan, prot, check_moves=False)
        if probs and not journal:
            # Approved, but the file does not survive re-judgement: record it (so the
            # wake stops retrying) and say so -- never a silent refusal.
            row = {"id": "-", "source": "-", "dest": "-", "bytes": 0, "files": 0,
                   "outcome": "refused", "reason": "; ".join(probs), "notifications": []}
            _notify_row(notify, pid, node, row)
            result = {"plan_id": pid, "started_at": started, "finished_at": _iso(_now()),
                      "node": node, "approved_by": approval.get("approved_by"),
                      "outcome": "refused", "reason": row["reason"], "ok": False,
                      "moves": [], "notifications": row["notifications"], "exit_code": 1}
            _write_json(_sub(base, "results") / f"{pid}.json", result)
            result["written"] = True
            return result
        done = {str(r.get("id")): r for r in journal.get("rows") or []
                if isinstance(r, dict) and r.get("id")}
        current = journal.get("current") if isinstance(journal.get("current"), dict) else None

        def write_journal(cur: Optional[Dict[str, Any]]) -> None:
            finished = [r for r in rows if r.get("outcome") != "not-attempted"
                        and (cur is None or r["id"] != cur["id"])]
            _write_json(jpath, {"plan_id": pid, "started_at": started, "rows": finished,
                                "current": cur})

        stop = None
        for mv in plan.get("moves") or []:
            mid = str(mv["id"])
            if mid in done:
                rows.append(done[mid])
                if done[mid].get("outcome") != "applied":
                    stop = stop or f"stopped after {mid} {done[mid].get('outcome')}"
                continue
            row: Dict[str, Any] = {"id": mv["id"], "source": mv["source"],
                                   "dest": mv["dest"], "bytes": 0, "files": 0,
                                   "outcome": "not-attempted", "reason": stop,
                                   "robocopy_rc": None, "linked": False,
                                   "rolled_back": False, "notifications": []}
            rows.append(row)
            if stop:
                continue
            if current is not None and str(current.get("id")) == mid:
                _recover_move(mv, row, current, runner, fs)
            else:
                _apply_move(mv, row, runner, fs, free_space_fn, floors, prot=prot,
                            now=_now(now), handles_fn=handles_fn, cluster_fn=cluster_fn,
                            journal=lambda before, _mv=mv: write_journal(
                                {"id": str(_mv["id"]), "source": _mv["source"],
                                 "dest": _mv["dest"],
                                 "before": {"files": int(before["files"]),
                                            "bytes": int(before["bytes"])}}))
            if row["outcome"] != "applied":
                stop = f"stopped after {mv['id']} {row['outcome']}"
            err = _ledger(catalog, node, pid, row)
            if err:
                row["ledger_error"] = err
            # Every attempted move of an APPROVED plan is announced, refusals too.
            _notify_row(notify, pid, node, row)
            row.pop("measured", None)
            try:
                write_journal(None)
            except OSError as exc:
                logger.error("relocate %s: cannot update the journal: %s", pid, exc)
    outcome, code = _roll_up([r["outcome"] for r in rows])
    result = {"plan_id": pid, "started_at": started, "finished_at": _iso(_now()),
              "node": node, "approved_by": approval.get("approved_by"),
              "outcome": outcome, "ok": code == 0, "moves": rows, "exit_code": code}
    _write_json(_sub(base, "results") / f"{pid}.json", result)
    result["written"] = True
    try:
        jpath.unlink()
    except FileNotFoundError:
        logger.debug("relocate: non-fatal", exc_info=True)
    except OSError as exc:
        logger.error("relocate %s: result written but the journal remains: %s", pid, exc)
    return result


def _apply_move(mv: Dict[str, Any], row: Dict[str, Any], runner: Runner, fs: HostFS,
                free_space_fn: FreeSpaceFn, floors: Dict[str, float], *,
                prot: Protection, now: datetime,
                handles_fn: Optional[Callable[[str], Optional[int]]],
                cluster_fn: Optional[Callable[[str], int]],
                journal: Callable[[Dict[str, Any]], None]) -> None:
    src, dst = mv["source"], mv["dest"]
    # Re-verify the world the plan was made in. Every check here is one the planner
    # also made; the time between approval and execution is where they go stale, and
    # the plan FILE is not trusted to have been made by the planner at all.
    static = validate_move(src, dst, prot)
    if static:
        row.update(outcome="refused", reason="; ".join(static))
        return
    if not fs.exists(src) or not fs.is_dir(src):
        row.update(outcome="refused", reason=f"{src} no longer exists")
        return
    if fs.is_reparse(src):
        row.update(outcome="refused", reason=f"{src} is now a reparse point (already moved?)")
        return
    if fs.exists(dst):
        row.update(outcome="refused", reason=f"destination {dst} now exists")
        return
    ddrive = fs.drive_of(fs.canon(dst)) or ""
    cluster = int(cluster_fn(ddrive)) if cluster_fn else DEFAULT_CLUSTER
    before = fs.stats(src, guards=prot.guards, cluster=cluster)
    row.update(bytes=int(before["bytes"]), files=int(before["files"]), measured=True)
    if before["truncated"] or before["reparse"] or before["errors"] or not before["files"] \
            or before["guarded"]:
        row.update(outcome="refused", reason=(
            f"{src} cannot be moved exactly now: files={before['files']}"
            f" reparse={before['reparse']} errors={before['errors']}"
            f" truncated={before['truncated']} protected={before['guarded']}"
            + (f" (e.g. {before['guarded_example']})" if before["guarded"] else "")))
        return
    planned = _parse_iso(mv.get("newest_mtime"))
    newest = before["newest"]
    if planned is None or (newest is not None and newest >= planned.timestamp() + 1):
        seen = _iso(datetime.fromtimestamp(newest, timezone.utc)) if newest else "?"
        row.update(outcome="refused", reason=(
            f"{src} is HOT: written since it was planned (newest file now {seen}, the plan"
            f" saw {mv.get('newest_mtime')})"))
        return
    if handles_fn is not None:
        h = handles_fn(src)
        row["open_handles"] = h
        if h:
            row.update(outcome="refused", reason=f"{src} has {h} open file handle(s) now")
            return
    floor = floor_for(floors, ddrive)
    try:
        free = float(free_space_fn(ddrive))
    except Exception as exc:  # noqa: BLE001
        row.update(outcome="refused", reason=f"cannot read free space on {ddrive}: {exc}")
        return
    after = free - int(before["alloc_bytes"]) * OVERHEAD
    row["floor_check"] = {"drive": ddrive, "free_now_gb": _gb(free),
                          "free_after_gb": _gb(after), "floor_gb": floor}
    if after < floor * GIB:
        row.update(outcome="refused", reason=(
            f"{ddrive} would fall to {_gb(after):.1f} GB free, below its {floor:g} GB"
            f" floor (free NOW {_gb(free):.1f} GB; {_gb(before['alloc_bytes']):.1f} GB on"
            f" disk incoming, the plan measured {mv.get('bytes', 0) / GIB:.1f} GB logical)"))
        return
    try:
        journal(before)
    except Exception as exc:  # noqa: BLE001 -- no journal, no move
        row.update(outcome="refused", reason=f"cannot write the relocate journal: {exc}")
        return

    failure = None
    try:
        rc, out = runner(_robocopy(src, dst))
        row["robocopy_rc"] = rc
        if rc >= ROBOCOPY_FAIL_RC:
            failure = f"robocopy exited {rc}: {out.strip()[-300:]}"
    except Exception as exc:  # noqa: BLE001
        failure = f"robocopy could not run: {type(exc).__name__}: {exc}"
    if failure is None:
        left = fs.stats(src) if fs.exists(src) else {"files": 0, "bytes": 0}
        got = fs.stats(dst) if fs.exists(dst) else {"files": 0, "bytes": 0}
        row["verified"] = {"source_files_left": left["files"], "dest_files": got["files"],
                           "dest_bytes": got["bytes"]}
        if left["files"] or got["files"] != before["files"] or got["bytes"] != before["bytes"]:
            failure = (f"verification failed: source still holds {left['files']} file(s);"
                       f" destination has {got['files']}/{before['files']} files,"
                       f" {got['bytes']}/{before['bytes']} bytes")
    if failure is None and mv.get("link", "junction") == "junction":
        try:
            fs.remove_empty_tree(src)
            fs.make_junction(src, dst, runner)
            if not fs.is_reparse(src):
                raise OSError(f"{src} is not a reparse point after the link")
            row["linked"] = True
        except Exception as exc:  # noqa: BLE001
            failure = f"junction {src} -> {dst} failed: {type(exc).__name__}: {exc}"
    if failure is None:
        row.update(outcome="applied", reason=None)
        _floor_after(row, ddrive, floor, free_space_fn)
        return
    row["reason"] = failure
    _rollback(row, src, dst, before, runner, fs)


def _floor_after(row: Dict[str, Any], drive: str, floor: float,
                 free_space_fn: FreeSpaceFn) -> None:
    """The model is an estimate: measure the destination after the move, and say so
    loudly if it ended under its floor (the move itself stands)."""
    try:
        free = float(free_space_fn(drive))
    except Exception as exc:  # noqa: BLE001
        row["floor_after"] = {"drive": drive, "error": f"{type(exc).__name__}: {exc}"}
        return
    row["floor_after"] = {"drive": drive, "free_gb": _gb(free), "floor_gb": floor}
    if free < floor * GIB:
        row["floor_breach"] = (f"{drive} ended at {_gb(free):.1f} GB free, below its"
                               f" {floor:g} GB floor, after the move")
        row["reason"] = row["floor_breach"]
        logger.error("relocate: %s", row["floor_breach"])


def _recover_move(mv: Dict[str, Any], row: Dict[str, Any], current: Dict[str, Any],
                  runner: Runner, fs: HostFS) -> None:
    """The journal says the previous apply was inside this move when it died."""
    src, dst = mv["source"], mv["dest"]
    raw = current.get("before") if isinstance(current.get("before"), dict) else {}
    before = {"files": int(raw.get("files") or 0), "bytes": int(raw.get("bytes") or 0)}
    row.update(bytes=before["bytes"], files=before["files"], recovered=True)
    note = "recovered a move the previous apply did not finish (it died mid-move)"
    if fs.exists(src) and fs.is_reparse(src) and fs.exists(dst) \
            and os.path.normcase(fs.canon(src)) == os.path.normcase(fs.canon(dst)):
        got = fs.stats(dst)
        if got["files"] == before["files"] and got["bytes"] == before["bytes"]:
            row.update(outcome="applied", linked=True,
                       reason=f"{note}: it had completed, linked and verifies")
            return
    row["reason"] = note
    _rollback(row, src, dst, before, runner, fs)


def _rollback(row: Dict[str, Any], src: str, dst: str, before: Dict[str, Any],
              runner: Runner, fs: HostFS) -> None:
    """Move whatever reached the destination back, and prove the source is whole.

    The move back never overwrites a file that exists at the source (/XO /XN /XC): a
    file written after the forward copy keeps its new bytes. A destination file whose
    source counterpart is byte-identical is a copy the forward move could not delete,
    and is dropped; any OTHER file left at the destination is a conflict -- left in
    place and reported as rollback-failed, never resolved by guessing."""
    try:
        if fs.exists(src) and fs.is_reparse(src):
            fs.remove_junction(src)
            row["linked"] = False
        if fs.exists(dst):
            rc, out = runner(_robocopy_back(dst, src))
            row["rollback_rc"] = rc
            if rc >= ROBOCOPY_FAIL_RC:
                raise OSError(f"robocopy back exited {rc}: {out.strip()[-300:]}")
            conflicts = fs.reconcile_back(dst, src)
            if conflicts:
                row["rollback_conflicts"] = conflicts[:20]
                raise OSError(f"{len(conflicts)} file(s) at the destination differ from the"
                              " source copy and were left there (the source copy was"
                              f" kept), e.g. {conflicts[0]}")
        back = fs.stats(src) if fs.exists(src) else {"files": 0, "bytes": 0}
        if back["files"] != before["files"] or back["bytes"] != before["bytes"]:
            raise OSError(f"source holds {back['files']}/{before['files']} files,"
                          f" {back['bytes']}/{before['bytes']} bytes after the move back")
        if fs.exists(dst):
            fs.remove_empty_tree(dst)
    except Exception as exc:  # noqa: BLE001
        row.update(outcome="rollback-failed",
                   reason=f"{row['reason']}; ROLLBACK FAILED: {type(exc).__name__}: {exc}"
                          f" -- bytes may be split between {src} and {dst}")
        logger.critical("relocate rollback failed: %s", row["reason"])
        return
    row.update(outcome="rolled-back", rolled_back=True)


def apply_approved(*, base: Optional[Path] = None, marker: Optional[Path] = None,
                   **kw: Any) -> Dict[str, Any]:
    """Apply every approved plan with no result yet, oldest first, one at a time.
    While the maintenance marker exists, nothing is applied (exit 0, `skipped`)."""
    mk = Path(marker) if marker else maintenance_marker()
    if mk.exists():
        return {"skipped": f"maintenance marker present ({mk})", "results": [],
                "exit_code": 0}
    adir = _sub(base, "approved")
    pending = []
    for p in sorted(adir.glob("*.json")) if adir.is_dir() else []:
        pid = p.stem
        if (_sub(base, "results") / p.name).exists():
            continue
        pending.append(pid)
    results = []
    code = 0
    for pid in pending:
        if mk.exists():  # a window can open between two plans
            return {"skipped": f"maintenance marker appeared ({mk})", "results": results,
                    "exit_code": code}
        try:
            r = apply_plan(load_plan(pid, base), base=base, **kw)
        except RelocateError as exc:
            r = {"plan_id": pid, "outcome": "could-not-run", "reason": str(exc),
                 "exit_code": 2}
        results.append(r)
        code = max(code, int(r.get("exit_code", 1)))
    return {"skipped": None, "pending": pending, "results": results, "exit_code": code}


def status(base: Optional[Path] = None) -> Dict[str, Any]:
    pdir = _sub(base, "plans")
    rows = []
    for p in sorted(pdir.glob("*.json")) if pdir.is_dir() else []:
        try:
            plan = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            rows.append({"plan_id": p.stem, "error": f"{type(exc).__name__}: {exc}"})
            continue
        pid = str(plan.get("plan_id") or p.stem)
        appr = load_approval(pid, base)
        res = load_result(pid, base)
        interrupted = not res and journal_path(pid, base).exists()
        rows.append({"plan_id": pid, "created_at": plan.get("created_at"),
                     "ok": plan.get("ok"), "moves": len(plan.get("moves") or []),
                     "bytes": sum(int(m.get("bytes") or 0) for m in plan.get("moves") or []),
                     "approved": bool(appr),
                     "approved_by": (appr or {}).get("approved_by"),
                     "result": (res or {}).get("outcome"),
                     "state": ("done:" + str(res.get("outcome")) if res else
                               "interrupted" if interrupted else
                               "approved" if appr else
                               "planned" if plan.get("ok") else "refused")})
    return {"dir": str(Path(base or relocate_dir())), "plans": rows,
            "maintenance": maintenance_marker().exists()}
