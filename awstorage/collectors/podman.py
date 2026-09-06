"""podman.py -- container engine storage as a snapshot, never touched.

Emits ONE snapshot rooted at the virtual path `podman://engine` with the four
things a container engine can silently eat a disk with: images, dangling
images (safe to reclaim), volumes (NEVER auto-reclaimed -- classified
`service-state`, the same class `policy.NEVER_AUTO` already refuses to
auto-apply), and build cache / aborted buildah working containers.

`build_in_progress()` is a build guard: pruning while a build is writing a
layer corrupts it. It is exposed separately (not folded into `collect()`) so
a caller -- the fleet steward, `node_run.apply_orders` -- can check it
*before* running a prune-engine action, not just record it after the fact.

Every subprocess call degrades honestly: `podman`/`buildah` absent,
unreachable, or returning something unparsable is one line in `errors` and
zero bytes for that piece -- never a crash, never a guess. Measured
2026-08-19 (`reclaim_podman_disk.py`): `podman system df`'s own byte figures
under-report against `df`, and aborted buildah working containers are
invisible to every podman-native accounting command -- both are exactly the
kind of silent gap this collector exists to surface rather than hide.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from typing import Any

from .._fs import SCHEMA_VERSION, fingerprint

_SIZE_RE = re.compile(r"^\s*([\d.]+)\s*([KMGTP]?)i?B?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}
_DEFAULT_TIMEOUT = 30


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_size(value: Any) -> int:
    """Bytes from a podman JSON size field -- already an int, or a human
    string like '1.2GB' / '512MiB'. Unparsable is 0, never guessed."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        m = _SIZE_RE.match(value)
        if m:
            return int(float(m.group(1)) * _UNITS.get(m.group(2).upper(), 1))
    return 0


def podman_available() -> bool:
    return shutil.which("podman") is not None


def build_in_progress(*, timeout: int = 5,
                       run=subprocess.run) -> bool:
    """True while a build is writing a layer -- pruning now corrupts it.

    Uses `pgrep -f` for buildah/podman-build processes, per the pattern
    already relied on elsewhere in this fleet for the same question. Absent
    `pgrep` (Windows, a minimal container) answers False -- undetectable is
    treated as "not building", never as "definitely building".
    """
    if shutil.which("pgrep") is None:
        return False
    try:
        p = run(["pgrep", "-f", r"buildah|podman[ -]build"],
                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0 and bool((p.stdout or "").strip())


def _run_json(cmd: list, timeout: int, run) -> tuple[Any, str]:
    try:
        p = run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"{' '.join(cmd)}: {type(exc).__name__}: {exc}"
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()[:200]
        return None, f"{' '.join(cmd)}: exit {p.returncode}: {detail}"
    try:
        return json.loads(p.stdout or "[]"), ""
    except json.JSONDecodeError as exc:
        return None, f"{' '.join(cmd)}: unparsable JSON: {exc}"


def _images(timeout: int, run) -> tuple[int, int, int, str]:
    """(total_bytes, dangling_bytes, dangling_count, error)."""
    data, err = _run_json(["podman", "images", "--format", "json"], timeout, run)
    if data is None:
        return 0, 0, 0, err
    total = dangling_bytes = dangling_count = 0
    for row in data if isinstance(data, list) else []:
        if not isinstance(row, dict):
            continue
        size = _parse_size(row.get("Size", 0))
        total += size
        names = row.get("Names") or []
        dangling = row.get("Dangling")
        if dangling is None:
            dangling = not names
        if dangling:
            dangling_bytes += size
            dangling_count += 1
    return total, dangling_bytes, dangling_count, ""


def _volumes(timeout: int, run) -> tuple[int, str]:
    """Total volume bytes via `system df -v`. Never used to decide deletion:
    volumes are `service-state` (NEVER_AUTO) and this tool prunes no volume,
    ever -- see `reclaim_podman_disk.py`'s standing rule."""
    # Measured against podman 5.x on 2026-09-02: `system df -v --format json` emits
    # NOTHING (the -v table is text-only), while `system df --format json` emits one
    # row per Type -- {"Type":"Local Volumes","RawSize":<int>,"RawReclaimable":<int>,
    # "Size":"54.39GB",...}. RawSize is the exact byte count; "Size" is a rounded string.
    data, err = _run_json(["podman", "system", "df", "--format", "json"], timeout, run)
    if data is None:
        return 0, err
    rows = data if isinstance(data, list) else (data.get("Rows") if isinstance(data, dict) else [])
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        if "volume" in str(row.get("Type", "")).lower():
            raw = row.get("RawSize")
            if isinstance(raw, (int, float)):
                return int(raw), ""
            return _parse_size(row.get("Size", 0)), ""
    return 0, "podman system df reported no Local Volumes row"


def _build_cache(timeout: int, run) -> tuple[int, str]:
    data, err = _run_json(["podman", "system", "df", "--format", "json"], timeout, run)
    if data is None:
        return 0, err
    rows = data if isinstance(data, list) else (data.get("Rows") if isinstance(data, dict) else [])
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("Type", "")).lower()
        if "build" in kind or "cache" in kind:
            raw = row.get("RawSize")
            if isinstance(raw, (int, float)):
                return int(raw), ""
            return _parse_size(row.get("Size", 0)), ""
    return 0, ""


def _buildah_tmp(timeout: int, run) -> tuple[int, str]:
    """Aborted buildah working containers -- invisible to every podman-native
    accounting command (measured 2026-08-19). Count only: buildah does not
    report a per-container size cheaply, and a count is enough to page on."""
    data, err = _run_json(["buildah", "containers", "--format", "json"], timeout, run)
    if data is None:
        return 0, err
    return (len(data) if isinstance(data, list) else 0), ""


def _tree(path: str, depth: int, size: int, cls: str, refetchable: bool,
          reason: str) -> dict:
    return {
        "path": path, "depth": depth, "bytes": int(size), "files": 0, "dirs": 0,
        "newest_mtime": 0.0, "oldest_mtime": 0.0,
        "fingerprint": fingerprint(int(size), 0, 0.0),
        "cls": cls, "refetchable": refetchable, "confidence": 0.9,
        "reason": reason, "source": "collector", "git": False,
    }


def collect(*, node: str | None = None, timeout: int = _DEFAULT_TIMEOUT,
            run=subprocess.run) -> dict:
    """One snapshot rooted at `podman://engine`, or an empty-but-honest one
    if podman is absent. `run` is injectable (tests pass a fake) -- never
    the real `subprocess.run` in a unit test.
    """
    node = node or socket.gethostname()
    errors: list[str] = []
    if not podman_available():
        errors.append("podman: not on PATH")
        images_bytes = dangling_bytes = dangling_count = volumes_bytes = 0
        cache_bytes = buildah_count = 0
    else:
        images_bytes, dangling_bytes, dangling_count, e1 = _images(timeout, run)
        volumes_bytes, e2 = _volumes(timeout, run)
        cache_bytes, e3 = _build_cache(timeout, run)
        buildah_count, e4 = _buildah_tmp(timeout, run)
        errors.extend(e for e in (e1, e2, e3, e4) if e)

    building = build_in_progress(run=run)
    root = "podman://engine"
    aggregate = images_bytes + volumes_bytes + cache_bytes
    trees = [
        _tree(root, 0, aggregate, "container-store", False,
              "podman engine storage (images + volumes + build-cache aggregate)"),
        _tree(f"{root}/images", 1, images_bytes, "container-store", False,
              "podman images --format json"),
        _tree(f"{root}/dangling-images", 1, dangling_bytes, "container-store", True,
              f"{dangling_count} dangling image(s); safe to `podman image prune -f`"),
        _tree(f"{root}/volumes", 1, volumes_bytes, "service-state", False,
              "podman volumes -- NEVER auto-pruned (may hold live service state)"),
        _tree(f"{root}/build-cache", 1, cache_bytes, "build-temp", True,
              "podman system df build cache"),
    ]
    if buildah_count:
        trees.append(_tree(f"{root}/buildah-tmp", 1, 0, "build-temp", True,
                            f"{buildah_count} aborted buildah working container(s)"))

    return {
        "schema": SCHEMA_VERSION, "node": node, "root": root, "taken_at": _now_iso(),
        "max_depth": 1, "time_budget_s": float(timeout), "truncated": False,
        "trees": trees, "top_files": [], "errors": errors, "error_count": len(errors),
        "elapsed_s": 0.0, "classified": True,
        "classifier": {"kind": "collector", "collector": "podman"},
        "engine": {"build_in_progress": building},
    }
