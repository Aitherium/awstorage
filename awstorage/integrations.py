"""Optional couplings to the rest of the aw family. Every one is GUARDED.

awstorage is stdlib-only because the box that most needs it is the one whose disk
is full, where pip cannot fetch anything; and a brick's ``adopt:`` may not need a
sibling (EC003). So nothing here imports a sibling at module load, and each
function answers ``{"available": False, "reason": ...}`` honestly when its package
(or its key, or its data) is absent -- never an empty success that reads as done.

- **awdit** -- :func:`audit_append` / :func:`audit_verify`: every sweep decision
  lands in a hash-chained, truncation-evident log. A deletion with no audit record
  is the exact failure awdit exists for, so ``sweep(require_audit=True)`` refuses to
  remove anything when this answers unavailable.
- **awseal** -- :func:`seal_dir` signs each harvested item directory after its
  copies verified; :func:`verify_shelf` reports sealed / tampered / unsealed.
- **awshare** -- :func:`publish_day` bundles one day's harvest (content-addressed,
  verified on fetch with ``awshare.fetch`` / ``awshare.fetch_verified``).
- **awm** -- :func:`land_to_awm` lands ONE memory per harvested item through
  ``MemoryStore.remember`` only -- never SQL, never a migration.
- **awrecover** -- :func:`snapshot_item` for a rule with ``snapshot: true``; when it
  answers unavailable the sweep KEEPS the item (a rule that asked for a snapshot
  must not silently lose it).
- **awdk** -- consumes :func:`awstorage.sweep` (returns the receipt dict) and the
  live-ids contract (``AWSTORAGE_LIVE_IDS`` / ``--live-ids``); nothing is imported
  from it here.
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


def _mod(name: str):
    """Import a sibling lazily. Returns (module, None) or (None, reason)."""
    try:
        return importlib.import_module(name), None
    except ImportError as exc:
        return None, f"{name} is not installed ({exc.__class__.__name__}); " \
                     f"pip install awstorage[harvest]"
    except Exception as exc:  # noqa: BLE001 -- a broken sibling must not take the sweep down
        return None, f"{name} failed to import: {type(exc).__name__}: {exc}"


def _unavailable(reason: str, **extra: Any) -> Dict[str, Any]:
    return {"available": False, "ok": False, "reason": reason, **extra}


# ── awdit ─────────────────────────────────────────────────────────────────────

def default_audit_log() -> Path:
    return Path.home() / ".aither" / "awstorage" / "audit.log"


def audit_available() -> Dict[str, Any]:
    m, why = _mod("awdit")
    if m is None:
        return _unavailable(why)
    if not callable(getattr(m, "append", None)):
        return _unavailable("awdit has no append(); incompatible version")
    return {"available": True, "ok": True, "reason": None}


class _ChainCache:
    """Remembers (head, count, size) of logs this process appended to.

    awdit.append re-reads the WHOLE log to find its head on every call: 2000 appends
    took 19.6 s (measured 2026-09-27), and a first sweep over ~19k stale Temp entries
    writes ~40k records -- quadratic, hours. So after one real head() the chain state
    is cached, and each record is written with awdit's OWN `digest_record` and anchor
    path: byte-for-byte the format awdit.append writes, proven by awdit.verify in the
    tests. If the file size is not what we last left it at (another writer), the cache
    is dropped and head() is read again -- we never chain onto a head we did not see.
    """

    def __init__(self) -> None:
        self.state: Dict[str, tuple] = {}


_CHAIN = _ChainCache()


def _fast_append(m, path: str, event: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    log_mod = getattr(m, "log", None)
    digest_record = getattr(log_mod, "digest_record", None)
    anchor_path = getattr(log_mod, "anchor_path", None)
    if digest_record is None or anchor_path is None:
        return None  # an awdit without the primitives: use its append()
    import time as _time

    try:
        size = os.path.getsize(path)
    except OSError:
        size = -1
    cached = _CHAIN.state.get(path)
    if cached is None or cached[2] != size:
        prev, count = m.head(path)
    else:
        prev, count = cached[0], cached[1]
    body = {"ts": _time.time(), "event": event, "prev": prev, "data": fields}
    record = dict(body)
    record["hash"] = digest_record(prev, body)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    # Same order as awdit.append: the record lands (fsync'd) BEFORE the anchor moves.
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    anchor_path(path).write_text(
        json.dumps({"head": record["hash"], "count": count + 1}, sort_keys=True),
        encoding="utf-8")
    _CHAIN.state[path] = (record["hash"], count + 1, os.path.getsize(path))
    return record


def audit_append(log: str | os.PathLike, event: str, **fields: Any) -> Dict[str, Any]:
    """Append one decision record. ok=False (with the reason) on ANY failure."""
    m, why = _mod("awdit")
    if m is None:
        return _unavailable(why)
    path = os.path.abspath(os.path.expanduser(str(log)))
    try:
        rec = _fast_append(m, path, f"awstorage.{event}", fields)
        if rec is None:
            rec = m.append(path, f"awstorage.{event}", **fields)
    except Exception as exc:  # noqa: BLE001 -- the caller decides whether this stops a removal
        _CHAIN.state.pop(path, None)
        return {"available": True, "ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    return {"available": True, "ok": True, "hash": (rec or {}).get("hash")}


def audit_verify(log: str | os.PathLike) -> Dict[str, Any]:
    """awdit.verify over the sweep's log: chain, order, and truncation vs the anchor."""
    m, why = _mod("awdit")
    if m is None:
        return _unavailable(why)
    p = os.path.expanduser(str(log))
    if not os.path.isfile(p):
        # No log is "could not judge", never "verified": nothing was checked.
        return _unavailable(f"no audit log at {p}")
    r = m.verify(p)
    return {"available": True, "ok": bool(r), "count": getattr(r, "count", None),
            "head": getattr(r, "head", None), "problems": list(getattr(r, "problems", []))}


# ── awseal ────────────────────────────────────────────────────────────────────

def seal_dir(path: Path, key: str | os.PathLike | None = None) -> Dict[str, Any]:
    """Sign a harvested item dir; the seal (awseal.json) sits inside it.

    Without an explicit key, awseal's own default location is used; no key there is
    an honest "unavailable", because awseal deliberately has no default key.
    """
    m, why = _mod("awseal")
    if m is None:
        return _unavailable(why)
    key_path = Path(os.path.expanduser(str(key))) if key else None
    try:
        s = m.sign(Path(path), key_path=key_path, subject=Path(path).name,
                   meta={"producer": "awstorage sweep"})
        out = m.write(s, Path(path))
    except Exception as exc:  # noqa: BLE001 -- awseal raises SealError for no key / no files
        return {"available": True, "ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    return {"available": True, "ok": True, "seal": str(out).replace("\\", "/"),
            "tree_digest": s.tree_digest, "public_key": s.public_key}


def _seal_name() -> str:
    m, _ = _mod("awseal")
    return getattr(m, "SEAL_NAME", "awseal.json") if m else "awseal.json"


def _is_item_manifest(p: Path) -> bool:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(d, dict) and "item" in d and "harvested" in d and "rule" in d


def _item_dirs(shelf: Path) -> List[Path]:
    """Dirs holding an awstorage item manifest; never descends into one (a harvested
    file may itself be called manifest.json somewhere below)."""
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(shelf):
        if "manifest.json" in filenames and _is_item_manifest(Path(dirpath) / "manifest.json"):
            out.append(Path(dirpath))
            dirnames[:] = []
        else:
            dirnames.sort()
    return sorted(out)


def verify_shelf(shelf: Path, expect_key: Optional[str] = None) -> Dict[str, Any]:
    """Verify every harvested item dir (a dir holding manifest.json) under `shelf`."""
    m, why = _mod("awseal")
    if m is None:
        return _unavailable(why)
    shelf = Path(os.path.expanduser(str(shelf)))
    if not shelf.is_dir():
        return _unavailable(f"{shelf} is not a directory")
    items: List[Dict[str, Any]] = []
    seal_name = _seal_name()
    for d in _item_dirs(shelf):
        row: Dict[str, Any] = {"dir": str(d).replace("\\", "/")}
        if not (d / seal_name).is_file():
            row["status"] = "missing"
        else:
            try:
                r = m.verify(d, expect_key=expect_key)
                row["status"] = "sealed" if r.get("ok") else "tampered"
                if not r.get("ok"):
                    row["diff"] = r.get("diff")
                    row["signature_ok"] = r.get("signature_ok")
            except Exception as exc:  # noqa: BLE001 -- an unreadable seal is not a pass
                row["status"] = "tampered"
                row["reason"] = f"{type(exc).__name__}: {exc}"
        items.append(row)
    counts = {k: sum(1 for i in items if i["status"] == k)
              for k in ("sealed", "tampered", "missing")}
    return {"available": True, "ok": bool(items) and counts["sealed"] == len(items),
            "items": items, "counts": counts,
            "reason": None if items else f"no harvested items under {shelf}"}


# ── awshare ───────────────────────────────────────────────────────────────────

def publish_day(day_dir: Path, to: Path, seal_key: str | os.PathLike | None = None
                ) -> Dict[str, Any]:
    """Bundle one day's harvest (<shelf>/<rule>/<date>) into `to` with awshare.

    Fetch side: ``awshare.fetch(<to>/<name>.awshare.json, dest, expect_key=...)`` or
    ``awshare.fetch_verified(archive, dest, manifest.digest)`` -- both verify the
    digest before a byte lands.
    """
    m, why = _mod("awshare")
    if m is None:
        return _unavailable(why, day=str(day_dir))
    day_dir = Path(day_dir)
    name = f"awstorage-harvest-{day_dir.parent.name}-{day_dir.name}"
    try:
        man = m.publish(day_dir, Path(to), name=name, seal=bool(seal_key),
                        key_path=Path(os.path.expanduser(str(seal_key))) if seal_key else None,
                        meta={"producer": "awstorage sweep", "day": day_dir.name,
                              "rule": day_dir.parent.name})
    except Exception as exc:  # noqa: BLE001 -- reported, the sweep result stands
        return {"available": True, "ok": False, "day": str(day_dir),
                "reason": f"{type(exc).__name__}: {exc}"}
    suffix = getattr(m, "MANIFEST_SUFFIX", ".awshare.json")
    return {"available": True, "ok": True, "day": str(day_dir), "name": man.name,
            "digest": man.digest, "size": man.size,
            "manifest": str(Path(to) / f"{man.name}{suffix}").replace("\\", "/")}


# ── awm ───────────────────────────────────────────────────────────────────────

def _awm_db_default() -> Path:
    try:
        from awm.cli import DEFAULT_DB  # type: ignore[import-not-found]
        return Path(DEFAULT_DB)
    except Exception:  # noqa: BLE001 -- the fallback is awm's documented location
        return Path.home() / ".aither" / "awm" / "memory.db"


def check_awm_scope(scope: str) -> None:
    """Raise SweepConfigError for a malformed scope when awm can judge it."""
    m, _why = _mod("awm")
    if m is None:
        return  # land_to_awm reports "unavailable" per item; nothing to judge here
    try:
        m.Scope.parse(scope)
    except Exception as exc:  # noqa: BLE001
        from .sweep import SweepConfigError
        raise SweepConfigError(f"--land-to-awm scope {scope!r}: {exc}") from exc


def land_to_awm(scope: str, manifest: Dict[str, Any], shelf_dir: str,
                db: str | os.PathLike | None = None) -> Dict[str, Any]:
    """ONE memory per harvested item, via MemoryStore.remember at exactly `scope`.

    The file is opened through awm's public class only. If that class grows an
    `auto_migrate` switch it is passed False; an older-schema file makes awm refuse
    (it raises rather than migrating), which is reported as a compat problem.
    """
    m, why = _mod("awm")
    if m is None:
        return _unavailable(why)
    path = Path(os.path.expanduser(str(db))) if db else _awm_db_default()
    try:
        sc = m.Scope.parse(scope)
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "ok": False, "reason": f"bad scope: {exc}"}
    kwargs: Dict[str, Any] = {}
    try:
        if "auto_migrate" in inspect.signature(m.MemoryStore).parameters:
            kwargs["auto_migrate"] = False
    except (TypeError, ValueError):
        pass
    item = str(manifest.get("item", ""))
    name = os.path.basename(item.rstrip("/\\")) or "item"
    key = f"storage.harvest.{name}"
    files = [h["path"] for h in manifest.get("harvested", [])]
    withheld = sum(1 for s in manifest.get("skipped", [])
                   if s.get("reason") == "withheld: secret-pattern")
    shown = ", ".join(files[:12]) + (f" (+{len(files) - 12} more)" if len(files) > 12 else "")
    value = (f"awstorage sweep ({manifest.get('rule')}) harvested {len(files)} file(s) from "
             f"{item} ({manifest.get('total_bytes', 0)} bytes, {manifest.get('file_count', 0)} "
             f"files) before removal. Shelf: {shelf_dir}. Withheld (secret pattern): "
             f"{withheld}. Files: {shown}")
    try:
        store = m.MemoryStore(path, **kwargs)
    except Exception as exc:  # noqa: BLE001 -- schema refusal is awm protecting itself
        return {"available": True, "ok": False,
                "reason": f"awm refused {path} (compat: {type(exc).__name__}: {exc})"}
    try:
        store.remember(sc, key, value, kind="fact",
                       meta={"source": "awstorage", "shelf": shelf_dir, "item": item,
                             "files": len(files)})
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        store.close()
    return {"available": True, "ok": True, "key": key, "scope": str(sc), "db": str(path)}


# ── awrecover ─────────────────────────────────────────────────────────────────

def snapshot_item(path: Path, store: Path, label: str) -> Dict[str, Any]:
    """awrecover snapshot of a directory item before its removal."""
    m, why = _mod("awrecover")
    if m is None:
        return _unavailable(f"awrecover unavailable: {why}")
    if not Path(path).is_dir():
        return {"available": True, "ok": False,
                "reason": f"{path} is not a directory; awrecover snapshots directories"}
    try:
        snap = m.snapshot(Path(path), Path(store), label,
                          meta={"producer": "awstorage sweep", "origin": str(path)})
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "ok": False, "reason": f"{type(exc).__name__}: {exc}"}
    return {"available": True, "ok": True, "label": label,
            "digest": getattr(snap, "digest", "")}
