"""Path guards shared by the index (awstorage.files) and the manage plane.

Two sets, and they mean different things:

* **sensitive** -- credentials and key material. Indexed (a disk inventory that
  hides files is a disk inventory that lies about bytes) but FLAGGED: redacted for
  any non-platform reader, refused for share and for content ingest.
* **never** -- paths no automated action may touch: the storage-topology planes
  that hold live state or source (data / source / backups, plus the constitution
  roots), anything whose path contains a live-state marker (Library data,
  postgres, WAL, git objects, secrets, lockbox, VM disks), the OS's own trees and
  node_modules. Indexed too; never managed, shared or ingested.

Stdlib only. The topology file is YAML; when pyyaml is absent the caller passes the
already-parsed dict (or nothing, and the path_contains + OS lists still apply).
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any, Iterable

SENSITIVE_DIRS = frozenset({".ssh", ".gnupg", ".aither", ".aws", ".kube", ".docker"})
SENSITIVE_GLOBS = (".env*", "id_rsa*", "id_ed25519*", "*.pem", "*.key", "*.pfx", "*.p12",
                   "*.kdbx", "*credentials*")

#: Case-insensitive substrings of a normalized (forward-slash) path.
NEVER_PATH_CONTAINS = ("/library/data/", "postgres", "pg_wal", "/.git/objects",
                       "secrets", "lockbox", ".vhdx")
NEVER_DIR_NAMES = frozenset({"node_modules"})
#: Topology planes whose canonical roots are never managed.
NEVER_PLANES = ("data", "source", "backups")
#: The constitution keys (check_storage_inventory_contract SIC004 names the same).
CONSTITUTION_KEYS = (
    ("planes", "source", "canonical", "deploy_root"),
    ("planes", "data", "canonical", "library"),
)


def _os_roots() -> list[str]:
    out = ["/usr", "/nix/store"]
    for env, default in (("SystemRoot", "C:/Windows"), ("ProgramFiles", "C:/Program Files"),
                         ("ProgramFiles(x86)", "C:/Program Files (x86)"),
                         ("ProgramData", "C:/ProgramData")):
        out.append(os.environ.get(env) or default)
    return [norm(p) for p in out]


def norm(p: str | os.PathLike) -> str:
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s.endswith("/") and not re.fullmatch(r"[A-Za-z]:/", s):
        s = s.rstrip("/")
    return s


def _parts(path: str) -> list[str]:
    return [x for x in norm(path).split("/") if x]


def is_sensitive(path: str) -> bool:
    """A credential-shaped file or anything under a credential directory."""
    parts = _parts(path)
    if not parts:
        return False
    lowered = [x.lower() for x in parts]
    if any(x in SENSITIVE_DIRS for x in lowered[:-1]) or lowered[-1] in SENSITIVE_DIRS:
        return True
    return any(fnmatch.fnmatchcase(lowered[-1], g) for g in SENSITIVE_GLOBS)


def never_roots_from_topology(topology: dict | None) -> list[str]:
    """Canonical filesystem roots of the never planes (+ constitution keys)."""
    if not isinstance(topology, dict):
        return []
    out: list[str] = []
    planes = topology.get("planes") or {}
    for plane in NEVER_PLANES:
        canon = ((planes.get(plane) or {}).get("canonical") or {})
        if isinstance(canon, dict):
            out += [v for v in canon.values() if isinstance(v, str)]
    for keys in CONSTITUTION_KEYS:
        node: Any = topology
        for k in keys:
            node = node.get(k) if isinstance(node, dict) else None
        if isinstance(node, str):
            out.append(node)
    # Only real filesystem paths: "aither://cold" and "Debian:/var/..." are not.
    return sorted({norm(v) for v in out
                   if v and "://" not in v and not re.match(r"^[A-Za-z]{2,}:", v)})


def load_topology(path: str | os.PathLike | None) -> dict | None:
    """Parse storage-topology.yaml when pyyaml is importable; None otherwise."""
    if not path or not Path(path).is_file():
        return None
    try:
        import yaml  # type: ignore  # optional extra
    except ImportError:
        return None
    try:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 -- an unreadable topology adds no roots
        return None


class Guards:
    """The never set, resolved once. `extra_roots` adds site-specific never roots."""

    def __init__(self, topology: dict | None = None,
                 extra_roots: Iterable[str] = ()) -> None:
        roots = set(_os_roots()) | set(never_roots_from_topology(topology))
        roots |= {norm(r) for r in extra_roots if r}
        self.never_roots = sorted(roots)
        self._roots_ci = [r.lower() for r in self.never_roots]

    def is_never(self, path: str) -> bool:
        p = norm(path)
        pl = p.lower()
        if any(pl == r or pl.startswith(r if r.endswith("/") else r + "/")
               for r in self._roots_ci):
            return True
        if any(m in pl + "/" for m in NEVER_PATH_CONTAINS):
            return True
        return any(x.lower() in NEVER_DIR_NAMES for x in _parts(p)[:-1])

    def is_never_dir(self, path: str) -> bool:
        """For a walker: a directory the --all-volumes walk must not descend into."""
        p = norm(path).lower()
        return any(p == r or p.startswith(r if r.endswith("/") else r + "/")
                   for r in self._roots_ci)

    def refusal(self, path: str) -> str | None:
        """Why a manage/share/ingest action must refuse this path, or None."""
        if is_sensitive(path):
            return "sensitive path (credential or key material)"
        if self.is_never(path):
            return "never-set path (live state, source, OS tree or node_modules)"
        return None


def redact(path: str) -> str:
    """The path with its basename replaced -- what a non-platform reader sees for a
    sensitive row."""
    p = norm(path)
    i = p.rfind("/")
    return (p[:i + 1] if i >= 0 else "") + "[redacted]"
