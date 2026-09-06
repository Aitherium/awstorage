"""journal.py -- systemd journal size as a snapshot (root `journal://engine`).

`journalctl --disk-usage` prints one line -- "Archived and active journals
take up N.NM in the file system." -- and this collector parses that number
and nothing else. Absent on a non-systemd host (Windows, macOS, a minimal
container): recorded as an error, zero bytes, never guessed.

Classified `logs`, matching `classify.CLASSES`; `refetchable=False` (a
journal is evidence, the same conservative call the heuristic classifier
makes for any `logs?`/`journal` path). The fleet policy's
`reclaim.journal_vacuum` class decides whether to `journalctl
--vacuum-size=<cap>` -- this collector only measures, it never vacuums.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone

from .._fs import SCHEMA_VERSION, fingerprint

_SIZE_RE = re.compile(r"([\d.]+)\s*([KMGT]?)i?B?", re.IGNORECASE)
_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_DEFAULT_TIMEOUT = 15


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def journalctl_available() -> bool:
    return shutil.which("journalctl") is not None


def _parse_disk_usage(text: str) -> int:
    """'Archived and active journals take up 8.0M in the file system.' -> bytes.
    No match -> 0 (never guessed)."""
    m = _SIZE_RE.search(text or "")
    if not m:
        return 0
    return int(float(m.group(1)) * _UNITS.get(m.group(2).upper(), 1))


def collect(*, node: str | None = None, timeout: int = _DEFAULT_TIMEOUT,
            run=subprocess.run) -> dict:
    """One snapshot rooted at `journal://engine`. `run` is injectable (tests
    pass a fake) -- never the real `subprocess.run` in a unit test."""
    node = node or socket.gethostname()
    errors: list[str] = []
    size_bytes = 0
    if not journalctl_available():
        errors.append("journalctl: not on PATH")
    else:
        try:
            p = run(["journalctl", "--disk-usage"], capture_output=True,
                     text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"journalctl --disk-usage: {type(exc).__name__}: {exc}")
        else:
            if p.returncode != 0:
                detail = (p.stderr or p.stdout or "").strip()[:200]
                errors.append(f"journalctl --disk-usage: exit {p.returncode}: {detail}")
            else:
                size_bytes = _parse_disk_usage((p.stdout or "") + (p.stderr or ""))

    root = "journal://engine"
    tree = {
        "path": root, "depth": 0, "bytes": size_bytes, "files": 0, "dirs": 0,
        "newest_mtime": 0.0, "oldest_mtime": 0.0,
        "fingerprint": fingerprint(size_bytes, 0, 0.0),
        "cls": "logs", "refetchable": False, "confidence": 0.85,
        "reason": "journalctl --disk-usage", "source": "collector", "git": False,
    }
    return {
        "schema": SCHEMA_VERSION, "node": node, "root": root, "taken_at": _now_iso(),
        "max_depth": 0, "time_budget_s": float(timeout), "truncated": False,
        "trees": [tree], "top_files": [], "errors": errors, "error_count": len(errors),
        "elapsed_s": 0.0, "classified": True,
        "classifier": {"kind": "collector", "collector": "journal"},
    }
