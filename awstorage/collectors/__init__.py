"""Collectors -- non-filesystem storage sources, shaped like a scan.

A collector returns a complete awstorage snapshot dict (schema, node, root,
taken_at, trees, top_files, errors, elapsed_s, truncated) exactly like
`_fs.scan()` does, so a node runner can push one exactly like a directory
scan -- through the same `remote.push_snapshot`, into the same catalog.

Two rules every collector follows:

**A collector classifies itself.** Its trees already carry `cls`,
`refetchable`, `confidence`, `reason`, `source="collector"` and the snapshot
is marked `classified: True`, so Genesis's ingest path (which only classifies
a snapshot that has NOT already been classified) never re-runs the
path-segment heuristic over a synthetic path like `podman://engine/volumes`
and reclassifies it into `unknown` by accident.

**A collector never crashes the run that hosts it.** The tool it shells
(`podman`, `journalctl`) may be absent, unreachable, or return garbage; every
one of those is recorded in the snapshot's `errors` list with zero bytes for
the piece that failed -- the same way a scan records a PermissionError on one
directory and keeps walking the rest. A zero that hides a failure is worse
than an honest error string.
"""

from __future__ import annotations

from typing import Callable, Dict

from .journal import collect as collect_journal
from .podman import build_in_progress
from .podman import collect as collect_podman

COLLECTORS: Dict[str, Callable[..., dict]] = {
    "podman": collect_podman,
    "journal": collect_journal,
}

__all__ = ["COLLECTORS", "collect_podman", "collect_journal", "build_in_progress"]
