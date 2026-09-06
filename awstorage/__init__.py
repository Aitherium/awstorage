"""awstorage -- every drive on every node, indexed, classified and diffed.

Scan a root, get a SNAPSHOT: every directory tree down to a bounded depth with
its bytes, file count and newest mtime, plus the largest files. Classify each
tree (cache / build-temp / model-weights / dataset / backup / repo / logs /
service-state / media / unknown) and mark whether it is RE-FETCHABLE. Store
snapshots in a catalog and DIFF them, so "what grew since last week" is a
query rather than a memory. Turn the classification into PROPOSALS under a
written policy, and APPLY only what the policy pre-approves or a human
approved -- dry-run by default, ledgered, and never outside a declared root.

    import awstorage
    from pathlib import Path

    snap = awstorage.scan(Path("E:/"), max_depth=3, time_budget_s=120)
    awstorage.classify_snapshot(snap)                # heuristics, offline
    cat = awstorage.Catalog(Path("inventory.db"))
    sid = cat.put_snapshot(snap)
    for row in awstorage.rank(snap)[:20]:
        print(row["bytes"], row["path"], row["cls"], row["refetchable"])
    props = awstorage.propose(snap, awstorage.default_policy())
    awstorage.apply(props[0], roots=[Path("E:/")], dry_run=True)

Three rules it exists to enforce:

**Measure before you delete.** A `du` answers one question once. A snapshot
answers the same question every week, and the diff between two is the
question you actually had ("what filled the disk?").

**Re-fetchable is a property, not a guess.** A tree is re-fetchable when a
known producer can recreate it (a package cache, a build output, a model
weight that lives on a mirror). The classifier records WHY it decided that,
and whether a heuristic or a model decided -- so a wrong call is auditable.

**Deleting is a policy, not a mood.** `apply` refuses anything outside the
declared roots, anything whose fingerprint changed since the scan, and any
class the policy does not pre-approve unless a human approved that proposal.
It writes a ledger row either way. A dry run is the default.

The package is stdlib-only and speaks to nothing. Fleet integration (a scanner
per node, a catalog behind an API, a GUI, an autonomous steward, model-backed
classification) lives in the platform that imports it -- awstorage works alone.
"""

from __future__ import annotations

from ._fs import SCHEMA_VERSION, ScanError, scan
from .catalog import Catalog
from .classify import (
    CLASSES,
    Classifier,
    HeuristicClassifier,
    LLMClassifier,
    classify_snapshot,
    classify_tree,
)
from .diff import diff_snapshots
from .graph import to_graph
from .policy import (
    ApplyRefused,
    Proposal,
    apply,
    default_policy,
    list_quarantine,
    propose,
    purge_quarantine,
    revert,
)
from .report import rank, summarize

__version__ = "0.1.0"

__all__ = [
    "SCHEMA_VERSION",
    "ScanError",
    "scan",
    "Catalog",
    "CLASSES",
    "Classifier",
    "HeuristicClassifier",
    "LLMClassifier",
    "classify_snapshot",
    "classify_tree",
    "diff_snapshots",
    "to_graph",
    "ApplyRefused",
    "Proposal",
    "apply",
    "default_policy",
    "list_quarantine",
    "propose",
    "purge_quarantine",
    "revert",
    "rank",
    "summarize",
    "__version__",
]
