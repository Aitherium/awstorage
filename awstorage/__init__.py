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

**Sweeping is harvest-first.** `sweep()` runs named retention rules unattended:
it skips live items, copies the small text that outlives a session to a shelf
(verified, secrets withheld) BEFORE removing anything, never follows a link, and
writes a receipt on every exit path.

**Agents suggest; awstorage decides.** `suggest()` lets any agent propose removing
a path. It validates (guards, git clean + pushed, live window, evidence), then
either auto-approves a regenerable quarantine from a trusted agent or files it for
a decision card; `apply_suggestions()` re-verifies before acting, and every outcome
feeds the agent's trust score. The auto lane needs a VERIFIED agent identity
(`set_identity_verifier`); a card approval needs a SIGNED answer receipt
(`awstorage.attest`, public key in the file named by `$AWSTORAGE_ATTEST_PUBKEY_FILE`, awseal to verify).
`watch_once()` keeps drives above their floors cheaply; `place()` refuses a move that would push a drive under its floor.

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
from .guards import Guards, is_sensitive
from .identity import list_volumes, whoami
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
from .space import parse_floors, place, prune_shelf, watch_once
from .suggest import (
    apply_suggestions,
    resolve_suggestion,
    revert_suggestion,
    set_archive_hook,
    set_card_hook,
    set_card_reader,
    set_identity_verifier,
    suggest,
    suggestions,
    trust,
)
from .sweep import LIVE_IDS_ENV, SweepConfigError, presets, sweep

__version__ = "0.5.1"

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
    "Guards",
    "is_sensitive",
    "list_volumes",
    "whoami",
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
    "sweep",
    "presets",
    "SweepConfigError",
    "LIVE_IDS_ENV",
    "suggest",
    "suggestions",
    "resolve_suggestion",
    "revert_suggestion",
    "apply_suggestions",
    "trust",
    "set_card_hook",
    "set_card_reader",
    "set_archive_hook",
    "set_identity_verifier",
    "watch_once",
    "place",
    "parse_floors",
    "prune_shelf",
    "__version__",
]
