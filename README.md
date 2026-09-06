# awstorage

**Every drive on every node, indexed, classified and diffed -- so you can see what you own before you delete it.**

```bash
pip install git+https://github.com/Aitherium/awstorage.git
awstorage scan E:/ --depth 3 --catalog inventory.db
awstorage inventory --catalog inventory.db
awstorage propose --catalog inventory.db --snapshot 1
awstorage apply   --catalog inventory.db --proposal 3 --root E:/        # dry run
awstorage apply   --catalog inventory.db --proposal 3 --root E:/ --yes  # quarantine it
awstorage revert  E:/.awstorage-quarantine/3-20260901T230000            # changed your mind
```

Stdlib only. Works alone, offline, on the box whose disk is full.

## What it does

1. **Scan** a root into a *snapshot*: every directory tree to a bounded depth with
   its bytes, file count and newest mtime, plus the largest files. Bounded by a time
   budget; a scan that runs out marks the snapshot `TRUNCATED` instead of printing a
   total that looks complete and is not.
2. **Classify** each tree: `package-cache`, `build-temp`, `model-weights`,
   `container-store`, `dataset`, `backup`, `repo`, `logs`, `service-state`, `media`,
   `vm-disk`, `unknown` -- and whether it is **re-fetchable**. Heuristics offline;
   plug any `complete(prompt) -> str` model callable into `LLMClassifier` and every
   verdict records whether a rule or a model made it, so a wrong call is auditable.
3. **Catalog** snapshots in SQLite and **diff** them: what appeared, vanished, grew
   and shrank since last time. "What filled the disk?" becomes a query.
4. **Propose** actions under a written policy. Rules pre-approve only re-fetchable
   classes past a size and an age; `service-state`, `dataset`, `vm-disk`, `backup` and
   `unknown` are never auto. Everything else is proposed for a human to approve.
5. **Apply** -- dry run by default. A delete is a **quarantine**: the tree is renamed
   onto the same volume under `<root>/.awstorage-quarantine/`, `revert` puts it back
   byte-for-byte, and only `quarantine --purge-older-than N --yes` reclaims the bytes.
   `apply` refuses anything outside the declared roots, anything that changed since the
   scan, and anything neither pre-approved nor approved. Every outcome is ledgered.

## Python

```python
import awstorage
from pathlib import Path

snap = awstorage.classify_snapshot(awstorage.scan(Path("E:/"), max_depth=3))
cat = awstorage.Catalog("inventory.db")
sid = cat.put_snapshot(snap)
for row in awstorage.rank(snap)[:10]:
    print(row["exclusive_bytes"], row["cls"], row["refetchable"], row["path"])
props = awstorage.propose(snap, awstorage.default_policy(), snapshot_id=sid)
awstorage.apply(props[0], roots=[Path("E:/")], dry_run=True)
```

## The three rules

- **Measure before you delete.** A `du` answers one question once.
- **Re-fetchable is a property, not a guess.** The classifier says why.
- **Deleting is a policy, not a mood.** Dry run, roots, fingerprints, quarantine, ledger.

## Composes with

- **awrecover** -- `backup_hook=lambda p: awrecover.snapshot(p, store, label)` turns
  `backup-then-delete` into a restorable snapshot first.
- **awdk / awnode / awsh** -- run the scanner where the disk is, post snapshots to a
  shared catalog, render proposals in a shell or a desktop panel.
- **awgraph** -- `awstorage graph` emits nodes and typed edges (`contains`,
  `duplicate_of`) any graph store can ingest.

`awstorage --self-test` proves the refusals still refuse and the quarantine still reverts.

Apache-2.0.
