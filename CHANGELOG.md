# Changelog

## 0.2.0 -- 2026-09-27

The unattended half. On 2026-09-27 drive C: reached 122 MB free and corrupted a WSL
root fs mid-boot: 173 GB of agent session scratchpads under
`%LOCALAPPDATA%\Temp\claude\` and ~19k stale Temp entries that nothing reaped.

### Added
- `awstorage sweep` / `awstorage.sweep()`: retention rules as policy data (`retention`
  list; `--policy` JSON), one glob match = one item, age = newest file inside the item.
  Presets `agent-scratch` (idle 12h) and `temp-toplevel` (idle 3d), opt-in by name only.
- Harvest before removal: include globs, per-file and per-item caps, binary sniff,
  size + sha256 verification of every copy, `manifest.json` per item; credential-shaped
  files withheld (named, never copied). `--harvest-offdrive`.
- Live guard (`live_guard.window`, `AWSTORAGE_LIVE_IDS`, `--live-ids`), busy items
  (a rename refused by a held handle) skipped, not failed.
- `--emergency-free-gb N`: halve `max_idle` / `purge_after` while a drive is under N GB.
- Receipt JSON written on every exit path; exit 0 / 1 (item failed, kept) / 2 (could not
  judge). Ledger rows in the catalog for every decision.
- Optional couplings in `awstorage.integrations` (extra `awstorage[harvest]`): awdit audit
  log + `awstorage audit verify` + `--require-audit`; awseal-sealed shelf +
  `awstorage harvest verify`; awshare `awstorage harvest publish` / `--publish-to`;
  awm `--land-to-awm`; awrecover `snapshot: true` rules.
- `--time-budget` (default 3000 s): the pass stops cleanly, receipt `truncated: true`;
  a fresh item's measurement stops at its first too-new file. The first real dry run
  over this box's Temp tree overran 15 minutes without either.
- Audit appends cache the chain head (awdit's own digest + anchor format): awdit.append
  re-reads the whole log per call, 2000 appends measured 19.6 s -- quadratic.
- `--harvest-to strata:<tier>`: ship verified harvests to AitherStrata over verified
  TLS (stdlib), read each object's stat back (size + sha256) before removal; an
  unavailable target removes nothing and exits 2.
- `resume_first` in the receipt: an item the time budget cut is measured first on
  the next pass.
- `python -m awstorage` (`__main__.py`); `--self-test` now shows each sweep guard firing.

### Changed
- Removal never follows a link: `_rmtree`, quarantine purge, `revert` and the fingerprint
  walk use `_fs.remove_tree` / `walk_no_follow`, which treat Windows junctions (invisible
  to `is_symlink()` before 3.12) as links. `scan` no longer counts a junction target's
  bytes.
- A quarantine move falls back to copy+delete ONLY on a cross-device rename, and refuses
  that fallback for a tree holding a link. Previously any rename error (e.g. a file held
  open on Windows) fell back to copy-then-delete.

## 0.1.0

First release: scan, classify, catalog, diff, propose, apply (quarantine), revert, purge,
graph, push, node-run.
