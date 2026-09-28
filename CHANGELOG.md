# Changelog

## 0.3.1 -- 2026-09-28

The live 3-hourly sweep (2026-09-28, 0.2.1) freed 35 GB in an emergency (C: 9.3 GB ->
44.6 GB free) and still exited 1: ONE Qt lockfile under %TEMP%, held open by a running
app, raised PermissionError during the emergency delete ("emergency delete incomplete:
1 error(s)"). A scheduled job that exits 1 on every in-use lockfile has a useless receipt.

### Fixed
- A file held open (PermissionError, Windows winerror 5/32/33) on ANY delete path --
  emergency delete, `action: delete`, quarantine purge -- is no longer a failure. The
  item is `skipped-busy` when nothing was removed, `partial-busy` when some was (freed
  bytes counted, the held rest stays for the next pass); exit code unaffected. A busy
  item is never counted as removed. Any OTHER OSError is still a failure (exit 1), also
  when it occurs alongside a busy file.

### Added
- Receipt `busy`: one row per busy item (`path`, `rule`, `action`, `outcome`,
  `bytes_freed`, `busy`, `first`). `skipped_busy` keeps its meaning (item untouched).
- `awstorage._fs.remove_tree_detail` -> `(bytes, errors, busy)` and `is_busy_error`;
  `remove_tree` is unchanged for its other callers (busy counts as an error there).
- Self-test check 9: a held file in an emergency delete is `partial-busy`, exit 0; a
  non-permission OSError still exits 1.

## 0.3.0 -- 2026-09-28

The per-file index and the manage plane in one CLI.

### Added
- **File index** (`awstorage files scan|find|dupes|tree|nodes|push`): one row per file in
  `files.db` (the catalog's sibling), FTS name search, directory rollups, duplicates by
  size -> partial hash -> sha256; incremental rescans with a per-row `seq` and
  tombstones; `files push` sends a DELTA since the fleet's acknowledged seq (409 -> one
  full resync). `awstorage.guards` is the one never/sensitive set; `awstorage whoami`
  names the node every verb speaks for (`awstorage.identity`).
- `awstorage manage revert|shares` (the node side of `awstorage.manage`).
- `awstorage node-run --orders-only`: fetch, apply and report approved orders without
  scanning or pushing (for a caller that already scanned -- `awstorage-scan.sh`).

### Changed
- `awstorage.manage` imports `awstorage.guards`; its embedded copy of the guard lists is
  gone. The catalog accepts the manage statuses `executing`, `drifted`, `refused`,
  `failed`.

## 0.2.1 -- 2026-09-28

The first real unattended run (2026-09-28) exited 0, saw 8541 items, removed 1130 and
harvested 106 MB -- and freed **0 bytes**: every removal was a quarantine onto the same
drive, back only after `purge_after` (24 h). The same day C: had hit 100% and corrupted a
WSL root fs. And one 106 GB dead session tree spent the whole 15 min budget being
measured, so it was never acted on.

### Added
- **Emergency delete.** A rule key `emergency_delete` (default `true` for the
  `agent-scratch` and `temp-toplevel` presets, `false` otherwise; allowed only for the
  regenerable classes `build-temp` / `package-cache`, and only with harvest on). Under
  `--emergency-free-gb N`, when the item's drive has < N GB free, an eligible item of
  such a quarantine rule is DELETED instead of quarantined -- only after its harvest
  verified (size + sha256 of every copy). Audited/ledgered as `deleted-emergency`. Freed
  bytes are credited back to the drive, so the pass stops emergency-deleting once the
  drive is above the floor again.
- Receipt: `emergency_deleted`, `bytes_emergency_deleted`, `bytes_purged`, and a note
  explaining a `bytes_freed` of 0 when everything was quarantined.
- **Per-item measure cap** `--measure-cap-s` (default 120; `measure_cap_s=` in the API,
  None = unbounded). Past it the item is judged by its top-level mtime plus a bounded
  sample (first 2000 files in scandir order, `sweep.sample_age`): all older than the idle
  cutoff -> eligible with size `unknown (capped)`; any fresh -> live, skipped. A walk that
  saw a fresh file is never capped into eligibility. Harvest still runs (candidates from
  the walk + sample); the manifest says `measure: capped`. Receipt `capped` lists each.
- Self-test: emergency delete fires only for a flagged rule under the floor and never
  without a verified harvest; the measure cap judges both ways.

### Changed
- **Purge runs first in every rule's pass**, before its items: a pass the time budget
  cuts no longer skips the only step that frees quarantined bytes.

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
