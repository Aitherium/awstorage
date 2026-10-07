# Changelog

## 0.5.3 -- 2026-10-07

Windows file IDs survive the delta push. 0.5.2 folded unsigned 64-bit NTFS/ReFS
`st_dev`/`st_ino` into SQLite's signed range (two's-complement, so hard-link
identity is exact), but the push validator still accepted only non-negative
ints, so every row with a folded id was rejected on ingest. `dev`/`ino` now
accept the full signed 64-bit range; `nlink` stays non-negative. 0.5.2 also
made receipt mtime checks tolerate coarse filesystem timestamps in tests.

## 0.5.1 -- 2026-09-29

The 0.4.1 security work, released on top of 0.5.0 (relocate). Relocate cards
are approved through the same signed receipt (platform
`awstorage_card_consumer.relocate_card_decision`), never the card's
`answered_by` label.

A security review of the first platform wiring found that "the owner approved this"
rested on fields an agent on the owner's host can write: a boolean `answer_attested`,
an `answered_by` stamped from any bearer Identity accepts (the agent session-bearer
included), and a caller-chosen `answered_via`. And a `suggested_by` the brick trusted
for the auto lane is whatever the in-process caller typed.

### Security
- **Card approvals need a SIGNED receipt** (`awstorage.attest`, new). Ed25519 over
  `{card_id, choice, answered_by, answered_at, nonce, surface, auth_method, auth_time,
  facts_sha256}` with the platform's vault-held key, verified with a provisioned public
  key (`AWSTORAGE_ATTEST_PUBKEY` / `AWSTORAGE_ATTEST_PUBKEY_FILE`) through awseal
  (imported guarded; absent -> refuse). Checked: signature, card id, choice, facts
  digest, interactive sign-in (`webauthn` / `totp_2fa`) at most 15 min old, owner
  principal, card window, nonce unused (table `attest_nonces`). `manage.card_decision`
  / `verify_card` gain `catalog=` (nonce store), `pubkey=`; `apply_manage` and
  `resolve_suggestion` pass their catalog.
- `manage.STORE_ATTESTS_ANSWERER` is now the master switch and ships **True**; it never
  makes a card without a valid receipt count. The `HUMAN_VIAS` surface allowlist is no
  longer consulted (`via` is a label; the signed `surface`/`auth_method` replace it);
  `NON_HUMAN_VIAS` labels (`agent`, `deadline`, ...) are still refused.
- **The auto lane needs a verified identity**: `set_identity_verifier(fn)` +
  `suggest(..., identity_proof=)`; otherwise `identity: unverified` -> card lane.
  Owner opt-in `AWSTORAGE_TRUST_INPROCESS=1` (`inprocess-trusted`, re-checked at
  apply). Catalog column `suggestions.identity` (additive; 0.4.0 rows read
  `unverified`, so their auto approvals are withdrawn at apply).
- **Path live ids**: a live id containing a path separator keeps that dir, its subtree
  and its ancestors (`sweep.live_path_hit`), so a runtime can register a generic
  `scratchpad`/`tmp` dir by full path instead of blocking every dir of that name.

### Security (second review)
- **Apply trusts no status** (c1). `apply_suggestions` re-verifies an `approved` row:
  the card recorded at resolve (new columns `card_snapshot`, `receipt_digest`; or the
  live card via the new `set_card_reader(fn)`) must pass `manage.verify_card` again,
  be the row's card, carry the receipt digest recorded at resolve and bind the row's
  content. An `auto-approved` row re-verifies its identity with the installed verifier
  against the proof stored at suggest time (new column `identity_proof`; a proof must
  be JSON-serialisable) and re-checks its evidence. Otherwise the row becomes
  `refused` (receipt `refused` count, exit 1) -- a status flipped in SQLite deletes
  nothing. Self-test check 18.
- **Cards bind their content** (c2). New fact `content_sha256: <hex>`
  (`manage.content_digest`, `suggest.suggestion_content_digest`) over the canonical
  proposal (members' path + sha256 + bytes, params, node, action, path ...);
  `manage._authorize` and suggestion resolve/apply recompute and compare; a card
  without it is refused (re-raise cards raised by earlier 0.4.1 builds).
- **Receipts expire** (c4): refused when older than 7 days
  (`AWSTORAGE_ATTEST_MAX_RECEIPT_AGE_S`, clamped 1 h..30 d), always by the real clock;
  `verify_receipt(now=)` is now ignored.
- **The verifier key file must be out of agents' reach** (c5):
  `AWSTORAGE_ATTEST_PUBKEY_FILE` under `~/.aither`, or world-writable (POSIX file,
  directory, or a non-sticky ancestor), is refused (`attest.pubkey_file_refusal`).
- Documented the threat model: approvals are a governance gate + audit trail, not a
  boundary against a hostile agent running as the owner's OS user.

### Security (third review)
- **The verifier key comes only from a FILE.** A raw 64-hex key in
  `AWSTORAGE_ATTEST_PUBKEY` skipped the location check (an env var is set by whoever
  starts the verifier); it is now refused with a message naming the fix. Both
  `AWSTORAGE_ATTEST_PUBKEY_FILE` and `AWSTORAGE_ATTEST_PUBKEY` take a PATH and both get
  the ~/.aither / world-writable check. Migration: write the key to a root/owner-owned
  file and point `AWSTORAGE_ATTEST_PUBKEY_FILE` at it.
- **One proposal, one content per card.** `manage.card_decision` refuses a card with
  more than one `proposal_id` fact and `manage.require_content` one with more than one
  `content_sha256` fact (keys matched case- and space-insensitively), so one signed
  answer cannot approve two proposals or two contents.

### Added
- Extra `attest = ["awseal>=0.1.1"]` (also in `dev`); CI installs `.[attest]`.
- Self-test checks 15-17: an unverified identity never auto-approves; a card with no
  receipt or a forged one is refused; a path live id keeps a generic dir.

## 0.5.0 -- 2026-09-28

Measured 2026-09-28: 88 GB moved D: -> C: by hand (robocopy /MOVE + a junction) with
nothing checking the destination; C: fell from 124 GB to 18 GB free, the day after C:
at 0 bytes corrupted the fleet root fs. A move is now PLANNED against every drive's
floor before a byte moves.

### Added
- `awstorage relocate plan|show|approve|apply|apply-approved|status`
  (`awstorage.relocate`). The planner measures each source (bytes, files, newest
  mtime, nested reparse points), gathers cold evidence (psutil open handles when
  installed, container mounts from `--mounts-file`) and projects every drive: the
  source gains the bytes, the destination loses `bytes * 1.02`. Refused: a floor
  crossing (`drive_floors_gb` in storage-topology.yaml), an existing destination, a
  reparse-point source, a source under `relocate_do_not_move` / the guards' never
  set, a tree modified within 14 days. A plan with any refusal cannot be approved.
- `apply` refuses without `approved/<plan_id>.json` (bound to the plan's sha256),
  re-measures and re-checks the destination floor right before each move, runs
  `robocopy /E /MOVE /COPY:DAT /DCOPY:DAT /R:1 /W:1 /MT:16`, verifies the source is
  empty and the destination's file count and bytes, junctions the old path, and
  moves the tree back on any failure. Each attempted move: one ledger row
  (`action=relocate`), one awrelay line, one Pulse event; a failed post is recorded
  in the result and logged, never fatal.
- `apply-approved` (the `storage-relocate` wake) applies every approved plan with no
  result, and applies nothing while `~/.aither/maintenance.marker` exists.
## 0.4.0 -- 2026-09-28

Measured the same day: dead agent sessions held 106 GB until found by hand; D: hit 0
bytes at 12:15 and C: fell 124 -> 18 GB inside an hour while the sweep runs every 3 h; a
peer moved 89 GB onto the nearly-full C:; agent worktrees held 130 GB uncovered; the
harvest shelf sat on E: at 99 %; nothing learned which suggestions were right.

### Added
- **Suggestions** (`awstorage.suggest`): `suggest(path, *, reason, suggested_by,
  action="quarantine", evidence=None, ttl_days=7.0, catalog=None)`,
  `suggestions(status=None, limit=50, catalog=None)`,
  `resolve_suggestion(id, decision, *, card=None, catalog=None)`,
  `apply_suggestions(*, dry_run=True, harvest_to=None, catalog=None)`,
  `revert_suggestion(id, *, catalog=None)`, `trust(agent=None, *, catalog=None)`,
  `set_card_hook`, `set_archive_hook`. Named validation checks; auto lane only for a
  regenerable quarantine with verified evidence from a trusted agent; everything else
  is card-only through `manage.verify_card` (refused while the store does not attest
  the answerer). Apply re-validates and refuses on drift, harvests first, ledgers and
  records the outcome; reverts (also via `awstorage revert`) are detected. CLI:
  `suggest`, `suggestions`, `suggestion approve|reject|revert`, `apply-suggestions`,
  `trust`.
- **Trust ledger**, derived from the suggestion rows:
  `(applied - 3*reverted + 1) / (applied + rejected + 2)`; threshold 0.6
  (`AWSTORAGE_TRUST_THRESHOLD`, clamped >= 0.51 so a new agent never auto-approves).
- `awstorage.gitcheck`: clean + pushed judgement (`git status --porcelain`,
  `rev-list @{u}..`, `HEAD [--branches] --not --remotes`), timeouts, fail closed.
- **watch** (`awstorage.space.watch_once`, `awstorage watch`): floors per drive, a
  no-walk fast path, emergency sweep of the presets on the drive under its floor,
  alerts to `~/.aither/awstorage/alerts.jsonl` + `$AWSTORAGE_ALERT_CMD`.
- **place** (`awstorage.place`, `awstorage place`): rank drives by free space after a
  move; refuse any that would end under its floor.
- **Shelf safety**: `sweep(floors=...)` / `--floors` / `$AWSTORAGE_FLOORS` keep an item
  (`harvest-skipped`) rather than harvest onto a shelf drive under its floor (unless the
  act deletes the item from that same drive); `awstorage shelf prune --older-than 30d`.
- Preset `agent-worktrees` (paths from `--policy`; idle 7d; quarantine;
  `require_git_clean`). Rule key `require_git_clean` (quarantine rules only): items that
  are not a clean, fully pushed git work tree root are kept (`skipped-git`).
- Catalog table `suggestions` (additive; an older catalog opens). A suggestion's id is
  a `proposals` row id with action `suggest:<action>`, which `policy.apply` refuses.
- Self-test checks 10-14: suggest refuses a dirty work tree, the auto lane never
  deletes, watch fires under a floor (and not above it), place refuses a move below a
  floor, a low shelf drive keeps the item.

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
