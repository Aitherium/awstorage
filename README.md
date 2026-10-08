# awstorage

<!-- aither-header:start GENERATED from the ecosystem registry. Edits here are overwritten; change the registry instead. -->

**[Docs](https://aitherium.github.io/awstorage/)**  ·  [Source](https://github.com/Aitherium/awstorage)  ·  `pip install awstorage`  ·  [The Aither World](https://aitherium.github.io/)

> **The Aither World** is an operating system for agents — a Linux you can hand to one, the runtimes it works in, and the tools it works with. [awnix](https://github.com/Aitherium/awnix) is the Linux underneath it; **awstorage** is one of its 67 bricks — each installs on its own, runs offline, and needs no account.
>
> **Start here:** Scan one drive and read a ranked inventory of what fills it, with each tree marked re-fetchable or not.

<!-- aither-header:end -->

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
7. **Sweep** -- named retention rules, unattended: live guard, harvest-first (verified,
   secrets withheld), link-safe removal, a receipt on every exit path. See below.
6. **Index files** (`awstorage files ...`): one row per file in `files.db` (the
   catalog's sibling), searchable by file name (SQLite FTS5, trigram), rolled up by
   directory, with duplicates found by size bucket, then a head+tail partial hash,
   then a full sha256 -- hard links collapse, and `actionable_bytes` counts only
   copies a manage action could really reclaim. Rescans are incremental: only files
   whose size, mtime or hash changed are written (each takes a new `seq`); files a
   COMPLETED walk no longer sees become tombstones; a truncated walk deletes nothing.
   Credential-shaped files (`.ssh`, `.env*`, `*.pem`, ...) are indexed but flagged and
   redacted for any non-platform reader (`awstorage.guards`).

```bash
awstorage whoami                                  # AWSTORAGE_NODE > ~/.aither/node-id > hostname
awstorage files scan E:/ D:/Media --hash auto     # index + hash only possible dupes
awstorage files scan --all-volumes                # every fixed volume minus the never set
awstorage files find quarterly report --ext pdf   # every word, substring of the name
awstorage files dupes --min-bytes 1048576         # most waste first
awstorage files tree E:/ --depth 2                # sizes by path, from the rollup
awstorage files nodes                             # what is indexed, and how stale
awstorage files push                              # DELTA since the fleet's last seq
awstorage manage shares                           # python -m awstorage.manage
```

`find|dupes|tree` read the FLEET index when a session bearer exists (`--remote`;
`--local` reads this node's `files.db`).

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

## Sweep agent scratch automatically

`scan -> propose -> apply` wants a person between the steps. The thing that filled
drive C: on 2026-09-27 (122 MB free, a WSL root fs corrupted mid-boot) did not: 173 GB
of per-session agent scratchpads under `%LOCALAPPDATA%\Temp\claude\<project>\<session>\`
that nothing reaped -- one dead session held 106 GB -- plus ~19k stale Temp entries.
`sweep` is the unattended half:

```bash
awstorage sweep --rules agent-scratch,temp-toplevel                  # dry run: the full plan
awstorage sweep --rules agent-scratch,temp-toplevel --yes \
    --harvest-to E:\AitherOS-Data\harvest --emergency-free-gb 40 \
    --receipt ~/.aither/awstorage/last_sweep.json
```

Schedule it with [awrise](https://github.com/Aitherium/awrise):

```bash
awrise add --name awstorage-sweep --every 3h --detach --timeout 3600 -- awstorage sweep --rules agent-scratch,temp-toplevel --yes --harvest-to E:\AitherOS-Data\harvest --emergency-free-gb 40 --receipt ~/.aither/awstorage/last_sweep.json
awrise set --name awstorage-sweep receipt=~/.aither/awstorage/last_sweep.json
```

One pass: **expand rules -> measure -> guard -> harvest -> remove -> ledger -> receipt.**

- **Rules are data, and opt-in by name.** Shipped presets: `agent-scratch`
  (`%LOCALAPPDATA%\Temp\claude\*\*` on Windows, `$TMPDIR/claude/*/*` elsewhere; idle 12h)
  and `temp-toplevel` (`%LOCALAPPDATA%\Temp\*` minus the claude dir; idle 3d). Nothing is
  swept without a rule naming it. Your own rules go in a JSON `--policy` file:
  ```json
  {"retention": [{"name": "build-scratch", "paths": ["~/scratch/*"], "class": "build-temp",
                  "max_idle": "2d", "action": "quarantine", "purge_after": "3d",
                  "exclude": ["~/scratch/keep-*"], "live_guard": {"window": "2h"},
                  "harvest": {"include": ["**/*.md"], "max_file_kb": 256},
                  "snapshot": false}]}
  ```
  One glob match = one item. `class` may not be a never-auto class (`service-state`,
  `dataset`, `vm-disk`, `backup`, `unknown`).
- **Age is the newest file inside the item**, never the item's own mtime.
- **Live guard.** An item that changed inside `live_guard.window` (default 2h), or whose
  name is registered live, is skipped and reported `skipped-live`. An agent runtime
  registers its session scratch through `AWSTORAGE_LIVE_IDS` (comma/space separated) or
  a `--live-ids` file (one id per line, `#` comments); an id matches the item's basename.
  An id containing a path separator is a PATH id: it keeps that exact dir, everything
  under it and every ancestor -- how a runtime marks a session dir with a generic name
  (`scratchpad`, `tmp`) live without shielding every dir of that name.
  An unreadable `--live-ids` file stops the sweep (exit 2) -- "nobody is live" is never
  a guess.
- **Harvest first.** Small text files matching the include globs (default `**/*.md`,
  `**/*.json`, `**/*report*`, `**/*eval*/**`, `**/results/**`; 512 KB/file, 20 MB/item;
  NUL in the first 8 KB = binary) are copied to
  `<shelf>/<rule>/<YYYY-MM-DD>/<item>/` with a `manifest.json` (item, bytes, file count,
  top-20 subdirs, every copy's sha256, every skip's reason). Every copy is re-read and
  checked (size + sha256) before the item may go; any failure keeps the item and exits 1.
  A file matching a credential pattern (`sk-`, `ghp_`, `AKIA`, `xoxb-`, private-key
  blocks, `password=<value>`, ...) is **withheld**: listed by name, never copied, the
  match never written. `--harvest-offdrive` refuses a shelf on the item's own drive.
- **Links are never followed.** A symlink or Windows junction inside an item is unlinked;
  its target is untouched (removal, quarantine, purge and scan all ask the same
  `is_link()`, which sees junctions on every Python).
- **Quarantine by default.** Items move to `<base>/.awstorage-quarantine/sweep-<rule>-*`
  (`awstorage revert` works on them) and are purged after the rule's `purge_after`.
  `action: delete` deletes outright -- only with `--yes`, like everything else.
- **Emergency.** `--emergency-free-gb N`: when an item's drive has less than N GB free,
  that rule's `max_idle` (and `purge_after`) halve for the pass; harvest still runs first.
  A rule with `emergency_delete: true` (the two presets; regenerable classes only)
  DELETES instead of quarantining there -- only after the item's harvest verified --
  because a same-drive quarantine frees nothing until `purge_after` (the first real run
  removed 1130 items and freed 0 bytes). Receipt: `emergency_deleted`,
  `bytes_emergency_deleted`; audit/ledger action `deleted-emergency`.
- **Purge every pass.** Each rule purges its expired quarantine BEFORE its items, so a
  pass the time budget cuts still frees bytes (`bytes_purged`, counted in `bytes_freed`).
- **Per-item measure cap.** `--measure-cap-s` (default 120): an item whose age walk runs
  past it is judged by its top-level mtime + its first 2000 files; all old -> eligible
  (size `unknown (capped)`, listed in the receipt's `capped`), any fresh -> live, skipped.
  One 106 GB dead session otherwise eats a whole pass just being measured.
- **Bounded.** `--time-budget SECONDS` (default 3000, inside awrise's 3600 s timeout)
  stops the pass cleanly and marks the receipt `truncated`; a fresh item's walk stops
  at its first too-new file instead of measuring 100 GB it will not touch. The next
  pass resumes, starting with the item the budget cut (`resume_first` in the receipt)
  -- a killed sweep would have left no receipt at all.
- **Receipt on every exit path**: `{exit_code, started, finished, items_seen,
  items_removed, bytes_freed, bytes_quarantined, bytes_harvested, skipped_live, errors,
  free_before, free_after, ...}`. `bytes_freed` counts only bytes actually gone (deleted
  or purged); a quarantine is reported separately. Exit 0 clean, 1 an item failed (kept,
  reported), 2 could not judge (bad rule, unreadable root; nothing removed). Every
  decision is a ledger row in the catalog (`--catalog`, default
  `~/.aither/awstorage/catalog.db`).

```python
import awstorage
receipt = awstorage.sweep(["agent-scratch"], dry_run=False,
                          harvest_to="E:/AitherOS-Data/harvest", emergency_free_gb=40,
                          receipt="~/.aither/awstorage/last_sweep.json",
                          live_ids=["<my-session-id>"])
```

## Agents suggest deletions

Dead agent sessions held 106 GB on 2026-09-28 until a person found them by hand -- and
the agents that made them knew they were dead. `suggest` lets any agent say so, and
gives it no power beyond saying so:

```bash
awstorage suggest C:/Users/me/AppData/Local/Temp/claude/proj/4f2e... \
    --reason "my session ended 2 days ago" --by lyra \
    --evidence '{"bytes": 113800000000, "idle_hours": 48}'
awstorage suggestions                       # every suggestion, newest first
awstorage suggestion approve 42 --card card.json   # a decision card, never a bare yes
awstorage suggestion reject 42
awstorage apply-suggestions                 # dry run: the plan
awstorage apply-suggestions --yes           # re-verify, harvest, quarantine, ledger
awstorage suggestion revert 42              # put it back (and the agent's trust pays)
awstorage trust                             # the per-agent ledger
```

```python
r = awstorage.suggest(path, reason="session ended", suggested_by="lyra",
                      action="quarantine", evidence={"bytes": n, "idle_hours": 48})
# {"id": 42, "status": "auto-approved"|"pending-card"|"refused"|"duplicate",
#  "why": "...", "class": "build-temp", "size": 113800000000, "checks": [...]}
awstorage.suggestions(status="pending-card")
awstorage.resolve_suggestion(42, "approve", card=card)
awstorage.apply_suggestions(dry_run=False, harvest_to="E:/AitherOS-Data/harvest")
```

- **Validated twice** -- at suggest time and again at apply time; each step is a named
  entry in `checks`. Refused: a path that does not exist or is a link; under the never /
  sensitive / OS set, a quarantine, a volume root, the home dir or a path awstorage
  depends on; inside a git work tree that is dirty, has commits no remote holds, or that
  git cannot judge (walks up for `.git`; `git status --porcelain`, `git rev-list @{u}..`
  and `HEAD --not --remotes`, each with a timeout); any file changed within the live
  window (2 h) or a path segment registered live (`AWSTORAGE_LIVE_IDS`); evidence that
  contradicts the measurement. A second open suggestion for the same path is a
  `duplicate` of the first.
- **Two lanes.** `auto-approved` only when ALL hold: a regenerable class (`build-temp`,
  `package-cache`; agent scratch and temp resolve to `build-temp` through the sweep
  presets, but a tree that names itself `dataset`/`repo`/... keeps that class), action
  `quarantine` (never delete, never archive), the evidence verifies (at least one of
  `bytes`, `files`, `idle_hours`, `cls` checked and none contradicted), no nested work
  tree is dirty or unjudged, the agent's IDENTITY is verified (below), and its trust
  clears the threshold. Everything else is `pending-card`: a decision card is raised
  through `awstorage.suggest.set_card_hook` (none by default: it waits in
  `suggestions`). Approving one needs a card that passes `awstorage.manage.verify_card`
  -- a SIGNED answer receipt (see "Signed answer receipts") -- the same check manage
  applies. Rejecting needs no card.
- **Apply trusts no status.** `catalog.db` is a file any local process can edit, so an
  `approved` row is re-verified: the card recorded at resolve (or the live card through
  `set_card_reader(fn)`) must pass `manage.verify_card` again, be the card the row
  names, carry the receipt whose digest was recorded at resolve, and carry a
  `content_sha256` fact equal to the digest of the row as it stands now (path, action,
  node, class, size, ...). An `auto-approved` row re-judges every lane condition from
  disk and the verifier (class re-classified, quarantine only, evidence re-checked,
  identity re-verified against the proof stored at suggest time -- so a proof must be
  JSON-serialisable -- and trust). Anything that does not verify is `refused`; a
  status alone never deletes.
- **Apply re-validates.** Re-validation refused, or size / file count / newest mtime moved
  since the suggestion -> `drifted`, nothing touched. An auto approval whose agent's
  trust has since fallen goes back to `pending-card`. Then harvest first (the sweep's
  verified harvest), then a quarantine under `<parent>/.awstorage-quarantine/suggest-<id>-*`
  (`awstorage revert` works; purged after 72 h) -- or, card-approved only, a delete or an
  archive through `set_archive_hook`. Every step is a ledger row; the outcome is recorded
  on the suggestion.
- **Trust** is derived from the suggestion rows, never a separate counter:
  `trust = (applied - 3*reverted + 1) / (applied + rejected + 2)` (Laplace-smoothed).
  A new agent scores 0.50, under the default threshold 0.6 (`AWSTORAGE_TRUST_THRESHOLD`,
  clamped to at least 0.51), so its first suggestions go to cards; one revert of an
  applied suggestion costs three applications.
- **Identity (0.4.1).** `suggested_by` is declared by the caller and every caller is
  in-process, so the brick cannot tell an agent from something typing its name. The
  auto lane therefore needs a VERIFIED identity: a verifier installed with
  `awstorage.set_identity_verifier(fn)` (`fn(suggested_by, proof) -> True`) accepted the
  `identity_proof` passed to `suggest`. Without one every suggestion records
  `identity: unverified` and goes to a card, whatever its trust. The owner may opt in
  to trusting in-process callers with `AWSTORAGE_TRUST_INPROCESS=1` (recorded as
  `inprocess-trusted` and re-checked at apply: unset it and those approvals are
  withdrawn). Transports stamp what they know -- AitherOS MCP `mcp-session:<uid>`,
  awdk `agent:<name>` -- neither is proof.

## Signed answer receipts (0.4.1)

A decision card's `answered_by`, `answered_via` and `answer_attested` live in files an
agent on the same host can edit, so none of them approves anything. The platform's
answering surface signs a receipt with an Ed25519 key that exists only in its vault and
stores it on the card as `answer_receipt` (`{alg, kid, receipt, sig}`; the receipt is
`{v, card_id, choice, answered_by, answered_at, nonce, surface, auth_method, auth_time,
facts_sha256}`). `awstorage.attest.verify_receipt` -- called by `manage.verify_card` and
so by manage apply, node orders and suggestion approvals -- refuses unless:

- awseal is installed (`pip install awstorage[attest]`; it carries the verifier) and a
  public key is provisioned in a FILE: `AWSTORAGE_ATTEST_PUBKEY_FILE=<path>`
  (`AWSTORAGE_ATTEST_PUBKEY` is accepted as a path too; a raw 64-hex key in either env
  var is REFUSED -- whoever starts the verifier sets its env). The FILE must be provisioned by root / the
  owner OUTSIDE `~/.aither` (e.g. `/etc/aither/attest.pub`, or a `%ProgramData%` path
  whose ACL agents cannot write): a path under `~/.aither`, or (POSIX) a world-writable
  file or directory, is refused -- whoever can swap the key can sign approvals;
- the signature verifies, and the receipt names this card, this answer and this card's
  facts (a fact edited after the answer is refused);
- `auth_method` is `webauthn` or `totp_2fa` and the sign-in was at most 15 min before
  the answer (`AWSTORAGE_ATTEST_MAX_AUTH_AGE_S`, clamped 60..3600) -- password, device
  flow (every agent bearer), PAT, API key, OIDC access token, magic link and internal
  mints never count;
- `answered_by` is an owner principal (`AWSTORAGE_MANAGE_OWNERS`);
- `answered_at` is inside the card's window and within 5 min of the store's own;
- the receipt is at most 7 days old by the REAL clock
  (`AWSTORAGE_ATTEST_MAX_RECEIPT_AGE_S`, clamped 1 h..30 d; `verify_receipt(now=)` is
  ignored -- an injectable clock is an injectable bypass);
- the nonce is new: the catalog table `attest_nonces` binds each nonce to one card and
  each card to one receipt (re-verifying the SAME receipt is fine).

Every card also carries `content_sha256: <hex>` -- the digest of WHAT is approved
(manage: node, action, path, bytes, tenant, owner, params and every member's path +
sha256 + bytes; suggestions: see above). `manage._authorize` and suggestion
resolve/apply recompute it from the row and refuse a mismatch or a card without it.

`manage.STORE_ATTESTS_ANSWERER` is now only the master switch (True; False refuses
every answer). A card without a valid receipt is refused either way.

### Threat model -- what an approval does and does not prove

On a single-user host agents run as the owner's OS user. They can delete files
directly, read the browser's localStorage session and, with `podman exec`, service
state. A verified receipt therefore proves **"an owner passkey/TOTP session existed
within 15 minutes of this answer"** -- not "the owner saw this card and chose this".
Approvals are a **governance gate and a tamper-evident audit trail for agents that use
the tools**, NOT a security boundary against a hostile local agent. That boundary needs
OS isolation: agents under a separate OS user, or in a container without podman or
vault access, and the verifier key provisioned where they cannot write it.

Follow-up that closes the remaining gap (review 2, a2/c3): a per-answer WebAuthn
step-up whose assertion signs the digest of the RENDERED card, verified here instead of
(or beside) the session-age check.

## Keep drives above their floors

```bash
awstorage watch --floors C:=40,D:=60,E:=30 --once --receipt ~/.aither/awstorage/watch.json
awstorage watch --floors C:=40,D:=60,E:=30 --once --yes      # let the emergency sweep act
awrise add --name awstorage-watch --every 5m --timeout 300 -- awstorage watch --floors C:=40,D:=60,E:=30 --once --yes --receipt ~/.aither/awstorage/watch.json
```

The 3-hourly sweep is too slow for a drive that falls 124 -> 18 GB in an hour. `watch`
is one `disk_usage` per floored drive: with every drive above its floor it walks no tree
and finishes in milliseconds. Under a floor it runs the emergency sweep of the presets
(`--rules`, default `agent-scratch,temp-toplevel`) on THAT drive only -- a plan unless
`--yes` -- appends an alert to `~/.aither/awstorage/alerts.jsonl`, and runs
`$AWSTORAGE_ALERT_CMD` with the alert JSON as its last argument (a JSON list such as
`["awrelay", "send", "#agents"]`, or a shell-like string; never run through a shell),
so awrelay / Pulse plug in without being imported. Exit 0 all above, 1 a drive still
under its floor, 2 could not judge. `$AWSTORAGE_FLOORS` holds the same spelling.

## Before moving data between drives

```bash
awstorage place --size 90GB --from C:/data/models --floors C:=40,D:=60,E:=30
awstorage place --size 90GB --to C: --floors C:=40      # exit 1: refused
```

`place` ranks every drive by its free space AFTER the move and refuses any that would
end under its floor (unlisted drives: `--default-floor-gb`, 20). Run it before moving
data -- on 2026-09-28 a peer moved 89 GB onto a nearly-full C:. Python:
`awstorage.place("90GB", {"C:": 40, "E:": 30}, source="D:/models")`.

## Shelf safety

The harvest shelf is a drive too (E: sat at 99 %). With floors set (`--floors` on
`sweep`, `$AWSTORAGE_FLOORS` for `apply-suggestions`), an item whose harvest would be
written onto a shelf drive under its floor is KEPT (`harvest-skipped: shelf drive low`)
-- never removed without its harvest. The one exception: an act that deletes the item
from the shelf's own drive (a `delete` rule or an emergency delete) repays the copy at
once, so the emergency on a full C: with the shelf on C: still frees space. Rotate the
shelf with `awstorage shelf prune --older-than 30d [--yes]` (the date in the day dir's
name decides, not its mtime).

## Agent worktrees

```json
{"retention": [{"name": "agent-worktrees", "paths": ["C:/.worktrees/*", "C:/wt/*"]}]}
```

`awstorage sweep --rules agent-worktrees --policy wt.json --yes`: idle 7 d, quarantine,
purge after 7 d. Opt-in twice -- named, and its paths come from the policy. Every item
must be a git work tree ROOT whose status is clean and whose commits a remote holds;
dirty, ahead, not a repo, or unjudgeable -> `skipped-git`, kept. git's own worktree
registry must then be pruned by the tool that owns it (`git worktree prune`); never
`git worktree remove`, which follows junctions (it deleted a shared `node_modules` on
2026-09-22).

## The three rules

- **Measure before you delete.** A `du` answers one question once.
- **Re-fetchable is a property, not a guess.** The classifier says why.
- **Deleting is a policy, not a mood.** Dry run, roots, fingerprints, quarantine, ledger.

## Composes with

Every coupling is optional and imported lazily (`pip install awstorage[harvest]` for
awseal + awdit + awshare); without the package the sweep says "unavailable" in its
receipt rather than pretending.

- **awdit** -- every sweep decision (harvested, withheld-secret, skipped-live,
  quarantined, deleted, purged, failed) is appended to a hash-chained, truncation-evident
  log (`--audit-log`, default `~/.aither/awstorage/audit.log`); the intent is recorded
  BEFORE a removal. `awstorage audit verify` checks it. `--require-audit` refuses to
  remove anything (exit 2) when awdit is absent or an append fails.
- **awseal** -- each harvested item dir is sealed (`awseal.json`, Ed25519) after its
  copies verify, with `--seal-key` or awseal's own default key. An explicit key that
  cannot seal keeps the item. `awstorage harvest verify <shelf>` reports sealed /
  tampered / unsealed.
- **awshare** -- `awstorage harvest publish <shelf>/<rule>/<day> --to <dir>` (or
  `sweep --publish-to <dir>`) bundles a day's harvest; fetch it back with
  `awshare.fetch(<dir>/<name>.awshare.json, dest)`, which verifies the digest before a
  byte lands.
- **awm** -- `sweep --land-to-awm tenant:user:project` lands ONE memory per harvested item
  (`storage.harvest.<item>`: what was kept and where) through `MemoryStore.remember`,
  never SQL; an older-schema awm file is reported as a compat problem, never migrated.
- **awrecover** -- a rule with `"snapshot": true` snapshots each item before removal
  (`--snapshot-store`); without awrecover the item is KEPT and reported. For proposals,
  `backup_hook=lambda p: awrecover.snapshot(p, store, label)` turns
  `backup-then-delete` into a restorable snapshot first.
- **AitherStrata** (the platform's tiered storage service) -- `--harvest-to
  strata:<hot|warm|cold>` (default tier cold) uploads each verified harvested file plus
  `manifest.json` (and `awseal.json` when sealed) with `POST /strata/write`, then reads
  every object back with `GET /strata/stat/<tier>/<path>` and compares size (and sha256
  when the server reports it) BEFORE the item may be removed; any mismatch keeps the
  item. stdlib urllib + ssl only. URL from `AITHERSTRATA_URL` (default
  `https://127.0.0.1:8136`; the service is TLS-only), CA from `AITHER_CA_BUNDLE` or
  `<repo>/AitherOS/Library/Data/tls/ca-chain.pem`, key from `AWSTORAGE_STRATA_KEY` (sent
  as `X-Internal-Key`, env var only). No CA, no key, or unreachable = "strata target
  unavailable": nothing removed, exit 2. There is no unverified-TLS mode.
- **awdk** -- calls `awstorage.sweep(...)` (returns the receipt dict) and registers its
  running sessions through `AWSTORAGE_LIVE_IDS`.
- **awrise** -- schedules the sweep and reads its receipt (see above).
- **awdk / awnode / awsh** -- run the scanner where the disk is, post snapshots to a
  shared catalog, render proposals in a shell or a desktop panel.
- **awgraph** -- `awstorage graph` emits nodes and typed edges (`contains`,
  `duplicate_of`) any graph store can ingest.

`awstorage --self-test` (or `python -m awstorage --self-test`) proves the refusals still refuse, the quarantine still reverts, and each sweep guard is seen firing: harvest-before-delete, secret withheld, live guard, junction not followed, emergency halving, emergency delete (only for a flagged rule, never without a verified harvest), the per-item measure cap both ways, receipt on failure.

Apache-2.0.

<!-- aither-ecosystem:start GENERATED from the ecosystem registry. Edits here are overwritten; change the registry instead. -->

## The aw family

Standalone tools that share one idea: **replace something you would otherwise have to _trust_ with something you can _check_.**

Each installs on its own, works offline, and needs no account.

| | instead of trusting | you check |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | a framework's idea of how your agents should run | one loop you can read, pointed at a backend you already pay for |
| [awskills](https://github.com/Aitherium/awskills) | that an agent knows your procedure | the procedure written down, versioned, and loadable by any agent |
| [awpack](https://github.com/Aitherium/awpack) | that the pack you want shipped inside somebody's SDK, under whatever licence that SDK happens to carry | the pack as its own versioned artifact, with its own licence, that any agent runtime can install |
| [awm](https://github.com/Aitherium/awm) | that memory stayed in its lane | tenant:user:project scopes, so a write cannot cross a boundary |
| [awdesk](https://github.com/Aitherium/awdesk) | that the agent is somewhere behind a browser tab | a tray icon, a face on your desktop, and the decision card that pops when it needs you |
| [awnode](https://github.com/Aitherium/awnode) | a vendor's cloud with every prompt | a local gateway routing to backends you chose |
| [awgraph](https://github.com/Aitherium/awgraph) | that grep found everything | an AST + tree-sitter call graph an agent can traverse |
| [awgit](https://github.com/Aitherium/awgit) | that no one else is editing this file | a lease, refused at commit time if you do not hold it |
| [awdelphi](https://github.com/Aitherium/awdelphi) | one agent's confident take on a decision | the round trace, the anonymity, and who dissents |
| [awclassify](https://github.com/Aitherium/awclassify) | a filename, a folder, or whoever last touched it | doc_type, visibility, audience and topics, with the evidence lines that decided each |
| [awdecide](https://github.com/Aitherium/awdecide) | a hosted classifier's probability that never learns whether it was right | the decision, its probability, and the calibration curve from your own resolved outcomes |
| [awtoll](https://github.com/Aitherium/awtoll) | that your tooling is saving you context | the measured token cost of each tool call, and what the alternative cost |
| [awseal](https://github.com/Aitherium/awseal) | that the artifact came from who you think | an Ed25519 seal — the key that verifies is not the key that forges |
| [awshare](https://github.com/Aitherium/awshare) | that the download is intact | content-addressed bundles, verified on fetch |
| [awsuite](https://github.com/Aitherium/awsuite) | that an agent holding your mailbox will not send on its own | every send, draft, upload and create returns a dry-run until confirm is true |
| [awnest](https://github.com/Aitherium/awnest) | that there is a person on the other end | a verdict with evidence, where "we could not tell" is not "yes" |
| [awrena](https://github.com/Aitherium/awrena) | a leaderboard someone can edit, and votes nobody counted | a scored duel with both answers kept, and a result bound to them |
| [awnboard](https://github.com/Aitherium/awnboard) | a share link anyone who sees it can use | an invitation addressed to one person, for one gate, revocable |
| [awnix](https://github.com/Aitherium/awnix) | that the box is what you left it as | an immutable image you built, with atomic rollback |
| [awrecover](https://github.com/Aitherium/awrecover) | that the restore worked | a restore that fully lands or does not land at all |
| **awstorage** _(you are here)_ | a du you ran last month, and a peers file that says 3 TB free | an inventory snapshot per node with a diff since the last one, and each tree classified re-fetchable or not |
| [awrelay](https://github.com/Aitherium/awrelay) | a SaaS in the middle of your agents | findings, alerts and coordination over your own transport |
| [awask](https://github.com/Aitherium/awask) | that anyone read the paragraph where you asked | the ask itself, with a button that steers the session that raised it |
| [awmail](https://github.com/Aitherium/awmail) | a mailbox somebody else can read | mail your agents send and receive over your own server |
| [awswarm](https://github.com/Aitherium/awswarm) | that a model either fits your GPU or it doesn't run at all | a placement plan and an acquisition-probability estimate before you spend on a run |
| [awfind](https://github.com/Aitherium/awfind) | one vendor's idea of the web | results from whichever providers you configured |
| [awbrowse](https://github.com/Aitherium/awbrowse) | that the page said what you were told | the render, the DOM and the requests it made |
| [awvoice](https://github.com/Aitherium/awvoice) | that a cloud vendor may hold your audio | a transcript and a wav from a service you host |
| [awvision](https://github.com/Aitherium/awvision) | a filename and a caption somebody wrote | what a model actually reports about the pixels |
| [awscreen](https://github.com/Aitherium/awscreen) | a selector that was true when the page was written | the elements actually rendered, by what they look like |
| [awbeads](https://github.com/Aitherium/awbeads) | that a layout your users built survives the next deploy | the arrangement as data you can read back, diff, and hand to another surface |
| [awbonsai](https://github.com/Aitherium/awbonsai) | that inference always means a request left the machine | a WebGPU model answering on the tab's own GPU, with a consent record logged before it ever loaded |
| [gawbbonet](https://github.com/Aitherium/gawbbonet) | the model to keep a 300-message campaign coherent by itself | campaign facts recalled from scoped memory you can list and edit |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | a vendor's quantisation defaults | sub-byte KV cache kernels you can benchmark yourself |
| [awrtifact](https://github.com/Aitherium/awrtifact) | a hand-rolled split script and a hand-edited worker manifest | byte-verified parts in a release, served with Range + CORS, sizes asserted by a live gate |
| [AitherZero](https://github.com/Aitherium/AitherZero) | a pile of scripts nobody has numbered | numbered, discoverable automation with declarative playbooks |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | what a page tells your browser to do | a federated search and desktop bridge you host |
| [awreason](https://github.com/Aitherium/awreason) | a confident paragraph | the phases it went through, and every tool call it made to get there |
| [awrecurse](https://github.com/Aitherium/awrecurse) | that everything you pasted in was actually read | which slices it opened, and what it concluded from each |
| [awprism](https://github.com/Aitherium/awprism) | the first explanation that fits | the ranked alternatives, and the observation that separates them |
| [awrepl](https://github.com/Aitherium/awrepl) | what the agent believes the value is | the value, printed from the live session |
| [awreport](https://github.com/Aitherium/awreport) | that the report you pasted carried no token in it | a redacted report, and the duplicate it merged into instead of filing twice |
| [awresearch](https://github.com/Aitherium/awresearch) | a summary of pages nobody opened | every claim against the source it came from |
| [awfocus](https://github.com/Aitherium/awfocus) | twelve terminal tabs and a bad memory | one command that names every session, finds any transcript, and opens or steers the one you want |
| [awgym](https://github.com/Aitherium/awgym) | that a world model learned anything from the games it saw | transitions captured from real play, fed back, and the retrodiction score falling on grids it never saw |
| [awpredict](https://github.com/Aitherium/awpredict) | a model because it trained without erroring | its prediction against a self-updating lookup, on the rows that are actually novel |
| [awevolve](https://github.com/Aitherium/awevolve) | that your optimisation loop is finding anything | every version it kept, the score that version earned, and the edit that produced it |
| [awsh](https://github.com/Aitherium/awsh) | that you already know the name of the command | what it decided your line meant, before it acts on it |
| [awmine](https://github.com/Aitherium/awmine) | that a session's lesson survived the session | a row per outcome, a candidate per lesson, and the transcript line each one came from |
| [awrise](https://github.com/Aitherium/awrise) | that a scheduled agent ran at all, and ran exactly once | a durable record of every wake -- fired, skipped, overlapped or timed out -- each with its reason |
| [awkno](https://github.com/Aitherium/awkno) | that the docs site is up, or that you remember the family | the whole ecosystem in your terminal, with no network at all |
| [awwall](https://github.com/Aitherium/awwall) | that a service only talks to the hosts you think it talks to | an explicit egress allowlist, where a denial names the rule that denied it |
| [awembed](https://github.com/Aitherium/awembed) | a general-purpose embedder that has never seen your code | a held-out split of whole directories, scored teacher vs student vs int8 |
| [awtax](https://github.com/Aitherium/awtax) | a closed tax app's sealed file you can never read again | a plain, provider-neutral schema of every figure, with the page it came from |
| [awsettings](https://github.com/Aitherium/awsettings) | that you will remember to re-approve the same thing on every box you work from | one profile, unioned rather than overwritten, with the credentials left behind |
| [awavatar](https://github.com/Aitherium/awavatar) | a cloud 3D vendor's opaque task id | a manifest with a sha256, a licence and a rig-audit verdict per file |

[**awnix**](https://github.com/Aitherium/awnix) is the ground floor — A Linux you can hand to an agent — immutable base, capabilities included.

## The Aitherium ecosystem

Every repository here is public. Each publishes an `aither-manifest.json` beside its page, so any surface can read every sibling's — the network is browsable from any node in it.

| repo | what it is | pages |
|---|---|---|
| [awdk](https://github.com/Aitherium/awdk) | Build AI agent fleets — 3 lines, any backend, local or cloud | [docs](https://aitherium.github.io/awdk/) |
| [awskills](https://github.com/Aitherium/awskills) | Portable agent skills — self-contained procedures an agent loads on demand | [docs](https://aitherium.github.io/awskills/) |
| [awpack](https://github.com/Aitherium/awpack) | First-party agent packs — the ones we build, versioned and installable on their own | [docs](https://aitherium.github.io/awpack/) |
| [awm](https://github.com/Aitherium/awm) | A portable, scoped agent memory | [docs](https://aitherium.github.io/awm/) |
| [awdesk](https://github.com/Aitherium/awdesk) | Aither World Desk -- the desktop body of AitherOS Online: tray, avatars, decision cards, the Living Desktop as an overlay | [docs](https://aitherium.github.io/awdesk/) |
| [awnode](https://github.com/Aitherium/awnode) | A lightweight local gateway — bridges your apps to the AI backends you chose | [docs](https://aitherium.github.io/awnode/) |
| [awrun](https://github.com/Aitherium/awrun) | A priority-aware queue and dispatcher for agentic runs and ad-hoc CI builds. It also judges whether the runner pool is big enough for the queue it is draining, and can ask a host to grow it -- reserving capacity is zero-sum, so a saturated pool needs more of it, not a different share of it | [docs](https://aitherium.github.io/awrun/) |
| [awgraph](https://github.com/Aitherium/awgraph) | A semantic code graph for agents — AST + tree-sitter, call graphs | [docs](https://aitherium.github.io/awgraph/) |
| [awgit](https://github.com/Aitherium/awgit) | Semantic version control on top of git — edit-ops and leases | [docs](https://aitherium.github.io/awgit/) |
| [awdelphi](https://github.com/Aitherium/awdelphi) | Anonymous multi-round expert panels — a converged answer with a trace | [docs](https://aitherium.github.io/awdelphi/) |
| [awclassify](https://github.com/Aitherium/awclassify) | Classify any document -- what it is, who may read it, who it is for, what it is about | — |
| [awdecide](https://github.com/Aitherium/awdecide) | One typed-decision contract -- choice / score / bool with a probability -- over a ladder of backends you already run (rules, tiny local models, an LLM's logprobs), fail-closed, with a Brier ledger that resolves every decision against its outcome | — |
| [awtoll](https://github.com/Aitherium/awtoll) | What every tool call costs you in context, measured from your own transcripts | [docs](https://aitherium.github.io/awtoll/) |
| [awseal](https://github.com/Aitherium/awseal) | Sign an artifact so a stranger can verify it | [docs](https://aitherium.github.io/awseal/) |
| [awshare](https://github.com/Aitherium/awshare) | Publish an artifact and fetch it back verified | [docs](https://aitherium.github.io/awshare/) |
| [awsuite](https://github.com/Aitherium/awsuite) | Your Google Workspace as agent tools, and no write happens without a yes | — |
| [awdit](https://github.com/Aitherium/awdit) | An append-only audit trail whose gaps are DETECTABLE | [docs](https://aitherium.github.io/awdit/) |
| [awbac](https://github.com/Aitherium/awbac) | Role-based access control that fails closed and explains itself | [docs](https://aitherium.github.io/awbac/) |
| [awiam](https://github.com/Aitherium/awiam) | Who is this caller? A directory and session store that fails honestly | [docs](https://aitherium.github.io/awiam/) |
| [awtunnel](https://github.com/Aitherium/awtunnel) | Reach a service that has no public address | [docs](https://aitherium.github.io/awtunnel/) |
| [awnest](https://github.com/Aitherium/awnest) | Prove there is a human before you let them into the nest | [docs](https://aitherium.github.io/awnest/) |
| [awrena](https://github.com/Aitherium/awrena) | Put two agents head to head and get a verdict you can check | [docs](https://aitherium.github.io/awrena/) |
| [awnboard](https://github.com/Aitherium/awnboard) | A front gate you can put in front of anything, and hand someone the key to | [docs](https://aitherium.github.io/awnboard/) |
| [awnix](https://github.com/Aitherium/awnix) | A Linux you can hand to an agent — immutable base, capabilities included | [docs](https://aitherium.github.io/awnix/) |
| [awrecover](https://github.com/Aitherium/awrecover) | Labelled snapshots with an all-or-nothing restore | [docs](https://aitherium.github.io/awrecover/) |
| **awstorage** _(you are here)_ | Every drive on every node, indexed, classified and diffed -- so you can see what you own before you delete it | [docs](https://aitherium.github.io/awstorage/) |
| [awrelay](https://github.com/Aitherium/awrelay) | Portable agent messaging — findings, alerts, coordination | [docs](https://aitherium.github.io/awrelay/) |
| [awask](https://github.com/Aitherium/awask) | Your agent asks you a question — and acts on your answer | [docs](https://aitherium.github.io/awask/) |
| [awmail](https://github.com/Aitherium/awmail) | Give an agent an email address — send, and actually receive | [docs](https://aitherium.github.io/awmail/) |
| [awnet](https://github.com/Aitherium/awnet) | The agentic web — agents host a mesh, and agents join one | [docs](https://aitherium.github.io/awnet/) |
| [awswarm](https://github.com/Aitherium/awswarm) | Run one model too big for any single GPU across a pool of small ones | — |
| [awfind](https://github.com/Aitherium/awfind) | A portable search client — query, results, ranking | [docs](https://aitherium.github.io/awfind/) |
| [awbrowse](https://github.com/Aitherium/awbrowse) | A portable browser client — navigate, console, network, DOM, screenshot | [docs](https://aitherium.github.io/awbrowse/) |
| [awvoice](https://github.com/Aitherium/awvoice) | Hear and speak — transcribe audio, synthesize a voice | [docs](https://aitherium.github.io/awvoice/) |
| [awvision](https://github.com/Aitherium/awvision) | See an image — describe it, ask it a question, compare two | [docs](https://aitherium.github.io/awvision/) |
| [awscreen](https://github.com/Aitherium/awscreen) | See this machine — what is on screen, and where to click it | [docs](https://aitherium.github.io/awscreen/) |
| [awkit](https://github.com/Aitherium/awkit) | Render an agent panel from a tool result — one component, any React app | — |
| [awbeads](https://github.com/Aitherium/awbeads) | A spatial canvas for a page — arrange things, connect them, and keep the arrangement | — |
| [awbonsai](https://github.com/Aitherium/awbonsai) | Run a real model in the visitor's own browser — no server round trip, no upload | — |
| [awknowledge](https://github.com/Aitherium/awknowledge) | How to run a coding agent so the result survives — the laws, with evidence | [docs](https://aitherium.github.io/awknowledge/) |
| [awbrain](https://github.com/Aitherium/awbrain) | Your history as a wiki of linked markdown — claims pinned to the evidence | — |
| [gawbbonet](https://github.com/Aitherium/gawbbonet) | GobboNet campaigns with a real agent brain — scoped memory, graph recall | [docs](https://aitherium.github.io/gawbbonet/) |
| [aitherkvcache](https://github.com/Aitherium/aitherkvcache) | Near-optimal KV cache quantization for LLM inference — sub-byte compression | [docs](https://aitherium.github.io/aitherkvcache/) |
| [awrtifact](https://github.com/Aitherium/awrtifact) | Deliberately chunk artifacts into GitHub release assets — the productized aitherkvcache mirror lane | [docs](https://aitherium.github.io/awrtifact/) |
| [AitherZero](https://github.com/Aitherium/AitherZero) | PowerShell 7+ automation framework — numbered, self-describing scripts | [docs](https://aitherium.github.io/AitherZero/) |
| [AitherConnect](https://github.com/Aitherium/AitherConnect) | Browser extension — federated AI search, page context, and the Living OS overlay | [docs](https://aitherium.github.io/AitherConnect/) |
| [awreason](https://github.com/Aitherium/awreason) | A portable reasoning client — sessions, phases, thoughts, and the chain that produced the answer | [docs](https://aitherium.github.io/awreason/) |
| [awrecurse](https://github.com/Aitherium/awrecurse) | Answer a question over a context far larger than the window — recursively, with the trace kept | [docs](https://aitherium.github.io/awrecurse/) |
| [awprism](https://github.com/Aitherium/awprism) | Turn a failure into ranked hypotheses — and say what would confirm each one | [docs](https://aitherium.github.io/awprism/) |
| [awrepl](https://github.com/Aitherium/awrepl) | A REPL an agent can actually use — state that survives between turns | [docs](https://aitherium.github.io/awrepl/) |
| [awreport](https://github.com/Aitherium/awreport) | File a bug report that has already scrubbed your secrets and collapsed the duplicate | — |
| [awresearch](https://github.com/Aitherium/awresearch) | Ask a research question, get a cited report you can check | [docs](https://aitherium.github.io/awresearch/) |
| [awfocus](https://github.com/Aitherium/awfocus) | See, search and steer every Claude session from one command | [docs](https://aitherium.github.io/awfocus/) |
| [awgym](https://github.com/Aitherium/awgym) | An ARC training gym — a game a world model can watch, and six roles that play through it | [docs](https://aitherium.github.io/awgym/) |
| [awpredict](https://github.com/Aitherium/awpredict) | Predict what your environment does next, and how surprised you were | [docs](https://aitherium.github.io/awpredict/) |
| [awevolve](https://github.com/Aitherium/awevolve) | Point an agent at a file and a command that scores it, and let it improve | — |
| [awsh](https://github.com/Aitherium/awsh) | Your terminal answers you -- type a question where a command would go | [docs](https://aitherium.github.io/awsh/) |
| [awmine](https://github.com/Aitherium/awmine) | Mine what your agents did -- outcomes, lessons and procedures out of the transcripts they left behind | — |
| [awrise](https://github.com/Aitherium/awrise) | Wake an agent on a schedule, let it do one thing, and put it back to sleep | [docs](https://aitherium.github.io/awrise/) |
| [awkno](https://github.com/Aitherium/awkno) | The man page for the Aither World — every brick, stack and law, offline | [docs](https://aitherium.github.io/awkno/) |
| [awwall](https://github.com/Aitherium/awwall) | Say what a workload may reach, and watch everything else fail closed | [docs](https://aitherium.github.io/awwall/) |
| [awrouter](https://github.com/Aitherium/awrouter) | OpenRouter for your own fleet: pick a model backend by cost/latency/ capability, fail over, fit the context window, stream. Standalone, OpenAI-compatible, no Aither-specifics required to be valuable | — |
| [awembed](https://github.com/Aitherium/awembed) | Train an embedding model that knows your corpus, and prove it beats the big one | [docs](https://aitherium.github.io/awembed/) |
| [awtax](https://github.com/Aitherium/awtax) | Turn any tax PDF -- returns, W-2, 1099, statements, even scans -- into structured data you can check | [docs](https://aitherium.github.io/awtax/) |
| [awflow](https://github.com/Aitherium/awflow) | A deterministic workflow runtime — chain agent calls with journal replay and budget control | [docs](https://aitherium.github.io/awflow/) |
| [awsettings](https://github.com/Aitherium/awsettings) | Your agent's permissions and config, following you to the next machine | [docs](https://aitherium.github.io/awsettings/) |
| [awavatar](https://github.com/Aitherium/awavatar) | One character spec in, a rigged, animated, multi-style avatar pack out | [docs](https://aitherium.github.io/awavatar/) |

**Built on** [llama.cpp](https://github.com/ggml-org/llama.cpp) · [vLLM](https://github.com/vllm-project/vllm) · [ComfyUI](https://github.com/comfyanonymous/ComfyUI) · [CentOS Stream](https://www.centos.org/centos-stream/) · [Podman](https://github.com/containers/podman) · [Docker](https://github.com/moby/moby) · [LanceDB](https://github.com/lancedb/lancedb) · [WireGuard](https://www.wireguard.com/) · [FFmpeg](https://ffmpeg.org/) · [Blender + Rigify](https://www.blender.org/) · [headroom](https://github.com/headroomlabs-ai/headroom) · [SANA](https://github.com/NVlabs/Sana) · [Hunyuan3D](https://github.com/Tencent-Hunyuan/Hunyuan3D-2.1) · [repowise](https://github.com/repowise-dev/repowise) · [Playwright](https://github.com/microsoft/playwright) · [Chromium](https://www.chromium.org/) · [Next.js](https://github.com/vercel/next.js) · [React](https://github.com/facebook/react).

<div id="aither-constellation" data-self="awstorage"></div>
<script src="aither-constellation.js"></script>

<!-- aither-ecosystem:end -->
