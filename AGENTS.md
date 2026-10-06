# awstorage for agents

Read this if you are an agent (or a human) editing this package. Short on
purpose: the commands, the traps that cost a session, and where the rest lives.
Nothing here is read at runtime — it is for you.

## What this is

PyPI distribution **`awstorage`** (version in `pyproject.toml`), import package
`awstorage`, Python >= 3.10. Every drive on every node, indexed, classified and
diffed — so you can see what you own before you delete it.

This repository is a **synced mirror** of the AitherOS monorepo (lane
`.github/workflows/sync-awstorage.yml`). Hand edits made here are overwritten
on the next sync — change the source and let the lane publish.

## Build, test, verify

```bash
python -m pytest tests -q        # the suite: 453 passed, 1 skipped at v0.5.1
pip install -e .                 # editable install for developing against it
```

The suite was run from a source checkout with no prior install. Sibling
integration tests (awm / awdit / awseal / awshare / awrecover) SKIP when the
sibling is absent rather than failing — the publish lane installs the package's
own dependencies, so a skip here is a gap in coverage, not a pass.

## Rules that keep this useful

- **STDLIB-ONLY IS A FEATURE.** The box that most needs awstorage is the one
  whose disk is full, where pip cannot fetch anything. Nothing in
  `awstorage/integrations.py` imports a sibling at module load; every coupling
  is guarded and answers `{"available": False, "reason": ...}` honestly when
  its package (or its key, or its data) is absent — never an empty success
  that reads as done.
- **Never SQL, never migrate, into another tool's file.** `land_to_awm` goes
  through awm's public class only. An older-schema awm file is a **compat
  problem**: reported, never migrated. Measured 2026-10-06 (awm 0.6.1): the
  refusal moved from `MemoryStore(...)` to the first write (`no such table:
  memories`) — both failure points classify as `compat:` in the reason, and
  `test_integrations.py` pins both.
- **Attestation fails closed.** `test_attest_fail_closed.py` and
  `test_attest_041.py` are the contract that a delete without its receipt does
  not happen. Do not add a success path around a missing attestation.
- **A deletion is the one action with no undo.** Every new classification
  needs its sweep test (`test_sweep_022.py` is the pattern): the suggestion,
  the receipt and the refusal each get a case.

## Read next

- `llms.txt` — the install/use card written for an agent to execute
- `README.md` — the human front door (the contracts above are stated there)
- `docs/` — the generated docs site source
