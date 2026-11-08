"""inventory.py -- every node publishes its own inventory, SIGNED, to a private GitHub
repo; any other node pulls it, verifies the signature against that node's key, and
answers queries locally. Discovery that works with no Genesis in the path.

    awstorage inventory publish [--kind files|hardware|software|services] [--keep N]
                                [--repo OWNER/NAME] [--allow-public]
    awstorage inventory pull <node>... | --all [--kind K] [--key HEX] [--accept-key-change]
    awstorage inventory query tree|find|dupes [args...] [--node ID]
    awstorage inventory query show <node> [--kind hardware|software|services] [--json]
    awstorage inventory nodes [--remote] [--kind K]
    awstorage inventory enroll                 (awseal key + nodes/<node>.pub, once)

Composition -- nothing here is a new transport or a new signature scheme:

* **awseal** signs the artifact directory (``inventory.json`` + ``files.db.gz``) with the
  node's OWN Ed25519 key (``~/.aither/awseal/signing.key``, or ``AWSEAL_KEY_PATH``).
* **awrtifact** chunks the artifact under GitHub's 2 GiB asset cap (``split_file``),
  talks to GitHub (``gh`` CLI, or the REST API with ``GH_TOKEN``), and its part sha256s
  are re-checked on the way back down.
* **awrelay** hears one line after a publish (best-effort; never fails the publish).

Layout in the repo (default ``Aitherium/inventory``, ``$AWSTORAGE_INVENTORY_REPO``):

* release ``<node>-<YYYYmmddTHHMMSSZ>``: ``files.db.gz.partN`` + ``files.db.gz.manifest.json``
  (awrtifact's split manifest), ``inventory.json`` (node, kind, scanned_at, rows, bytes,
  schema), and ``awseal.json`` uploaded LAST -- a release without its seal is refused.
* release ``<node>-latest``: one ``latest.json`` naming the newest release (a pointer for
  people and browsers; ``pull`` itself lists releases and takes the newest stamp, so a
  stale pointer cannot roll a reader back).
* file ``nodes/<node>.pub``: the node's awseal public key, committed through the
  contents API (so every key change is a git commit). Written by ``enroll`` --
  ``files schedule`` runs it, and ``adk pair`` / ``adk enroll`` run ``files schedule`` --
  or by the first ``publish`` when absent.

Trust: a pull verifies against ``--key`` if given, else ``nodes/<node>.pub`` from the
repo; the first key a reader accepts is PINNED locally and a later change in the repo is
REFUSED until ``--accept-key-change``. No key, a bad signature, changed bytes, a seal
over the wrong files, or a manifest naming another node/release: REFUSED, and the
previous cache is left untouched. Publishing to a repo that is not PRIVATE (public, or
internal) is REFUSED without ``--allow-public``.

What leaves the node: paths, sizes, mtimes, extensions, inode ids, git roots, volume
mounts -- and sha256 / head-tail hashes for every file NOT flagged sensitive or never
(a key file's hash would confirm a guess of its contents). No file content, no catalog
push state, no credentials.

Kinds are pluggable (``register_kind``): ``files`` plus ``hardware``, ``software`` and
``services`` (``host_inventory.py``: small JSON documents, no env vars / command lines /
tokens). A non-files kind's releases are ``<node>-<kind>-<stamp>`` and
``<node>-<kind>-latest``; ``files`` keeps ``<node>-<stamp>`` / ``<node>-latest``. A node id
ending in ``-<kind>`` is refused so the two namings can never collide.

Retention: after a successful publish the node's OWN releases of that kind older than
the newest N (``--keep`` / ``$AWSTORAGE_INVENTORY_KEEP``, default 5) are deleted --
never a ``-latest`` pointer, never another node's or kind's release, never a tag that
does not match the exact ``<node>[-<kind>]-<stamp>`` shape. A failed listing deletes
nothing; the publish result's ``retention`` names what was pruned.

Exit 0 done, 1 REFUSED (the refusal is the answer), 2 could not run.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import __version__
from . import files as _files
from .identity import _NODE_RE, whoami

DEFAULT_REPO = "Aitherium/inventory"
REPO_ENV = "AWSTORAGE_INVENTORY_REPO"
CACHE_ENV = "AWSTORAGE_INVENTORY_CACHE"
ANNOUNCE_ENV = "AWSTORAGE_INVENTORY_ANNOUNCE"
KEEP_ENV = "AWSTORAGE_INVENTORY_KEEP"
DEFAULT_KEEP = 5
FORMAT = "awstorage-inventory/1"
MANIFEST_NAME = "inventory.json"
POINTER_NAME = "latest.json"
SEAL_NAME = "awseal.json"
_STAMP = "%Y%m%dT%H%M%SZ"
_STAMP_RE = r"\d{8}T\d{6}Z"
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class InventoryError(Exception):
    """Could not run (exit 2)."""

    code = 2


class RefusedError(InventoryError):
    """The answer is no (exit 1): untrusted, tampered, public, mismatched."""

    code = 1


# ---------------------------------------------------------------------------
# kinds -- the seam for hardware / software / services
# ---------------------------------------------------------------------------

@dataclass
class Kind:
    """One inventory kind. ``export(src, node, out_path) -> stats`` writes the artifact
    file (uncompressed) and returns at least ``rows`` and ``scanned_at``;
    ``merge(artifact_path, node, cache_dir) -> None`` folds a VERIFIED artifact into the
    local cache; ``query_index(cache_dir) -> path`` names what queries read."""

    name: str
    schema_version: int
    artifact: str
    export: Callable[[Path, str, Path], dict]
    merge: Callable[[Path, str, Path], None]
    query_index: Callable[[Path], Path]
    extra: dict = field(default_factory=dict)


KINDS: dict[str, Kind] = {}


def register_kind(kind: Kind) -> None:
    KINDS[kind.name] = kind


def _kind(name: str) -> Kind:
    k = KINDS.get(name)
    if k is None:
        raise InventoryError(f"unknown inventory kind {name!r} (known: {sorted(KINDS)})")
    return k


def _uri(p: Path, query: str = "") -> str:
    """A SQLite URI for a local path (``file:/D:/x`` on Windows, ``file:/x`` elsewhere)."""
    posix = Path(p).resolve().as_posix()
    return ("file:" + ("" if posix.startswith("/") else "/")
            + urllib.parse.quote(posix, safe="/:") + query)


def _ro_uri(p: Path) -> str:
    return _uri(p, "?mode=ro")


def _connect(p: Path) -> sqlite3.Connection:
    """A connection that may ATTACH by URI (read-only sources)."""
    return sqlite3.connect(_uri(p), uri=True, timeout=30)


def export_files(src: Path, node: str, out: Path) -> dict:
    """This node's rows of a files.db, into a fresh files.db with the SAME schema (so
    every ``files`` query runs on it unchanged). Hashes are dropped for sensitive/never
    rows; push bookkeeping (push_id, last_push_at, pushed_seq, tombstones) stays home."""
    if not Path(src).is_file():
        raise InventoryError(f"no file index at {src} -- run: awstorage files scan")
    out = Path(out)
    if out.exists():
        out.unlink()
    db = _connect(out)
    try:
        _files.ensure_schema(db)
        db.execute("ATTACH DATABASE ? AS src", (_ro_uri(Path(src)),))
        t = _files.PLATFORM_TENANT
        with db:
            db.execute(
                "INSERT INTO files(tenant, node, path, name, parent, bytes, mtime_ns, ext,"
                " mime, partial_hash, sha256, dev, ino, nlink, git_root, sensitive, never,"
                " seq, scanned_at, push_id)"
                " SELECT tenant, node, path, name, parent, bytes, mtime_ns, ext, mime,"
                " CASE WHEN sensitive OR never THEN NULL ELSE partial_hash END,"
                " CASE WHEN sensitive OR never THEN NULL ELSE sha256 END,"
                " dev, ino, nlink, git_root, sensitive, never, seq, scanned_at, NULL"
                " FROM src.files WHERE tenant = ? AND node = ?", (t, node))
            db.execute("INSERT INTO dirs SELECT * FROM src.dirs WHERE tenant = ? AND node = ?",
                       (t, node))
            db.execute(
                "INSERT INTO roots(tenant, node, root, files, bytes, scanned_at, hashed_pct,"
                " truncated, errors, last_push_at, pushed_seq, content_ingest)"
                " SELECT tenant, node, root, files, bytes, scanned_at, hashed_pct, truncated,"
                " errors, NULL, 0, 0 FROM src.roots WHERE tenant = ? AND node = ?", (t, node))
            db.execute("INSERT INTO node_volumes SELECT * FROM src.node_volumes"
                       " WHERE tenant = ? AND node = ?", (t, node))
            db.execute("UPDATE meta SET v = (SELECT CAST(COALESCE(MAX(seq), 0) AS TEXT)"
                       " FROM files) WHERE k = 'seq'")
        db.execute("DETACH DATABASE src")
        rows, nbytes = db.execute("SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM files"
                                  ).fetchone()
        if not rows:
            raise RefusedError(f"nothing indexed for node {node!r} in {src} -- run: awstorage"
                          " files scan (an empty inventory would overwrite a real one)")
        with db:
            _refresh_all_groups(db)
        scanned = db.execute("SELECT MAX(scanned_at) FROM roots").fetchone()[0]
        nroots = db.execute("SELECT COUNT(*) FROM roots").fetchone()[0]
        db.execute("PRAGMA journal_mode=DELETE")
    finally:
        db.close()
    return {"rows": int(rows), "indexed_bytes": int(nbytes), "roots": int(nroots),
            "scanned_at": scanned}


def _refresh_all_groups(db: sqlite3.Connection) -> None:
    t = _files.PLATFORM_TENANT
    db.execute("DELETE FROM dupe_groups WHERE tenant = ?", (t,))
    shas = [r[0] for r in db.execute(
        "SELECT sha256 FROM files WHERE tenant = ? AND sha256 IS NOT NULL"
        " GROUP BY sha256 HAVING COUNT(*) > 1", (t,))]
    _files._refresh_groups(db, t, shas)


def merge_files(artifact: Path, node: str, cache_dir: Path) -> None:
    """Replace ``node``'s rows in the shared cache index with a verified snapshot, so
    find/dupes see every pulled node at once (cross-node duplicates included)."""
    target = files_query_index(cache_dir)
    _files.open_index(target).close()          # create it with the files.db pragmas/schema
    db = _connect(target)
    try:
        db.execute("ATTACH DATABASE ? AS snap", (_ro_uri(artifact),))
        t = _files.PLATFORM_TENANT
        with db:
            for table in ("files", "dirs", "roots", "node_volumes"):
                db.execute(f"DELETE FROM {table} WHERE tenant = ? AND node = ?", (t, node))  # noqa: S608
            cols = ("tenant, node, path, name, parent, bytes, mtime_ns, ext, mime,"
                    " partial_hash, sha256, dev, ino, nlink, git_root, sensitive, never, seq,"
                    " scanned_at, push_id")
            db.execute(f"INSERT INTO files({cols}) SELECT {cols} FROM snap.files"  # noqa: S608
                       " WHERE tenant = ? AND node = ?", (t, node))
            for table in ("dirs", "roots", "node_volumes"):
                db.execute(f"INSERT INTO {table} SELECT * FROM snap.{table}"  # noqa: S608
                           " WHERE tenant = ? AND node = ?", (t, node))
            _refresh_all_groups(db)
        db.execute("DETACH DATABASE snap")
    finally:
        db.close()


def files_query_index(cache_dir: Path) -> Path:
    return Path(cache_dir) / "files.db"


register_kind(Kind(name="files", schema_version=1, artifact="files.db",
                   export=export_files, merge=merge_files, query_index=files_query_index))


def _register_host_kinds() -> None:
    from . import host_inventory as _hi  # noqa: PLC0415
    for name in _hi.KIND_NAMES:
        register_kind(Kind(name=name, schema_version=_hi.SCHEMA_VERSION,
                           artifact=f"{name}.json", export=_hi.make_export(name),
                           merge=_hi.make_merge(name),
                           query_index=lambda d, n=name: _hi.kind_cache_dir(d, n)))


_register_host_kinds()


def release_prefix(node: str, kind: str = "files") -> str:
    """``<node>-`` for files (the 0.9.0 naming, unchanged), ``<node>-<kind>-`` otherwise."""
    return f"{node}-" if kind == "files" else f"{node}-{kind}-"


def latest_tag(node: str, kind: str = "files") -> str:
    return release_prefix(node, kind) + "latest"


def _host_kind_suffixes() -> tuple[str, ...]:
    return tuple(f"-{n}" for n in KINDS if n != "files")


# ---------------------------------------------------------------------------
# GitHub, through awrtifact's gh layer
# ---------------------------------------------------------------------------

def _need(mod: str, extra: str = "inventory"):
    try:
        return __import__(mod, fromlist=["_"])
    except ImportError as exc:
        raise InventoryError(f"{mod} is not installed: pip install 'awstorage[{extra}]'"
                             f" ({exc})") from exc


class GitHub:
    """The handful of GitHub calls an inventory makes, all on awrtifact's ``gh`` module
    (the ``gh`` CLI, or the REST API with GH_TOKEN). Tests substitute a fake."""

    def __init__(self) -> None:
        self.gh = _need("awrtifact.gh")
        for fn in ("repo_private", "list_releases", "release_exists", "create_release",
                   "upload", "download_asset", "release_assets", "put_file"):
            if not hasattr(self.gh, fn):
                raise InventoryError(f"awrtifact.gh has no {fn}(): upgrade awrtifact")

    def repo_private(self, repo: str) -> bool | None:
        return self.gh.repo_private(repo)

    def list_releases(self, repo: str, prefix: str = "") -> list[str]:
        return list(self.gh.list_releases(repo, prefix))

    def release_exists(self, repo: str, tag: str) -> bool:
        return bool(self.gh.release_exists(repo, tag))

    def create_release(self, repo: str, tag: str, title: str, notes: str) -> None:
        self.gh.create_release(repo, tag, title, notes)

    def upload(self, repo: str, tag: str, path: Path) -> None:
        self.gh.upload(repo, tag, str(path))

    def download(self, repo: str, tag: str, name: str, dest: Path) -> int:
        return int(self.gh.download_asset(repo, tag, name, str(dest)))

    def assets(self, repo: str, tag: str) -> set[str]:
        return set(self.gh.release_assets(repo, tag))

    def get_file(self, repo: str, path: str) -> str | None:
        if self.gh.backend() == "api":
            from awrtifact import ghapi  # noqa: PLC0415
            got = ghapi.get_file(repo, path)
            return None if got is None else got["content"].decode("utf-8")
        proc = self.gh._run(["api", f"repos/{repo}/contents/{path}",
                             "-H", "Accept: application/vnd.github.raw"])
        if proc.returncode == 0:
            return proc.stdout
        if "404" in proc.stderr or "Not Found" in proc.stderr:
            return None
        raise InventoryError(f"gh api contents/{path}: {proc.stderr.strip()}")

    def put_file(self, repo: str, path: str, content: str, message: str) -> str:
        return str(self.gh.put_file(repo, path, content, message))

    def delete_release(self, repo: str, tag: str) -> None:
        """Delete one release AND its tag (retention). Raises on failure."""
        if self.gh.backend() == "api":
            from awrtifact import ghapi  # noqa: PLC0415
            rel = ghapi._release(repo, tag)  # noqa: SLF001 - awrtifact has no delete yet
            if rel is None:
                return
            ghapi._request("DELETE", f"{ghapi.API}/repos/{repo}/releases/{rel['id']}")  # noqa: SLF001
            try:
                ghapi._request("DELETE", f"{ghapi.API}/repos/{repo}/git/refs/tags/"  # noqa: SLF001
                               + urllib.parse.quote(tag))
            except ghapi.GhApiError as exc:
                if exc.status not in (404, 422):
                    raise
            return
        proc = self.gh._run(["release", "delete", tag, "--repo", repo, "--yes",  # noqa: SLF001
                             "--cleanup-tag"])
        if proc.returncode != 0:
            raise InventoryError(f"gh release delete {tag}: {proc.stderr.strip()}")


# ---------------------------------------------------------------------------
# keys + trust
# ---------------------------------------------------------------------------

def _check_node(node: str) -> str:
    if (not node or not _NODE_RE.match(node) or node.endswith("-latest")
            or node.endswith(_host_kind_suffixes())):
        raise InventoryError(f"not a usable node id for a release tag: {node!r} (it may not"
                             f" end in -latest or -<kind>)")
    return node


def _check_repo(repo: str) -> str:
    if not _REPO_RE.match(repo or ""):
        raise InventoryError(f"repo must be OWNER/NAME: {repo!r}")
    return repo


def key_path_for(path: str | None) -> Path | None:
    return Path(path) if path else None


def default_key_path() -> Path:
    """awseal's key location, resolved NOW (``AWSEAL_KEY_PATH``, else
    ``~/.aither/awseal/signing.key``) -- awseal resolves its default at import time."""
    env = os.environ.get("AWSEAL_KEY_PATH")
    return Path(env) if env else Path.home() / ".aither" / "awseal" / "signing.key"


def ensure_key(key_path: Path | None = None) -> tuple[Path, bool]:
    """(key path, created). Local only -- no network. ``files schedule`` (run by
    ``adk pair`` / ``adk enroll``) calls this so every enrolled node can sign."""
    aw = _need("awseal")
    kp = key_path or default_key_path()
    if kp.is_file():
        return kp, False
    aw.keygen(kp)
    return kp, True


def own_public_key(key_path: Path | None = None) -> str:
    aw = _need("awseal")
    try:
        return aw.public_key_hex(path=key_path)
    except aw.SealError as exc:
        raise RefusedError(f"no awseal signing key for this node ({exc}) -- run: awstorage"
                      " inventory enroll") from exc


def pub_path(node: str) -> str:
    return f"nodes/{node}.pub"


def _clean_key(text: str | None) -> str | None:
    if text is None:
        return None
    k = text.strip().lower()
    return k if re.fullmatch(r"[0-9a-f]{64}", k) else ""


def enroll(node: str, repo: str, gh: Any, *, key_path: Path | None = None,
           create_key: bool = True) -> dict:
    """Make sure this node HAS an awseal key and that ``nodes/<node>.pub`` in the repo
    names it. Refuses when the repo already pins a DIFFERENT key (a rotation is a
    deliberate commit by a person, never a side effect of a publish)."""
    _check_node(node)
    _check_repo(repo)
    kp = key_path or default_key_path()
    if not kp.is_file() and not create_key:
        raise RefusedError(f"no awseal signing key at {kp} -- run: awstorage inventory enroll")
    kp, created_key = ensure_key(kp)
    mine = own_public_key(kp)
    registered = _clean_key(gh.get_file(repo, pub_path(node)))
    state = "present"
    if registered is None:
        state = gh.put_file(repo, pub_path(node), mine + "\n",
                            f"inventory: register {node}'s awseal key")
        registered = _clean_key(gh.get_file(repo, pub_path(node)))
    if registered != mine:
        raise RefusedError(f"{pub_path(node)} in {repo} names key {str(registered)[:16]}..., this"
                      f" node signs with {mine[:16]}... -- refusing to publish under a key"
                      " the registry does not name (rotate by committing the new key)")
    return {"node": node, "repo": repo, "public_key": mine, "registry": pub_path(node),
            "registry_state": state, "created_key": created_key, "key_path": str(kp)}


def cache_root() -> Path:
    env = os.environ.get(CACHE_ENV)
    return Path(env) if env else _files.default_catalog_path().parent / "inventory"


def _pin_file(node: str) -> Path:
    return cache_root() / "trust" / f"{node}.pub"


def trusted_key(node: str, repo: str, gh: Any, *, key: str | None = None,
                accept_key_change: bool = False) -> tuple[str, str]:
    """(key hex, where it came from). Unknown or changed keys are REFUSED."""
    if key:
        k = _clean_key(key)
        if not k:
            raise RefusedError(f"--key is not a 64-hex Ed25519 public key: {key!r}")
        return k, "--key"
    k = _clean_key(gh.get_file(repo, pub_path(node)))
    if k is None:
        raise RefusedError(f"unknown key: {repo} has no {pub_path(node)} -- refusing an"
                      " inventory nobody vouches for")
    if not k:
        raise RefusedError(f"{pub_path(node)} in {repo} is not a 64-hex Ed25519 public key")
    pin = _pin_file(node)
    if pin.is_file():
        pinned = _clean_key(pin.read_text(encoding="utf-8"))
        if pinned and pinned != k and not accept_key_change:
            raise RefusedError(f"{pub_path(node)} changed since this machine first trusted it"
                          f" ({pinned[:16]}... -> {k[:16]}...); pass --accept-key-change"
                          " only if the node really rotated its key")
    return k, f"{repo}:{pub_path(node)}"


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------

def _sha256(p: Path) -> str:
    from awrtifact.hashes import sha256_file  # noqa: PLC0415
    return sha256_file(p)


def announce(text: str, channel: str = "#agents",
             run: Callable[..., Any] | None = None) -> str:
    """One awrelay line. Best-effort: the answer is a status string, never an exception."""
    if (os.environ.get(ANNOUNCE_ENV) or "1").strip() in ("0", "false", "no", "off"):
        return "disabled"
    exe = shutil.which("awrelay")
    if not exe and run is None:
        return "skipped: awrelay not installed"
    try:
        proc = (run or subprocess.run)([exe or "awrelay", "send", channel, text,
                                        "--kind", "finding"], capture_output=True,
                                       text=True, timeout=20, check=False)
        return "sent" if proc.returncode == 0 else f"failed: exit {proc.returncode}"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"failed: {exc}"


def keep_count(keep: int | str | None = None) -> int:
    """How many stamped releases retention keeps: ``keep``, else ``$AWSTORAGE_INVENTORY_KEEP``,
    else 5. Never below 1 -- the release just published always survives."""
    raw = keep if keep is not None else os.environ.get(KEEP_ENV)
    try:
        n = int(str(raw).strip()) if raw is not None and str(raw).strip() else DEFAULT_KEEP
    except ValueError:
        n = DEFAULT_KEEP
    return max(1, n)


def stamped_releases(tags: list[str], node: str, kind: str = "files") -> list[tuple[str, str]]:
    """[(stamp, tag)] oldest first: ONLY tags that are exactly ``<prefix><stamp>``."""
    pat = re.compile("^" + re.escape(release_prefix(node, kind)) + "(" + _STAMP_RE + ")$")
    return sorted((m.group(1), t) for t in tags if (m := pat.match(t)))


def prune(*, node: str, repo: str, gh: Any, kind: str = "files", keep: int | None = None,
          protect: str | None = None) -> dict:
    """Delete ``node``'s own ``kind`` releases older than the newest ``keep``. A listing
    that fails deletes NOTHING; a delete that fails is reported and the rest go on."""
    n = keep_count(keep)
    try:
        tags = list(gh.list_releases(repo, release_prefix(node, kind)))
    except Exception as exc:  # noqa: BLE001 - no listing, no deletion
        return {"keep": n, "pruned": [], "failed": [],
                "error": f"listing failed, nothing deleted: {type(exc).__name__}: {exc}"[:300]}
    stamped = stamped_releases(tags, node, kind)
    doomed = [t for _, t in stamped[:-n]] if len(stamped) > n else []
    doomed = [t for t in doomed if t not in (protect, latest_tag(node, kind))]
    pruned, failed = [], []
    for t in doomed:
        try:
            gh.delete_release(repo, t)
            pruned.append(t)
        except Exception as exc:  # noqa: BLE001 - one stuck release never stops the rest
            failed.append({"release": t, "error": f"{type(exc).__name__}: {exc}"[:200]})
    return {"keep": n, "pruned": pruned, "failed": failed,
            "kept": [t for _, t in stamped if t not in pruned]}


def publish(*, node: str, repo: str, src: Path, gh: Any, kind: str = "files",
            key_path: Path | None = None, allow_public: bool = False,
            work: Path | None = None, part_size: int | None = None,
            announce_channel: str | None = "#agents",
            announcer: Callable[[str, str], str] | None = None,
            now: float | None = None, keep: int | None = None) -> dict:
    _check_node(node)
    _check_repo(repo)
    k = _kind(kind)
    aw = _need("awseal")
    split = _need("awrtifact.split")
    from awrtifact.manifest import DEFAULT_PART_SIZE  # noqa: PLC0415
    from awrtifact.manifest import write as write_manifest  # noqa: PLC0415

    private = gh.repo_private(repo)
    if private is None:
        raise InventoryError(f"{repo} does not exist (or this credential cannot see it)")
    if private is not True and not allow_public:
        raise RefusedError(f"{repo} is NOT private: an inventory names every path on this node;"
                      " pass --allow-public only if that is really meant")
    key_path = key_path or default_key_path()
    reg = enroll(node, repo, gh, key_path=key_path, create_key=False)

    stamp = time.strftime(_STAMP, time.gmtime(now if now is not None else time.time()))
    tag = release_prefix(node, k.name) + stamp
    base = Path(work) if work else Path(src).parent / "tmp"
    base.mkdir(parents=True, exist_ok=True)
    wd = Path(tempfile.mkdtemp(prefix=f"inventory-{stamp}-", dir=str(base)))
    try:
        sealed, parts = wd / "sealed", wd / "parts"
        sealed.mkdir()
        raw = wd / k.artifact
        stats = k.export(Path(src), node, raw)
        gz = sealed / (k.artifact + ".gz")
        with open(raw, "rb") as fi, gzip.open(gz, "wb", compresslevel=6) as fo:
            shutil.copyfileobj(fi, fo, 1 << 20)
        raw.unlink()
        manifest = {"format": FORMAT, "node": node, "kind": k.name,
                    "schema_version": k.schema_version, "release": tag,
                    "created": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime(now if now is not None
                                                         else time.time())),
                    "artifact": gz.name, "artifact_bytes": gz.stat().st_size,
                    "awstorage": __version__, **stats}
        (sealed / MANIFEST_NAME).write_text(json.dumps(manifest, indent=1, sort_keys=True),
                                            encoding="utf-8")
        seal = aw.sign(sealed, key_path=key_path, subject=f"inventory:{node}:{k.name}",
                       meta={"node": node, "kind": k.name, "release": tag})
        if seal.public_key != reg["public_key"]:
            raise RefusedError("the key that signed is not the key the registry names")
        aw.write(seal, sealed)
        split_manifest = split.split_file(gz, part_size or DEFAULT_PART_SIZE, parts)
        write_manifest(split_manifest, parts / f"{gz.name}.manifest.json")

        if gh.release_exists(repo, tag):
            raise RefusedError(f"release {tag} already exists in {repo}")
        gh.create_release(repo, tag, f"{node} {k.name} inventory {stamp}",
                          f"{stats['rows']} rows, scanned {stats.get('scanned_at')};"
                          f" sealed by awseal key {reg['public_key'][:16]}...")
        for p in split_manifest["parts"]:
            gh.upload(repo, tag, parts / p["name"])
        gh.upload(repo, tag, parts / f"{gz.name}.manifest.json")
        gh.upload(repo, tag, sealed / MANIFEST_NAME)
        gh.upload(repo, tag, sealed / SEAL_NAME)          # last: no seal, no inventory

        latest = latest_tag(node, k.name)
        if not gh.release_exists(repo, latest):
            gh.create_release(repo, latest, f"{node} latest {k.name} inventory",
                              "Pointer only: latest.json names the newest release.")
        ptr = wd / POINTER_NAME
        ptr.write_text(json.dumps({"node": node, "release": tag, "kind": k.name,
                                   "rows": stats["rows"], "created": manifest["created"]},
                                  indent=1), encoding="utf-8")
        gh.upload(repo, latest, ptr)
    finally:
        shutil.rmtree(wd, ignore_errors=True)

    retention = prune(node=node, repo=repo, gh=gh, kind=k.name, keep=keep, protect=tag)
    text = (f"{node} published inventory kind={k.name} rows={stats['rows']}"
            f" release={tag}")
    relay = "disabled"
    if announce_channel:
        try:
            relay = (announcer or announce)(text, announce_channel)
        except Exception as exc:  # noqa: BLE001 - an announcement never fails a publish
            relay = f"failed: {exc}"
    return {"ok": True, "node": node, "repo": repo, "release": tag, "kind": k.name,
            "rows": stats["rows"], "artifact_bytes": manifest["artifact_bytes"],
            "parts": len(split_manifest["parts"]), "public_key": reg["public_key"],
            "registry_state": reg["registry_state"], "announce": relay,
            "retention": retention}


# ---------------------------------------------------------------------------
# pull
# ---------------------------------------------------------------------------

def newest_release(tags: list[str], node: str, kind: str = "files") -> str | None:
    stamped = stamped_releases(tags, node, kind)
    return stamped[-1][1] if stamped else None


def remote_nodes(tags: list[str], kind: str = "files") -> dict[str, str]:
    """{node: newest ``kind`` release} from a release list."""
    out: dict[str, str] = {}
    mid = "" if kind == "files" else "-" + re.escape(kind)
    pat = re.compile("^(.+)" + mid + "-(" + _STAMP_RE + ")$")
    others = _host_kind_suffixes()
    for t in tags:
        m = pat.match(t)
        if not m or (kind == "files" and m.group(1).endswith(others)):
            continue
        if m.group(1) not in out or out[m.group(1)] < t:
            out[m.group(1)] = t
    return out


def pull(*, node: str, repo: str, gh: Any, key: str | None = None,
         accept_key_change: bool = False, release: str | None = None,
         kind: str = "files") -> dict:
    _check_node(node)
    _check_repo(repo)
    wanted = _kind(kind)
    aw = _need("awseal")
    from awrtifact import manifest as split_manifest_mod  # noqa: PLC0415

    tag = release or newest_release(gh.list_releases(repo, release_prefix(node, wanted.name)),
                                    node, wanted.name)
    if not tag:
        raise InventoryError(f"no {wanted.name} inventory published for {node!r} in {repo}")
    trusted, key_src = trusted_key(node, repo, gh, key=key,
                                   accept_key_change=accept_key_change)
    root = cache_root()
    root.mkdir(parents=True, exist_ok=True)
    wd = Path(tempfile.mkdtemp(prefix=f"pull-{node}-", dir=str(root)))
    try:
        sealed, parts = wd / "sealed", wd / "parts"
        sealed.mkdir()
        parts.mkdir()
        have = gh.assets(repo, tag)
        if SEAL_NAME not in have:
            raise RefusedError(f"{tag} carries no {SEAL_NAME}: an unsealed inventory is refused")
        gh.download(repo, tag, SEAL_NAME, sealed / SEAL_NAME)
        gh.download(repo, tag, MANIFEST_NAME, sealed / MANIFEST_NAME)
        try:
            man = json.loads((sealed / MANIFEST_NAME).read_text(encoding="utf-8"))
        except ValueError as exc:
            raise RefusedError(f"{tag}/{MANIFEST_NAME} is not JSON: {exc}") from exc
        art = str(man.get("artifact") or "")
        if not art or "/" in art or "\\" in art or art in (SEAL_NAME, MANIFEST_NAME):
            raise RefusedError(f"{tag}/{MANIFEST_NAME} names no usable artifact")
        smn = f"{art}.manifest.json"
        gh.download(repo, tag, smn, parts / smn)
        try:
            sm = split_manifest_mod.load(parts / smn)
        except ValueError as exc:
            raise RefusedError(f"{tag}/{smn}: {exc}") from exc
        if sm["name"] != art:
            raise RefusedError(f"{smn} describes {sm['name']!r}, not {art!r}")
        with open(sealed / art, "wb") as out:
            for p in sm["parts"]:
                dest = parts / p["name"]
                gh.download(repo, tag, p["name"], dest)
                if dest.stat().st_size != p["size"] or _sha256(dest) != p["sha256"]:
                    raise RefusedError(f"{tag}/{p['name']} does not match its manifest")
                with open(dest, "rb") as fi:
                    shutil.copyfileobj(fi, out, 1 << 20)
                dest.unlink()
        verdict = aw.verify(sealed, expect_key=trusted)
        if not (verdict.get("ok") and verdict.get("signature_ok")
                and verdict.get("content_ok") and verdict.get("key_trusted") is True):
            why = ("key not trusted" if verdict.get("key_trusted") is not True else
                   "bad signature" if not verdict.get("signature_ok") else
                   f"content changed {verdict.get('diff')}")
            raise RefusedError(f"{tag} FAILED verification ({why}); nothing was cached")
        seal = aw.load(sealed)
        if set(seal.files) != {art, MANIFEST_NAME}:
            raise RefusedError(f"{tag}: the seal covers {sorted(seal.files)}, not the artifact"
                          " and its manifest")
        meta = dict(seal.meta or {})
        for fld, want in (("node", node), ("release", tag)):
            if man.get(fld) != want or meta.get(fld) != want:
                raise RefusedError(f"{tag}: signed {fld} is {man.get(fld)!r}/{meta.get(fld)!r},"
                              f" expected {want!r}")
        k = _kind(str(man.get("kind") or ""))
        if k.name != wanted.name:
            raise RefusedError(f"{tag}: signed kind is {k.name!r}, expected {wanted.name!r}")
        if man.get("format") != FORMAT or meta.get("kind") != k.name:
            raise RefusedError(f"{tag}: unsupported format {man.get('format')!r}")
        if int(man.get("schema_version") or 0) > k.schema_version:
            raise InventoryError(f"{tag} is {k.name} schema {man.get('schema_version')}; this"
                                 f" awstorage reads <= {k.schema_version}: upgrade")
        raw = wd / k.artifact
        with gzip.open(sealed / art, "rb") as fi, open(raw, "wb") as fo:
            shutil.copyfileobj(fi, fo, 1 << 20)
        k.merge(raw, node, root)
        nd = root / "nodes" / node
        if k.name != "files":
            nd = nd / k.name
        nd.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sealed / MANIFEST_NAME, nd / MANIFEST_NAME)
        shutil.copyfile(sealed / SEAL_NAME, nd / SEAL_NAME)
        rec = {"node": node, "repo": repo, "release": tag, "kind": k.name,
               "rows": man.get("rows"), "scanned_at": man.get("scanned_at"),
               "public_key": trusted, "key_source": key_src,
               "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        (nd / "pulled.json").write_text(json.dumps(rec, indent=1), encoding="utf-8")
        pin = _pin_file(node)
        if key_src != "--key":
            pin.parent.mkdir(parents=True, exist_ok=True)
            pin.write_text(trusted + "\n", encoding="utf-8")
    finally:
        shutil.rmtree(wd, ignore_errors=True)
    return {"ok": True, **rec}


def cached_nodes() -> list[dict]:
    out = []
    d = cache_root() / "nodes"
    if d.is_dir():
        for nd in sorted(d.iterdir()):
            try:
                out.append(json.loads((nd / "pulled.json").read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
    return out


def cached_kinds(node: str) -> list[str]:
    """The non-files kinds pulled (verified) for ``node``."""
    d = cache_root() / "nodes" / node
    return sorted(k for k in KINDS if k != "files" and (d / k / "pulled.json").is_file())


def cached_index(node: str | None = None, kind: str = "files") -> Path | None:
    """The cache index holding ``node`` (any pulled node when None), or None."""
    p = _kind(kind).query_index(cache_root())
    if not p.is_file():
        return None
    if node is None:
        return p
    return p if (cache_root() / "nodes" / node / "pulled.json").is_file() else None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

VERBS = ("publish", "pull", "query", "nodes", "enroll")


def _default_repo(a) -> str:
    return getattr(a, "repo", None) or os.environ.get(REPO_ENV) or DEFAULT_REPO


def _src_index(a) -> Path:
    return Path(a.index) if a.index else _files.default_index_path(a.catalog)


def _emit(a, res: dict, line: str) -> None:
    print(json.dumps(res, indent=1) if getattr(a, "json", False) else line)


def _run(fn: Callable[[], int]) -> int:
    try:
        return fn()
    except InventoryError as exc:
        print(("REFUSED: " if exc.code == 1 else "cannot run: ") + str(exc), file=sys.stderr)
        return exc.code


def main(argv: list[str], gh_factory: Callable[[], Any] = GitHub) -> int:
    if argv[:1] == ["query"]:
        return _query(argv[1:])
    ap = argparse.ArgumentParser(prog="awstorage inventory",
                                 description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="verb", required=True)

    def common(p) -> None:
        p.add_argument("--repo", help=f"OWNER/NAME (default ${REPO_ENV} or {DEFAULT_REPO})")
        p.add_argument("--json", action="store_true")

    pb = sub.add_parser("publish", help="export, seal and upload this node's inventory")
    pb.add_argument("--kind", default="files", choices=sorted(KINDS))
    pb.add_argument("--node", help="default: awstorage whoami (the registered id)")
    pb.add_argument("--catalog")
    pb.add_argument("--index", help="files.db to export (default: next to the catalog)")
    pb.add_argument("--key", help="awseal private key file (default: awseal's)")
    pb.add_argument("--allow-public", action="store_true",
                    help="publish to a repo that is not private (paths become public)")
    pb.add_argument("--work", help="scratch dir (default: beside the index)")
    pb.add_argument("--part-size", type=int)
    pb.add_argument("--keep", type=int,
                    help=f"stamped releases of this node+kind to keep (default ${KEEP_ENV}"
                         f" or {DEFAULT_KEEP})")
    pb.add_argument("--announce-channel", default="#agents")
    pb.add_argument("--no-announce", action="store_true")
    common(pb)

    pl = sub.add_parser("pull", help="fetch, verify and cache other nodes' inventories")
    pl.add_argument("node", nargs="*")
    pl.add_argument("--all", action="store_true", help="every node in the repo")
    pl.add_argument("--key", help="trust exactly this public key (hex) for the node")
    pl.add_argument("--release", help="a specific release instead of the newest")
    pl.add_argument("--accept-key-change", action="store_true")
    pl.add_argument("--kind", default="files", choices=sorted(KINDS))
    common(pl)

    nd = sub.add_parser("nodes", help="pulled inventories (or --remote: what the repo has)")
    nd.add_argument("--remote", action="store_true")
    nd.add_argument("--kind", default="files", choices=sorted(KINDS))
    common(nd)

    en = sub.add_parser("enroll", help="create the awseal key if missing; commit"
                                       " nodes/<node>.pub")
    en.add_argument("--node")
    en.add_argument("--key")
    common(en)

    a = ap.parse_args(argv)
    return _run(lambda: _dispatch(a, gh_factory))


def _dispatch(a, gh_factory) -> int:
    repo = _default_repo(a)
    if a.verb == "nodes" and not a.remote:
        rows = cached_nodes()
        for r in rows:
            r["kinds"] = cached_kinds(r["node"])
        if a.json:
            print(json.dumps({"nodes": rows}, indent=1))
        for r in [] if a.json else rows:
            print(f"{r['node']:<20} {r.get('rows')} rows  {r['release']}  verified"
                  f" {r['verified_at']}  key {r['public_key'][:16]}... ({r['key_source']})"
                  + (f"  +{','.join(r['kinds'])}" if r["kinds"] else ""))
        if not rows and not a.json:
            print("no inventories pulled yet -- run: awstorage inventory pull --all")
        return 0
    gh = gh_factory()
    if a.verb == "nodes":
        latest = remote_nodes(gh.list_releases(repo, ""), a.kind)
        _emit(a, {"repo": repo, "kind": a.kind, "nodes": latest},
              "\n".join(f"{n:<20} {t}" for n, t in sorted(latest.items()))
              or f"{repo} has no {a.kind} inventories")
        return 0
    if a.verb == "enroll":
        res = enroll(_check_node(a.node or whoami()), repo, gh, key_path=key_path_for(a.key))
        _emit(a, res, f"{res['node']}: key {res['public_key'][:16]}... registered at"
                      f" {repo}:{res['registry']} ({res['registry_state']})")
        return 0
    if a.verb == "publish":
        res = publish(node=a.node or whoami(), repo=repo, src=_src_index(a), gh=gh,
                      kind=a.kind, key_path=key_path_for(a.key), allow_public=a.allow_public,
                      work=Path(a.work) if a.work else None, part_size=a.part_size,
                      announce_channel=None if a.no_announce else a.announce_channel,
                      keep=a.keep)
        ret = res["retention"]
        _emit(a, res, f"published {res['node']} {res['kind']}: {res['rows']} rows ->"
                      f" {repo}@{res['release']} ({res['parts']} part(s),"
                      f" {res['artifact_bytes']} bytes; relay {res['announce']});"
                      f" retention keep {ret['keep']}: pruned {len(ret['pruned'])}"
                      + (f" ({', '.join(ret['pruned'])})" if ret["pruned"] else "")
                      + (f"; {ret['error']}" if ret.get("error") else "")
                      + (f"; {len(ret['failed'])} delete(s) failed" if ret["failed"] else ""))
        return 0
    nodes = list(a.node or [])
    if a.all:
        nodes += sorted(remote_nodes(gh.list_releases(repo, ""), a.kind))
    if not nodes:
        raise InventoryError("name a node or pass --all")
    if a.key and len(nodes) != 1:
        raise InventoryError("--key trusts ONE node's key: name exactly one node")
    results, rc = [], 0
    for n in dict.fromkeys(nodes):
        try:
            r = pull(node=n, repo=repo, gh=gh, key=a.key, release=a.release,
                     accept_key_change=a.accept_key_change, kind=a.kind)
            if not a.json:
                print(f"verified {n} {a.kind}: {r['rows']} rows from {r['release']}"
                      f" (key {r['public_key'][:16]}... via {r['key_source']})")
        except InventoryError as exc:
            r = {"ok": False, "node": n, "error": str(exc), "refused": exc.code == 1}
            rc = max(rc, exc.code)
            if not a.json:
                print(("REFUSED " if exc.code == 1 else "FAILED ") + f"{n}: {exc}",
                      file=sys.stderr)
        results.append(r)
    if a.json:
        print(json.dumps({"results": results}, indent=1))
    return rc


def _query(rest: list[str]) -> int:
    """``inventory query tree|find|dupes ...`` = ``files <verb> ...`` against the
    verified cache: the same code and the same output as the local index."""
    if rest[:1] == ["show"]:
        return _query_show(rest[1:])
    if not rest or rest[0] not in ("tree", "find", "dupes"):
        print("usage: awstorage inventory query tree|find|dupes [files args...] [--node ID]\n"
              "       awstorage inventory query show <node> [--kind K] [--json]",
              file=sys.stderr)
        return 2
    idx = cached_index()
    if idx is None:
        print("no inventories pulled yet -- run: awstorage inventory pull <node>|--all",
              file=sys.stderr)
        return 2
    from .cli import main as cli_main  # noqa: PLC0415
    return int(cli_main(["files", rest[0], *rest[1:], "--index", str(idx), "--local"]))


def _query_show(rest: list[str]) -> int:
    """``inventory query show <node> [--kind hardware|software|services] [--json]``: the
    verified, pulled host documents for a node (every pulled kind when --kind is absent)."""
    from . import host_inventory as _hi  # noqa: PLC0415
    ap = argparse.ArgumentParser(prog="awstorage inventory query show")
    ap.add_argument("node")
    ap.add_argument("--kind", choices=list(_hi.KIND_NAMES))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(rest)
    kinds = [a.kind] if a.kind else list(_hi.KIND_NAMES)
    docs = {k: d for k in kinds
            if (d := _hi.cached_doc(cache_root(), k, a.node)) is not None}
    if not docs:
        want = a.kind or "hardware|software|services"
        print(f"no {want} inventory pulled for {a.node!r} -- run: awstorage inventory pull"
              f" {a.node} --kind {a.kind or 'hardware'}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(docs[a.kind] if a.kind else docs, indent=1))
    else:
        print("\n".join(_hi.render(d) for d in docs.values()))
    return 0
