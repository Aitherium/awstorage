"""Offload: move a cold tree OFF this machine into S3, verified, with a stub that
brings it back.

Written 2026-10-22, the day E: fell to 3 GB free and nearly took the fleet's vhdx
with it. ``relocate`` moves bytes between local drives; when every local drive is
short, the bytes have to leave the box. This is the verb that does it::

    awstorage offload <path> --to strata-cold            # upload, verify, delete
    awstorage offload <root> [<root> ...] --dry-run      # rank candidates, act on none
    awstorage restore <path> [--file REL] [--to DIR]     # bring it back, sha256-checked
    awstorage restore --list                             # every offload this node made

The contract, in order, PER FILE (a crash anywhere leaves the local copy or a stub
line that can restore it -- never neither):

1. **upload** -- one ``put_object`` below the part size, else a multipart upload whose
   upload id is JOURNALED, so a re-run lists the parts S3 already holds and re-sends
   only the missing ones (resume). Every part carries its SHA-256, which S3 checks on
   receipt and rejects on mismatch.
2. **verify** -- ``get_object_attributes`` reads back the checksum S3 computed over the
   bytes it STORED: the full-object SHA-256 for a single put, the composite
   ``sha256(part digests)-N`` for multipart. It must equal the value computed locally
   from the same buffers that produced the file's whole sha256, and the stored size must
   equal the local size. ``--verify full`` re-downloads the object and hashes it
   instead (costs egress). The file must also be unchanged (size, mtime) since it was
   read.
3. **record** -- one JSON line appended (and fsynced) to the stub before anything is
   deleted: ``<dir>/AWOFFLOADED.jsonl`` for a directory, ``<file>.awoffload.jsonl`` for
   a file. A copy of the stub goes to ``~/.aither/storage/offload/manifests`` and to the
   bucket under ``<prefix>manifests/``, so losing the local disk loses nothing.
4. **delete** -- only now.

Refused outright (the whole call, before a byte moves): the guards' never set
(credential paths, live state, Library data, postgres/WAL, VM disks, OS trees), the
topology's ``relocate_do_not_move`` roots, live WSL/engine disks, database files, and
anything that reads as tenant or customer data -- tenant files have their own
customer-keyed path and never land in a platform bucket.

boto3 is imported lazily and only by the verbs that talk to S3; the rest of awstorage
stays stdlib-only. Exit codes as everywhere: 0 ok, 1 refused / failed, 2 could not
judge (no boto3, no credential, no target).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from ._fs import entry_is_link, is_link, walk_no_follow
from .guards import Guards, load_topology, norm
from .identity import whoami

MiB = 1024 * 1024
DEFAULT_PART = 64 * MiB
MAX_PARTS = 10000
#: GLACIER_IR bills every object as >= 128 KiB; smaller ones stay STANDARD.
SMALL_OBJECT = 128 * 1024
DEFAULT_CLASS = "GLACIER_IR"
STUB_DIR_NAME = "AWOFFLOADED.jsonl"
STUB_FILE_SUFFIX = ".awoffload.jsonl"
STUB_VERSION = 1

#: AWS list price, us-east-1, USD per GB-month (2026-10). For the dry-run estimate only.
PRICE_GB_MONTH = {"STANDARD": 0.023, "GLACIER_IR": 0.004}

#: Site roots come from the topology (``relocate_do_not_move`` + the guards' planes);
#: a real offload refuses to run without one. These markers apply everywhere.
BUILTIN_NEVER_ROOTS: Tuple[str, ...] = ()
#: Case-insensitive substrings of a normalized path that refuse it.
NEVER_CONTAINS = ("/wsl/", "tenant", "customer", "/tnt_", "/lockbox", "/library/")
NEVER_SUFFIXES = (".vhdx", ".vhd", ".avhdx", ".vmdk", ".qcow2", ".vdi", ".img",
                  ".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3",
                  ".sqlite-wal", ".sqlite-shm", ".sqlite-journal", ".mdf", ".ldf")
NEVER_FILE_NAMES = ("pg_version", "postmaster.pid")


class OffloadError(RuntimeError):
    """A refusal or a failure the caller must see."""


def _base_dir() -> Path:
    env = os.environ.get("AWSTORAGE_OFFLOAD_DIR")
    return Path(env) if env else Path.home() / ".aither" / "storage" / "offload"


def _b64(digest: bytes) -> str:
    return base64.b64encode(digest).decode("ascii")


def part_size_for(size: int, base: int = DEFAULT_PART) -> int:
    """The smallest power-of-two multiple of ``base`` that fits ``size`` in 10k parts."""
    ps = base
    while -(-size // ps) > MAX_PARTS:
        ps *= 2
    return ps


def storage_class_for(size: int, wanted: str) -> str:
    return "STANDARD" if (wanted == "GLACIER_IR" and size < SMALL_OBJECT) else wanted


# -- refusal ---------------------------------------------------------------------------


def refusal(path: str, guards: Optional[Guards] = None,
            extra_roots: Iterable[str] = ()) -> Optional[str]:
    """Why ``path`` must never be offloaded, or None."""
    p = norm(os.path.abspath(path))
    pl = p.lower()
    for r in (*BUILTIN_NEVER_ROOTS, *extra_roots):
        rl = norm(r).lower().rstrip("/")
        if pl == rl or pl.startswith(rl + "/") or rl.startswith(pl + "/"):
            return f"protected root {r} (live disk, deploy root or Library)"
    for m in NEVER_CONTAINS:
        if m in pl + "/":
            return f"path contains {m.strip('/')!r} (live state or tenant/customer data)"
    if pl.endswith(NEVER_SUFFIXES):
        return "VM disk or database file"
    if pl.rsplit("/", 1)[-1] in NEVER_FILE_NAMES:
        return "live database directory marker"
    if guards is not None:
        why = guards.refusal(p)
        if why:
            return why
    return None


def make_guards(topology: Optional[dict]) -> Tuple[Guards, List[str]]:
    extra = list((topology or {}).get("relocate_do_not_move") or [])
    return Guards(topology=topology, extra_roots=extra), extra


# -- target + client -------------------------------------------------------------------


def find_topology_path(explicit: Optional[str] = None) -> Optional[Path]:
    from .relocate import find_topology  # noqa: PLC0415 -- one lookup, shared

    return find_topology(explicit)


def resolve_target(name: str, topology: Optional[dict], *, bucket: Optional[str] = None,
                   region: Optional[str] = None, prefix: Optional[str] = None) -> dict:
    """``object_stores.<name>`` from storage-topology.yaml, flags overriding."""
    stores = (topology or {}).get("object_stores") or {}
    cfg = dict(stores.get(name) or {})
    if bucket:
        cfg["bucket"] = bucket
    if region:
        cfg["region"] = region
    if prefix is not None:
        cfg["prefix"] = prefix
    if not cfg.get("bucket"):
        raise OffloadError(f"no object store {name!r}: not in storage-topology.yaml "
                           "object_stores and no --bucket given")
    cfg.setdefault("region", "us-east-1")
    cfg.setdefault("offload_prefix", "offload/")
    if prefix is None:
        cfg["prefix"] = cfg.get("offload_prefix") or "offload/"
    cfg["name"] = name
    return cfg


def _vault_credentials(target: dict, topology_path: Optional[Path]) -> Optional[Tuple[str, str]]:
    """Read the target's credential pair from the AitherOS vault tool, when this runs
    inside a checkout that has one. Values are returned, never printed."""
    if topology_path is None:
        return None
    tools = topology_path.resolve().parent.parent / "dev" / "tools"
    if not (tools / "aither_secret.py").is_file():
        return None
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    try:
        import aither_secret  # type: ignore  # noqa: PLC0415
    except Exception:  # noqa: BLE001 -- an unimportable tool is "no vault here"
        return None
    for pair in target.get("credential_secrets") or []:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        key, _ = aither_secret.fetch(pair[0])
        sec, _ = aither_secret.fetch(pair[1])
        if key and sec:
            return key.strip(), sec.strip()
    return None


def make_s3_client(target: dict, topology_path: Optional[Path] = None, workers: int = 4):
    """A boto3 S3 client for the target. Raises ImportError without boto3 and
    OffloadError without a credential."""
    import boto3  # noqa: PLC0415 -- optional: only the S3 verbs need it
    import botocore.session  # noqa: PLC0415
    from botocore.config import Config  # noqa: PLC0415

    cfg = Config(signature_version="s3v4", retries={"max_attempts": 10, "mode": "adaptive"},
                 connect_timeout=10, read_timeout=300, max_pool_connections=workers + 4)
    kw: Dict[str, Any] = {"region_name": target["region"], "config": cfg}
    if target.get("endpoint"):
        kw["endpoint_url"] = target["endpoint"]
    creds = _vault_credentials(target, topology_path)
    if creds is None and botocore.session.get_session().get_credentials() is None:
        raise OffloadError("no AWS credential: the boto3 chain is empty and the vault "
                           f"served none of {target.get('credential_secrets')}")
    if creds is not None:
        kw["aws_access_key_id"], kw["aws_secret_access_key"] = creds
    return boto3.client("s3", **kw)


# -- upload ----------------------------------------------------------------------------


def _atomic_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj), encoding="utf-8")
    os.replace(tmp, path)


def _err_code(exc: BaseException) -> str:
    resp = getattr(exc, "response", None) or {}
    return str((resp.get("Error") or {}).get("Code") or "")


def _list_parts(client, bucket: str, key: str, upload_id: str) -> Dict[int, Tuple[str, str]]:
    out: Dict[int, Tuple[str, str]] = {}
    marker = 0
    while True:
        kw: Dict[str, Any] = {"Bucket": bucket, "Key": key, "UploadId": upload_id}
        if marker:
            kw["PartNumberMarker"] = marker
        r = client.list_parts(**kw)
        for p in r.get("Parts") or []:
            out[int(p["PartNumber"])] = (p["ETag"], p.get("ChecksumSHA256") or "")
        if not r.get("IsTruncated"):
            return out
        marker = int(r.get("NextPartNumberMarker") or 0)


def upload_file(client, bucket: str, key: str, path: str, *, storage_class: str,
                part_size: int, workers: int = 4, journal_dir: Optional[Path] = None,
                log: Callable[[str], None] = lambda _m: None) -> dict:
    """Upload one file. Returns {sha256, s3_checksum, parts, part_size, sent, skipped}.

    ``s3_checksum`` is the value S3 must report for the stored object: the base64
    full-object SHA-256 (single put) or ``<base64 composite>-<N>`` (multipart).
    """
    st = os.stat(path)
    size = st.st_size
    meta_base = {"part-size": str(part_size)}
    if size <= part_size:
        with open(path, "rb") as f:
            buf = f.read()
        digest = hashlib.sha256(buf).digest()
        client.put_object(Bucket=bucket, Key=key, Body=buf, ChecksumSHA256=_b64(digest),
                          StorageClass=storage_class,
                          Metadata={**meta_base, "sha256": digest.hex()})
        return {"sha256": digest.hex(), "s3_checksum": _b64(digest), "parts": 0,
                "part_size": part_size, "sent": 1, "skipped": 0}

    jdir = journal_dir or (_base_dir() / "journal")
    jpath = jdir / (hashlib.sha256(f"{bucket}/{key}".encode()).hexdigest()[:32] + ".json")
    upload_id: Optional[str] = None
    done: Dict[int, Tuple[str, str]] = {}
    if jpath.is_file():
        try:
            j = json.loads(jpath.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            j = {}
        if (j.get("key") == key and j.get("size") == size and j.get("part_size") == part_size
                and j.get("mtime_ns") == st.st_mtime_ns):
            upload_id = j.get("upload_id") or None
            try:
                if upload_id is None:
                    raise LookupError("journal has no upload id")
                done = _list_parts(client, bucket, key, upload_id)
                log(f"  resume {key}: {len(done)} part(s) already in S3")
            except Exception as exc:  # noqa: BLE001
                if not isinstance(exc, LookupError) and _err_code(exc) != "NoSuchUpload":
                    raise
                upload_id, done = None, {}
        elif j.get("upload_id"):
            try:
                client.abort_multipart_upload(Bucket=bucket, Key=j.get("key", key),
                                              UploadId=j["upload_id"])
            except Exception as exc:  # noqa: BLE001 -- lifecycle reaps it after 7 days
                log(f"  stale upload not aborted ({exc}); the 7-day lifecycle reaps it")
    if upload_id is None:
        r = client.create_multipart_upload(Bucket=bucket, Key=key, ChecksumAlgorithm="SHA256",
                                           StorageClass=storage_class, Metadata=meta_base)
        upload_id = r["UploadId"]
        _atomic_json(jpath, {"key": key, "bucket": bucket, "upload_id": upload_id,
                             "size": size, "part_size": part_size,
                             "mtime_ns": st.st_mtime_ns, "path": path})

    whole = hashlib.sha256()
    digests: List[bytes] = []
    parts: List[dict] = []
    sent = skipped = 0
    inflight: List[Tuple[int, str, Future]] = []

    def _drain(keep: int) -> None:
        nonlocal sent
        while len(inflight) > keep:
            n, b, fut = inflight.pop(0)
            r = fut.result()
            if r.get("ChecksumSHA256") and r["ChecksumSHA256"] != b:
                raise OffloadError(f"part {n} of {key}: S3 stored checksum "
                                   f"{r['ChecksumSHA256']} != sent {b}")
            parts.append({"PartNumber": n, "ETag": r["ETag"], "ChecksumSHA256": b})
            sent += 1

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex, open(path, "rb") as f:
        n = 0
        while True:
            buf = f.read(part_size)
            if not buf:
                break
            n += 1
            whole.update(buf)
            d = hashlib.sha256(buf).digest()
            digests.append(d)
            b = _b64(d)
            prev = done.get(n)
            if prev is not None and prev[1] == b:
                parts.append({"PartNumber": n, "ETag": prev[0], "ChecksumSHA256": b})
                skipped += 1
                continue
            inflight.append((n, b, ex.submit(
                client.upload_part, Bucket=bucket, Key=key, UploadId=upload_id,
                PartNumber=n, Body=buf, ChecksumSHA256=b)))
            _drain(max(1, workers) * 2)
        _drain(0)
    parts.sort(key=lambda p: p["PartNumber"])
    client.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id,
                                     MultipartUpload={"Parts": parts})
    try:
        jpath.unlink()
    except OSError:
        log(f"  journal {jpath} not removed (harmless: a re-run sees NoSuchUpload)")
    composite = _b64(hashlib.sha256(b"".join(digests)).digest()) + f"-{len(digests)}"
    return {"sha256": whole.hexdigest(), "s3_checksum": composite, "parts": len(digests),
            "part_size": part_size, "sent": sent, "skipped": skipped}


# -- verify ----------------------------------------------------------------------------


def verify_object(client, bucket: str, key: str, *, size: int, s3_checksum: str,
                  sha256: str, mode: str = "checksum") -> Tuple[bool, str, Optional[str]]:
    """Does the STORED object match what was read locally? (ok, why, version_id)."""
    r = client.get_object_attributes(Bucket=bucket, Key=key,
                                     ObjectAttributes=["Checksum", "ObjectSize",
                                                       "ObjectParts", "StorageClass"])
    version = r.get("VersionId")
    if r.get("ObjectSize") != size:
        return False, f"size {r.get('ObjectSize')} != local {size}", version
    if mode == "full":
        h = hashlib.sha256()
        body = client.get_object(Bucket=bucket, Key=key,
                                 **({"VersionId": version} if version else {}))["Body"]
        for chunk in iter(lambda: body.read(8 * MiB), b""):
            h.update(chunk)
        if h.hexdigest() != sha256:
            return False, f"re-read sha256 {h.hexdigest()[:12]} != local {sha256[:12]}", version
        return True, "re-read sha256 matched", version
    remote = ((r.get("Checksum") or {}).get("ChecksumSHA256") or "")
    if not remote:
        return False, "S3 reports no SHA-256 for the object", version
    want_b, _, want_n = s3_checksum.partition("-")
    got_b, _, _ = remote.partition("-")
    if got_b != want_b:
        return False, f"S3 checksum {remote} != local {s3_checksum}", version
    if want_n:
        total = (r.get("ObjectParts") or {}).get("TotalPartsCount")
        if total is not None and int(total) != int(want_n):
            return False, f"S3 part count {total} != local {want_n}", version
    return True, "S3 sha256 checksum matched", version


# -- stub ------------------------------------------------------------------------------


def stub_path_for(path: str) -> Path:
    p = Path(path)
    return p / STUB_DIR_NAME if p.is_dir() else Path(str(p) + STUB_FILE_SUFFIX)


def read_stub(stub: Path) -> Tuple[dict, Dict[str, dict]]:
    header: dict = {}
    recs: Dict[str, dict] = {}
    with open(stub, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "awoffload" in obj:
                header = header or obj
            elif "rel" in obj:
                recs[obj["rel"]] = obj
    return header, recs


def _append_line(stub: Path, obj: dict) -> None:
    with open(stub, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _manifest_id(root: str) -> str:
    return hashlib.sha256(norm(root).lower().encode()).hexdigest()[:16]


# -- walking ---------------------------------------------------------------------------


def iter_files(root: str) -> Iterator[Tuple[str, str]]:
    """(absolute path, posix rel) for every regular file under root; links skipped."""
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for d, _dirs, files, _links in walk_no_follow(root):
        for e in files:
            if e.name == STUB_DIR_NAME and os.path.samefile(d, root):
                continue
            yield e.path, Path(os.path.relpath(e.path, root)).as_posix()


def _object_key(prefix: str, node: str, abspath: str) -> str:
    p = norm(abspath)
    if len(p) >= 2 and p[1] == ":":
        p = p[0].upper() + p[2:]
    return f"{prefix.rstrip('/')}/{node}/{p.lstrip('/')}"


def _remove_file(path: str) -> None:
    try:
        os.remove(path)
    except PermissionError:
        os.chmod(path, stat.S_IWRITE)
        os.remove(path)


def _prune_empty_dirs(root: str) -> int:
    removed = 0
    for d, _dirs, _files in sorted(os.walk(root), key=lambda t: -len(t[0])):
        if os.path.normcase(d) == os.path.normcase(root) or is_link(d):
            continue
        try:
            os.rmdir(d)
            removed += 1
        except OSError:
            continue
    return removed


# -- offload ---------------------------------------------------------------------------


def offload(path: str, target: dict, client, *, guards: Optional[Guards] = None,
            extra_roots: Iterable[str] = (), workers: int = 4, verify: str = "checksum",
            storage_class: str = DEFAULT_CLASS, part_base: int = DEFAULT_PART,
            node: Optional[str] = None, log: Callable[[str], None] = print) -> dict:
    """Upload -> verify -> record -> delete, per file. Returns the receipt."""
    root = os.path.abspath(path)
    if not os.path.exists(root):
        raise OffloadError(f"{root} does not exist")
    if is_link(root):
        raise OffloadError(f"{root} is a link/junction; offload its target instead")
    extra = list(extra_roots)
    why = refusal(root, guards, extra)
    if why:
        raise OffloadError(f"refused {root}: {why}")
    files = list(iter_files(root))
    for ap, _rel in files:
        why = refusal(ap, guards, extra)
        if why:
            raise OffloadError(f"refused {root}: contains {ap} ({why})")

    node = node or whoami()
    bucket, prefix = target["bucket"], target.get("prefix") or "offload/"
    stub = stub_path_for(root)
    done: Dict[str, dict] = {}
    if stub.is_file():
        header, done = read_stub(stub)
        if header.get("bucket") not in (None, bucket):
            raise OffloadError(f"{stub} records bucket {header.get('bucket')}, not {bucket}")
    else:
        _append_line(stub, {"awoffload": STUB_VERSION, "root": root, "node": node,
                            "target": target.get("name"), "bucket": bucket,
                            "region": target.get("region"), "prefix": prefix,
                            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})

    receipt: Dict[str, Any] = {"root": root, "bucket": bucket, "stub": str(stub),
                               "files": 0, "bytes": 0, "verified": 0, "deleted": 0,
                               "resumed_parts": 0, "failures": [], "ok": True}
    t0 = time.time()
    for ap, rel in files:
        if os.path.normcase(ap) == os.path.normcase(str(stub)):
            continue
        st = os.stat(ap)
        key = _object_key(prefix, node, ap)
        cls = storage_class_for(st.st_size, storage_class)
        receipt["files"] += 1
        try:
            prev = done.get(rel)
            if prev and prev.get("size") == st.st_size and prev.get("mtime_ns") == st.st_mtime_ns:
                # Recorded but still on disk: the run died between record and delete.
                ok, why, _v = verify_object(client, bucket, prev["key"], size=prev["size"],
                                            s3_checksum=prev["s3_checksum"],
                                            sha256=prev["sha256"], mode=verify)
                if not ok:
                    raise OffloadError(f"re-verify failed: {why}")
                rec = prev
            else:
                up = upload_file(client, bucket, key, ap, storage_class=cls,
                                 part_size=part_size_for(st.st_size, part_base),
                                 workers=workers, log=log)
                receipt["resumed_parts"] += up["skipped"]
                st2 = os.stat(ap)
                if (st2.st_size, st2.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
                    raise OffloadError("file changed while it was uploaded")
                ok, why, version = verify_object(client, bucket, key, size=st.st_size,
                                                 s3_checksum=up["s3_checksum"],
                                                 sha256=up["sha256"], mode=verify)
                if not ok:
                    raise OffloadError(f"verify failed: {why}")
                rec = {"rel": rel, "key": key, "size": st.st_size, "mtime_ns": st.st_mtime_ns,
                       "sha256": up["sha256"], "s3_checksum": up["s3_checksum"],
                       "parts": up["parts"], "part_size": up["part_size"],
                       "version_id": version, "storage_class": cls, "verify": why,
                       "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                _append_line(stub, rec)
            receipt["verified"] += 1
            _remove_file(ap)
            receipt["deleted"] += 1
            receipt["bytes"] += st.st_size
            log(f"  ok  {rel}  {st.st_size / 1024 ** 3:.2f} GiB  {rec.get('verify', '')}")
        except Exception as exc:  # noqa: BLE001 -- per-file: keep the local copy, go on
            receipt["ok"] = False
            receipt["failures"].append({"rel": rel, "error": f"{type(exc).__name__}: {exc}"})
            log(f"  FAIL {rel}: {type(exc).__name__}: {exc} (local copy kept)")
    if os.path.isdir(root):
        receipt["dirs_pruned"] = _prune_empty_dirs(root)
    receipt["seconds"] = round(time.time() - t0, 1)
    receipt["manifest"] = _publish_manifest(stub, root, node, client, bucket, prefix, log)
    return receipt


def _publish_manifest(stub: Path, root: str, node: str, client, bucket: str, prefix: str,
                      log: Callable[[str], None]) -> dict:
    """Copy the stub to the local manifest dir and into the bucket."""
    mid = _manifest_id(root)
    data = stub.read_bytes()
    out: Dict[str, Any] = {"id": mid}
    local = _base_dir() / "manifests" / f"{mid}.jsonl"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(data)
    out["local"] = str(local)
    key = f"{prefix.rstrip('/')}/manifests/{node}/{mid}.jsonl"
    try:
        client.put_object(Bucket=bucket, Key=key, Body=data,
                          ChecksumSHA256=_b64(hashlib.sha256(data).digest()),
                          StorageClass="STANDARD")
        out["s3_key"] = key
    except Exception as exc:  # noqa: BLE001 -- the local copies still restore
        out["s3_error"] = f"{type(exc).__name__}: {exc}"
        log(f"  manifest not uploaded ({exc}); local stub + {local} still restore")
    return out


# -- restore ---------------------------------------------------------------------------


def find_stub(path: str) -> Optional[Path]:
    p = os.path.abspath(path)
    for cand in (Path(p) / STUB_DIR_NAME, Path(p + STUB_FILE_SUFFIX)):
        if cand.is_file():
            return cand
    central = _base_dir() / "manifests" / f"{_manifest_id(p)}.jsonl"
    return central if central.is_file() else None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * MiB), b""):
            h.update(chunk)
    return h.hexdigest()


def restore(path: str, client_for: Callable[[dict], Any], *, only: Optional[str] = None,
            to: Optional[str] = None, force: bool = False,
            log: Callable[[str], None] = print) -> dict:
    """Download, sha256-check, then move into place. ``client_for(header)`` -> client.

    A destination that already exists is left alone when it already matches the record,
    and REFUSED when it differs (a newer local file) unless ``force``."""
    stub = find_stub(path)
    if stub is None:
        raise OffloadError(f"no offload stub or manifest for {path}")
    header, recs = read_stub(stub)
    if only is not None:
        want = Path(only).as_posix()
        recs = {k: v for k, v in recs.items() if k == want}
        if not recs:
            raise OffloadError(f"{only} is not in {stub}")
    root = header.get("root") or os.path.abspath(path)
    single_file = stub.name.endswith(STUB_FILE_SUFFIX)
    dest_root = os.path.abspath(to) if to else (os.path.dirname(root) if single_file else root)
    client = client_for(header)
    bucket = header["bucket"]
    out: Dict[str, Any] = {"stub": str(stub), "dest": dest_root, "files": 0, "bytes": 0,
                           "matched": 0, "failures": [], "ok": True}
    for rel, rec in sorted(recs.items()):
        dest = Path(dest_root) / rel
        out["files"] += 1
        try:
            if os.path.commonpath([os.path.abspath(dest), dest_root]) != dest_root:
                raise OffloadError(f"{rel!r} resolves outside {dest_root}")
            if dest.exists():
                if _sha256_file(dest) == rec["sha256"]:
                    out["matched"] += 1
                    log(f"  present {rel}  sha256 already matches")
                    continue
                if not force:
                    raise OffloadError(f"{dest} exists and differs from the offloaded copy "
                                       "(a newer local file?); --force to overwrite")
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(str(dest) + ".awrestore.part")
            h = hashlib.sha256()
            kw: Dict[str, Any] = {"Bucket": bucket, "Key": rec["key"]}
            if rec.get("version_id"):
                kw["VersionId"] = rec["version_id"]
            body = client.get_object(**kw)["Body"]
            with open(tmp, "wb") as f:
                for chunk in iter(lambda: body.read(8 * MiB), b""):
                    h.update(chunk)
                    f.write(chunk)
            if h.hexdigest() != rec["sha256"]:
                tmp.unlink()
                raise OffloadError(f"sha256 {h.hexdigest()[:12]} != manifest "
                                   f"{rec['sha256'][:12]}")
            os.replace(tmp, dest)
            if rec.get("mtime_ns"):
                os.utime(dest, ns=(rec["mtime_ns"], rec["mtime_ns"]))
            out["matched"] += 1
            out["bytes"] += rec["size"]
            log(f"  restored {rel}  sha256 {rec['sha256'][:16]} matched")
        except Exception as exc:  # noqa: BLE001 -- per-file, reported
            out["ok"] = False
            out["failures"].append({"rel": rel, "error": f"{type(exc).__name__}: {exc}"})
            log(f"  FAIL {rel}: {exc}")
    full_in_place = only is None and to is None and out["ok"]
    if full_in_place and stub.parent != _base_dir() / "manifests":
        stub.rename(str(stub) + ".restored")
        out["stub_retired"] = True
    return out


def list_manifests() -> List[dict]:
    rows = []
    for f in sorted((_base_dir() / "manifests").glob("*.jsonl")):
        try:
            header, recs = read_stub(f)
        except (OSError, ValueError):
            continue
        rows.append({"id": f.stem, "root": header.get("root"), "bucket": header.get("bucket"),
                     "files": len(recs), "bytes": sum(r.get("size", 0) for r in recs.values()),
                     "created": header.get("created")})
    return rows


# -- dry run ---------------------------------------------------------------------------


def measure(path: str) -> dict:
    total = files = 0
    newest_m = newest_a = 0.0
    entries = [path] if os.path.isfile(path) else None
    if entries:
        st = os.stat(path)
        return {"bytes": st.st_size, "files": 1, "newest_mtime": st.st_mtime,
                "newest_atime": st.st_atime}
    for _d, _dirs, fs, _links in walk_no_follow(path):
        for e in fs:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            total += st.st_size
            files += 1
            newest_m = max(newest_m, st.st_mtime)
            newest_a = max(newest_a, st.st_atime)
    return {"bytes": total, "files": files, "newest_mtime": newest_m, "newest_atime": newest_a}


def candidates(roots: Iterable[str], guards: Optional[Guards] = None,
               extra_roots: Iterable[str] = (), min_bytes: int = 0) -> List[dict]:
    """Every child of each root, measured and judged, biggest first. Acts on nothing."""
    extra = list(extra_roots)
    rows: List[dict] = []
    now = time.time()
    for root in roots:
        root = os.path.abspath(root)
        if not os.path.exists(root):
            rows.append({"path": root, "bytes": 0, "refused": "does not exist"})
            continue
        kids = [root] if os.path.isfile(root) else []
        if not kids:
            with os.scandir(root) as it:
                kids = [e.path for e in it if not entry_is_link(e)]
        for k in kids:
            m = measure(k)
            if m["bytes"] < min_bytes:
                continue
            why = refusal(k, guards, extra)
            if why is None and os.path.isdir(k):
                for ap, _rel in iter_files(k):
                    why = refusal(ap, guards, extra)
                    if why:
                        why = f"contains {os.path.basename(ap)} ({why})"
                        break
            rows.append({"path": k, **m,
                         "idle_days": round((now - m["newest_mtime"]) / 86400, 1)
                         if m["newest_mtime"] else None,
                         "atime_idle_days": round((now - m["newest_atime"]) / 86400, 1)
                         if m["newest_atime"] else None,
                         "usd_month_glacier_ir": round(m["bytes"] / 1e9
                                                       * PRICE_GB_MONTH["GLACIER_IR"], 3),
                         "refused": why})
    rows.sort(key=lambda r: -r.get("bytes", 0))
    return rows


# -- CLI -------------------------------------------------------------------------------


def _load(a) -> Tuple[Optional[dict], Optional[Path], Guards, List[str]]:
    tpath = find_topology_path(getattr(a, "topology", None))
    topo = load_topology(tpath) if tpath else None
    g, extra = make_guards(topo)
    return topo, tpath, g, extra


def _gib(n: float) -> str:
    return f"{n / 1024 ** 3:,.2f} GiB"


def _cmd_offload(a) -> int:
    topo, tpath, guards, extra = _load(a)
    if topo is None and not a.dry_run:
        print("NOT VERIFIED: no storage-topology.yaml (or no pyyaml) -- without it the "
              "site's protected roots are unknown, so nothing is offloaded")
        return 2
    if a.dry_run:
        rows = candidates(a.paths, guards, extra, min_bytes=int(a.min_gib * 1024 ** 3))
        if a.json:
            print(json.dumps(rows, indent=1, default=str))
            return 0
        print(f"{'size':>12}  {'files':>8}  {'mtime-idle':>10}  {'atime-idle':>10}  "
              f"{'$/mo GIR':>8}  path")
        for r in rows[: a.top]:
            verdict = f"  REFUSED: {r['refused']}" if r.get("refused") else ""
            print(f"{_gib(r.get('bytes', 0)):>12}  {r.get('files', 0):>8}  "
                  f"{str(r.get('idle_days')) + 'd':>10}  {str(r.get('atime_idle_days')) + 'd':>10}"
                  f"  {r.get('usd_month_glacier_ir', 0):>8}  {r['path']}{verdict}")
        ok_bytes = sum(r.get("bytes", 0) for r in rows if not r.get("refused"))
        print(f"offloadable: {_gib(ok_bytes)}; nothing was moved (dry run)")
        return 0
    if len(a.paths) != 1:
        print("offload takes exactly one path (or --dry-run over several)")
        return 2
    try:
        target = resolve_target(a.to, topo, bucket=a.bucket, region=a.region)
        extra = extra + list(target.get("never_offload") or [])
        client = make_s3_client(target, tpath, a.workers)
    except ImportError:
        print("NOT VERIFIED: boto3 is not installed (pip install boto3)")
        return 2
    except OffloadError as exc:
        print(f"NOT VERIFIED: {exc}")
        return 2
    try:
        r = offload(a.paths[0], target, client, guards=guards, extra_roots=extra,
                    workers=a.workers, verify=a.verify, storage_class=a.storage_class)
    except OffloadError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(json.dumps(r, indent=1, default=str) if a.json else
          f"offloaded {r['deleted']}/{r['files']} file(s), {_gib(r['bytes'])} to "
          f"s3://{r['bucket']}; verified {r['verified']}; failures {len(r['failures'])}; "
          f"stub {r['stub']}")
    return 0 if r["ok"] else 1


def _cmd_restore(a) -> int:
    if a.list:
        for row in list_manifests():
            print(f"{_gib(row['bytes']):>12}  {row['files']:>6} files  {row['created']}  "
                  f"{row['root']}")
        return 0
    if not a.path:
        print("restore needs a path (or --list)")
        return 2
    topo, tpath, _g, _e = _load(a)

    def client_for(header: dict):
        name = header.get("target") or "strata-cold"
        try:
            target = resolve_target(name, topo, bucket=header.get("bucket"),
                                    region=header.get("region"))
        except OffloadError:
            target = {"bucket": header["bucket"], "region": header.get("region") or "us-east-1"}
        return make_s3_client(target, tpath, 4)

    try:
        r = restore(a.path, client_for, only=a.file, to=a.to, force=a.force)
    except ImportError:
        print("NOT VERIFIED: boto3 is not installed (pip install boto3)")
        return 2
    except OffloadError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(json.dumps(r, indent=1, default=str) if a.json else
          f"restored {r['matched']}/{r['files']} file(s), {_gib(r['bytes'])} into {r['dest']}; "
          f"sha256 matched {r['matched']}; failures {len(r['failures'])}")
    return 0 if r["ok"] else 1


def add_parsers(sub) -> None:
    o = sub.add_parser("offload", help="move a cold tree to S3 (verified), leave a restore stub")
    o.add_argument("paths", nargs="+")
    o.add_argument("--to", default="strata-cold",
                   help="object_stores entry in storage-topology.yaml (default strata-cold)")
    o.add_argument("--dry-run", action="store_true",
                   help="rank each root's children by size and last access; move nothing")
    o.add_argument("--bucket")
    o.add_argument("--region")
    o.add_argument("--topology")
    o.add_argument("--workers", type=int, default=6)
    o.add_argument("--verify", choices=["checksum", "full"], default="checksum",
                   help="checksum: S3's stored SHA-256 (no egress); full: re-download")
    o.add_argument("--storage-class", default=DEFAULT_CLASS,
                   choices=["STANDARD", "GLACIER_IR"],
                   help="GLACIER_IR (default) reads back instantly; archive classes that "
                        "need a thaw are not offered because restore does not thaw")
    o.add_argument("--top", type=int, default=40)
    o.add_argument("--min-gib", type=float, default=0.0)
    o.add_argument("--json", action="store_true")
    o.set_defaults(fn=_cmd_offload)

    r = sub.add_parser("restore", help="bring an offloaded path back, sha256-checked")
    r.add_argument("path", nargs="?")
    r.add_argument("--file", help="restore one file (path relative to the offloaded root)")
    r.add_argument("--to", help="restore into this directory instead of the original place")
    r.add_argument("--list", action="store_true", help="list this node's offload manifests")
    r.add_argument("--force", action="store_true",
                   help="overwrite a local file that differs from the offloaded copy")
    r.add_argument("--topology")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=_cmd_restore)
