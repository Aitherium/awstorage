# ruff: noqa: N803 -- the fake mirrors boto3 kwarg names (Bucket, Key, ...)
"""offload / restore against an in-memory S3 that keeps real checksum semantics.

The fake validates every part's ChecksumSHA256 on receipt (as S3 does) and reports
the checksum of the bytes it STORED from get_object_attributes -- so a test that
corrupts what is stored proves the verify step is what stands between an upload
and the delete.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os

import pytest
from awstorage import offload as off


def _b64(d: bytes) -> str:
    return base64.b64encode(d).decode()


class FakeClientError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self):
        self.objects: dict = {}      # key -> {"data", "checksum", "parts", "class", "ver"}
        self.uploads: dict = {}      # upload_id -> {"key", "parts": {n: (etag, b64, data)}}
        self.calls: list = []
        self.fail_part_once: set = set()
        self.corrupt_on_store = False
        self._n = 0

    def _store(self, key, data, checksum, parts, cls):
        if self.corrupt_on_store:
            data = data[:-1] + bytes([data[-1] ^ 0xFF])
            if parts:
                checksum = _b64(hashlib.sha256(b"".join(
                    hashlib.sha256(data[i:i + len(data) // parts or 1]).digest()
                    for i in range(0, len(data), len(data) // parts or 1))).digest())
                checksum += f"-{parts}"
            else:
                checksum = _b64(hashlib.sha256(data).digest())
        self._n += 1
        self.objects[key] = {"data": data, "checksum": checksum, "parts": parts,
                             "class": cls, "ver": f"v{self._n}"}

    def put_object(self, Bucket, Key, Body, ChecksumSHA256=None, StorageClass="STANDARD",
                   Metadata=None):
        self.calls.append(("put_object", Key))
        if ChecksumSHA256 and _b64(hashlib.sha256(Body).digest()) != ChecksumSHA256:
            raise FakeClientError("BadDigest")
        self._store(Key, Body, _b64(hashlib.sha256(Body).digest()), 0, StorageClass)
        return {"VersionId": self.objects[Key]["ver"]}

    def create_multipart_upload(self, Bucket, Key, ChecksumAlgorithm, StorageClass, Metadata):
        uid = f"u{len(self.uploads) + 1}"
        self.uploads[uid] = {"key": Key, "parts": {}, "class": StorageClass}
        self.calls.append(("create_multipart_upload", Key))
        return {"UploadId": uid}

    def upload_part(self, Bucket, Key, UploadId, PartNumber, Body, ChecksumSHA256):
        self.calls.append(("upload_part", PartNumber))
        if PartNumber in self.fail_part_once:
            self.fail_part_once.discard(PartNumber)
            raise ConnectionError("network dropped")
        if _b64(hashlib.sha256(Body).digest()) != ChecksumSHA256:
            raise FakeClientError("BadDigest")
        etag = hashlib.md5(Body).hexdigest()
        self.uploads[UploadId]["parts"][PartNumber] = (etag, ChecksumSHA256, bytes(Body))
        return {"ETag": etag, "ChecksumSHA256": ChecksumSHA256}

    def list_parts(self, Bucket, Key, UploadId, PartNumberMarker=0):
        if UploadId not in self.uploads:
            raise FakeClientError("NoSuchUpload")
        ps = self.uploads[UploadId]["parts"]
        return {"Parts": [{"PartNumber": n, "ETag": e, "ChecksumSHA256": c}
                          for n, (e, c, _d) in sorted(ps.items())], "IsTruncated": False}

    def abort_multipart_upload(self, Bucket, Key, UploadId):
        self.uploads.pop(UploadId, None)

    def complete_multipart_upload(self, Bucket, Key, UploadId, MultipartUpload):
        up = self.uploads.pop(UploadId)
        nums = [p["PartNumber"] for p in MultipartUpload["Parts"]]
        assert nums == sorted(up["parts"]), "every uploaded part must be completed"
        data = b"".join(up["parts"][n][2] for n in nums)
        comp = _b64(hashlib.sha256(b"".join(
            base64.b64decode(up["parts"][n][1]) for n in nums)).digest()) + f"-{len(nums)}"
        self._store(Key, data, comp, len(nums), up["class"])

    def get_object_attributes(self, Bucket, Key, ObjectAttributes):
        o = self.objects[Key]
        out = {"ObjectSize": len(o["data"]), "Checksum": {"ChecksumSHA256": o["checksum"]},
               "VersionId": o["ver"], "StorageClass": o["class"]}
        if o["parts"]:
            out["ObjectParts"] = {"TotalPartsCount": o["parts"]}
        return out

    def get_object(self, Bucket, Key, VersionId=None):
        return {"Body": io.BytesIO(self.objects[Key]["data"])}


PART = 5 * 1024 * 1024


@pytest.fixture(autouse=True)
def _offload_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTORAGE_OFFLOAD_DIR", str(tmp_path / "state"))


def _tree(root):
    (root / "sub").mkdir(parents=True)
    files = {
        "big.gguf": os.urandom(PART * 2 + 12345),   # multipart, 3 parts
        "sub/small.bin": os.urandom(200 * 1024),    # single put, GLACIER_IR
        "sub/tiny.txt": b"hello",                    # single put, STANDARD
    }
    for rel, data in files.items():
        (root / rel).write_bytes(data)
    return files


TARGET = {"name": "strata-cold", "bucket": "bkt", "region": "us-east-1", "prefix": "offload/"}


def _run(root, s3, **kw):
    kw.setdefault("workers", 2)
    return off.offload(str(root), TARGET, s3, part_base=PART, node="n1",
                       log=lambda _m: None, **kw)


def test_offload_verifies_deletes_and_restores(tmp_path):
    root = tmp_path / "gguf-build"
    files = _tree(root)
    s3 = FakeS3()
    r = _run(root, s3)
    assert r["ok"] and r["deleted"] == 3 and r["verified"] == 3
    assert r["bytes"] == sum(len(d) for d in files.values())
    for rel in files:
        assert not (root / rel).exists()
    assert (root / off.STUB_DIR_NAME).is_file()
    assert not (root / "sub").exists(), "empty dirs are pruned"
    classes = {k.rsplit("/", 1)[-1]: o["class"] for k, o in s3.objects.items()}
    assert classes["big.gguf"] == "GLACIER_IR" and classes["tiny.txt"] == "STANDARD"
    assert any("/manifests/n1/" in k for k in s3.objects), "manifest goes to the bucket"

    one = off.restore(str(root), lambda _h: s3, only="sub/small.bin",
                      to=str(tmp_path / "probe"), log=lambda _m: None)
    assert one["ok"] and one["matched"] == 1
    assert (tmp_path / "probe" / "sub" / "small.bin").read_bytes() == files["sub/small.bin"]

    full = off.restore(str(root), lambda _h: s3, log=lambda _m: None)
    assert full["ok"] and full["matched"] == 3
    for rel, data in files.items():
        assert (root / rel).read_bytes() == data


def test_corrupt_stored_object_keeps_every_local_file(tmp_path):
    """If verify were skipped, these files would be deleted. They must not be."""
    root = tmp_path / "data"
    files = _tree(root)
    s3 = FakeS3()
    s3.corrupt_on_store = True
    r = _run(root, s3)
    assert not r["ok"]
    assert r["deleted"] == 0 and r["verified"] == 0
    assert len(r["failures"]) == 3
    assert all("verify failed" in f["error"] for f in r["failures"])
    for rel, data in files.items():
        assert (root / rel).read_bytes() == data


def test_size_mismatch_is_a_verify_failure(tmp_path, monkeypatch):
    root = tmp_path / "d"
    root.mkdir()
    (root / "f.bin").write_bytes(b"x" * 1000)
    s3 = FakeS3()
    real = s3.get_object_attributes

    def lying(**kw):
        out = real(**kw)
        out["ObjectSize"] -= 1
        return out

    monkeypatch.setattr(s3, "get_object_attributes", lying)
    r = _run(root, s3)
    assert r["deleted"] == 0 and (root / "f.bin").exists()


def test_full_verify_re_reads_the_object(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "f.bin").write_bytes(os.urandom(3000))
    s3 = FakeS3()
    r = _run(root, s3, verify="full")
    assert r["ok"] and r["deleted"] == 1


def test_multipart_resumes_only_missing_parts(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    data = os.urandom(PART * 3 + 7)
    (root / "big.bin").write_bytes(data)
    s3 = FakeS3()
    s3.fail_part_once = {3}
    r1 = _run(root, s3, workers=1)
    assert not r1["ok"] and (root / "big.bin").exists()
    s3.calls.clear()
    r2 = _run(root, s3, workers=1)
    assert r2["ok"] and r2["deleted"] == 1
    sent = sorted(n for c, n in s3.calls if c == "upload_part")
    # Part 4 may have landed in the first run (it was in flight when 3 failed).
    assert 3 in sent and 1 not in sent and 2 not in sent, f"re-sent {sent}"
    assert r2["resumed_parts"] == 4 - len(sent)
    out = off.restore(str(root), lambda _h: s3, log=lambda _m: None)
    assert out["ok"] and (root / "big.bin").read_bytes() == data


def test_restore_rejects_a_sha256_mismatch(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "f.bin").write_bytes(b"payload" * 100)
    s3 = FakeS3()
    assert _run(root, s3)["ok"]
    key = next(k for k in s3.objects if k.endswith("f.bin"))
    s3.objects[key]["data"] = b"tampered"
    out = off.restore(str(root), lambda _h: s3, log=lambda _m: None)
    assert not out["ok"] and not (root / "f.bin").exists()
    assert not (root / "f.bin.awrestore.part").exists()


def test_single_file_offload_leaves_sibling_stub(tmp_path):
    f = tmp_path / "model.gguf"
    f.write_bytes(os.urandom(4096))
    s3 = FakeS3()
    r = off.offload(str(f), TARGET, s3, part_base=PART, node="n1", log=lambda _m: None)
    assert r["ok"] and not f.exists()
    assert (tmp_path / ("model.gguf" + off.STUB_FILE_SUFFIX)).is_file()
    out = off.restore(str(f), lambda _h: s3, log=lambda _m: None)
    assert out["ok"] and f.exists()


@pytest.mark.parametrize("rel", ["WSL/awnix/ext4.vhdx", "x/tenants/acme/file.bin",
                                 "x/customer-uploads/a.pdf", "x/app.db", "x/disk.vhdx",
                                 "x/pgdata/PG_VERSION"])
def test_refuses_protected_paths(tmp_path, rel):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x")
    assert off.refusal(str(p)) is not None
    with pytest.raises(off.OffloadError):
        off.offload(str(tmp_path / rel.split("/")[0]), TARGET, FakeS3(), node="n1",
                    log=lambda _m: None)
    assert p.exists()


def test_topology_roots_are_refused(tmp_path):
    root = tmp_path / "deploy"
    root.mkdir()
    (root / "a.bin").write_bytes(b"x")
    with pytest.raises(off.OffloadError):
        off.offload(str(root), TARGET, FakeS3(), extra_roots=[str(root)], node="n1",
                    log=lambda _m: None)
    assert off.refusal(str(tmp_path), extra_roots=[str(root)]) is not None, \
        "a parent of a protected root is refused too"


def test_candidates_ranks_by_size_and_flags_refusals(tmp_path):
    (tmp_path / "big").mkdir()
    (tmp_path / "big" / "w.bin").write_bytes(b"x" * 5000)
    (tmp_path / "small").mkdir()
    (tmp_path / "small" / "w.bin").write_bytes(b"x" * 10)
    (tmp_path / "dbdir").mkdir()
    (tmp_path / "dbdir" / "state.sqlite").write_bytes(b"x" * 100)
    rows = off.candidates([str(tmp_path)])
    names = [os.path.basename(r["path"]) for r in rows]
    assert names[0] == "big"
    db = next(r for r in rows if r["path"].endswith("dbdir"))
    assert db["refused"]
    assert (tmp_path / "big" / "w.bin").exists(), "dry run moves nothing"


def test_resolve_target_from_topology():
    topo = {"object_stores": {"strata-cold": {"bucket": "b", "region": "us-west-2",
                                              "offload_prefix": "off/"}}}
    t = off.resolve_target("strata-cold", topo)
    assert (t["bucket"], t["region"], t["prefix"]) == ("b", "us-west-2", "off/")
    with pytest.raises(off.OffloadError):
        off.resolve_target("nope", topo)


def test_part_size_keeps_under_10k_parts():
    assert off.part_size_for(49 * 1024 ** 3) == off.DEFAULT_PART
    big = 5 * 1024 ** 4
    assert -(-big // off.part_size_for(big)) <= off.MAX_PARTS


def test_restore_refuses_to_overwrite_a_newer_local_file(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "f.bin").write_bytes(b"old" * 100)
    s3 = FakeS3()
    assert _run(root, s3)["ok"]
    (root / "f.bin").write_bytes(b"newer local edit")
    out = off.restore(str(root), lambda _h: s3, only="f.bin", log=lambda _m: None)
    assert not out["ok"] and (root / "f.bin").read_bytes() == b"newer local edit"
    forced = off.restore(str(root), lambda _h: s3, only="f.bin", force=True,
                         log=lambda _m: None)
    assert forced["ok"] and (root / "f.bin").read_bytes() == b"old" * 100


def test_restore_rejects_a_stub_path_escaping_the_root(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "f.bin").write_bytes(b"x" * 10)
    s3 = FakeS3()
    assert _run(root, s3)["ok"]
    stub = root / off.STUB_DIR_NAME
    stub.write_text(stub.read_text().replace('"rel": "f.bin"', '"rel": "../evil.bin"'))
    out = off.restore(str(root), lambda _h: s3, log=lambda _m: None)
    assert not out["ok"] and not (tmp_path / "evil.bin").exists()


def test_crash_between_record_and_delete_re_verifies_before_delete(tmp_path, monkeypatch):
    root = tmp_path / "d"
    root.mkdir()
    (root / "f.bin").write_bytes(b"y" * 4000)
    s3 = FakeS3()
    real_remove = off._remove_file

    def crash(_p):
        raise OSError("crash")

    monkeypatch.setattr(off, "_remove_file", crash)
    r1 = _run(root, s3)
    assert not r1["ok"] and (root / "f.bin").exists()
    monkeypatch.setattr(off, "_remove_file", real_remove)
    s3.calls.clear()
    key = next(k for k in s3.objects if k.endswith("f.bin"))
    s3.objects[key]["checksum"] = "AAAA"          # the stored copy no longer verifies
    r2 = _run(root, s3)
    assert not r2["ok"] and (root / "f.bin").exists(), "re-verify must gate the delete"
    assert ("put_object", key) not in s3.calls, "a recorded file is re-verified, not re-sent"
    s3.objects[key]["checksum"] = base64.b64encode(
        hashlib.sha256(b"y" * 4000).digest()).decode()
    r3 = _run(root, s3)
    assert r3["ok"] and not (root / "f.bin").exists()


def test_file_changed_during_upload_is_kept(tmp_path, monkeypatch):
    root = tmp_path / "d"
    root.mkdir()
    f = root / "f.bin"
    f.write_bytes(b"z" * 4000)
    s3 = FakeS3()
    real_put = s3.put_object

    def put_and_touch(**kw):
        out = real_put(**kw)
        if kw["Key"].endswith("f.bin"):
            st = f.stat()
            os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
        return out

    monkeypatch.setattr(s3, "put_object", put_and_touch)
    r = _run(root, s3)
    assert not r["ok"] and f.exists()
    assert "changed" in r["failures"][0]["error"]


def test_verify_accepts_composite_without_part_suffix(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    (root / "big.bin").write_bytes(os.urandom(PART + 99))
    s3 = FakeS3()
    real = s3.get_object_attributes

    def no_suffix(**kw):
        out = real(**kw)
        out["Checksum"]["ChecksumSHA256"] = out["Checksum"]["ChecksumSHA256"].split("-")[0]
        return out

    s3.get_object_attributes = no_suffix
    assert _run(root, s3)["ok"]


def test_journal_without_upload_id_starts_fresh(tmp_path):
    root = tmp_path / "d"
    root.mkdir()
    big = root / "big.bin"
    big.write_bytes(os.urandom(PART * 2 + 1))
    st = big.stat()
    key = off._object_key("offload/", "n1", str(big))
    jdir = tmp_path / "state" / "journal"
    jdir.mkdir(parents=True)
    name = hashlib.sha256(f"bkt/{key}".encode()).hexdigest()[:32] + ".json"
    (jdir / name).write_text(json.dumps({"key": key, "size": st.st_size, "part_size": PART,
                                         "mtime_ns": st.st_mtime_ns}))
    assert _run(root, FakeS3())["ok"]
