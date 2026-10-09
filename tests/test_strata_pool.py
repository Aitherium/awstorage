"""The Strata pool as a content-addressed object store, and the archive hooks.

Against a local stub that namespaces a tenant bearer exactly as the service does
(`tests/strata_pool_stub.py`).
"""

from __future__ import annotations

import hashlib

import pytest
from awstorage import strata as st
from awstorage.strata import StrataTarget, StrataUnavailableError

from .strata_pool_stub import KEY, PoolStub

BEARER = "tok-" + "acme"

# awshare is an optional sibling of awstorage; the pool store is built on it.
awshare = pytest.importorskip("awshare")


@pytest.fixture
def pool():
    s = PoolStub()
    yield s
    s.close()


def _target(pool, tier="warm", **kw) -> StrataTarget:
    return StrataTarget(tier, url=pool.url, env={}, insecure_http_for_tests=True, **kw)


def test_a_bearer_never_travels_with_the_internal_key(pool):
    t = _target(pool, key=KEY, bearer=BEARER)
    t.put("a.txt", b"hi")
    sent = pool.headers_seen[-1]
    assert sent.get("Authorization") == f"Bearer {BEARER}"
    assert "X-Internal-Key" not in sent


def test_bearer_from_env_and_check_accepts_it(pool):
    t = StrataTarget("warm", url=pool.url, env={st.BEARER_ENV: BEARER},
                     insecure_http_for_tests=True)
    assert t.bearer == BEARER and not t.key
    assert t.auth_headers() == {"Authorization": f"Bearer {BEARER}"}


def test_stat_or_none_is_none_on_404_and_raises_on_an_outage(pool):
    t = _target(pool, bearer=BEARER)
    assert t.stat_or_none("nope") is None
    pool.stat_status = 500
    with pytest.raises(RuntimeError):
        t.stat_or_none("nope")


def test_object_store_needs_a_tenant_and_a_credential(pool):
    with pytest.raises(ValueError):
        st.strata_object_store("", target=_target(pool, bearer=BEARER))
    with pytest.raises(ValueError):
        st.strata_object_store("../x", target=_target(pool, bearer=BEARER))
    with pytest.raises(StrataUnavailableError):
        st.strata_object_store("acme", target=_target(pool))


def test_objects_land_under_the_tenant_namespace_and_put_is_idempotent(pool, tmp_path):
    store = st.strata_object_store("acme", target=_target(pool, bearer=BEARER))
    f = tmp_path / "f.bin"
    f.write_bytes(b"pooled bytes")
    sha = hashlib.sha256(b"pooled bytes").hexdigest()
    assert store.put(f) == (sha, True)
    assert pool.writes == [f"aither://warm/__t__/acme/objects/{sha[:2]}/{sha}"]
    assert store.location == "aither://warm/__t__/acme/objects"
    fresh = st.strata_object_store("acme", target=_target(pool, bearer=BEARER))
    assert fresh.put(f) == (sha, False)  # proven present by stat, not re-sent
    assert len(pool.writes) == 1


def test_an_internal_key_caller_lands_in_the_same_tenant_subtree(pool, tmp_path):
    store = st.strata_object_store("acme", target=_target(pool, key=KEY))
    f = tmp_path / "f.bin"
    f.write_bytes(b"x")
    sha, _ = store.put(f)
    assert pool.writes == [f"aither://warm/__t__/acme/objects/{sha[:2]}/{sha}"]


def test_materialize_refuses_bytes_that_do_not_match_their_name(pool, tmp_path):
    store = st.strata_object_store("acme", target=_target(pool, bearer=BEARER))
    f = tmp_path / "f.bin"
    f.write_bytes(b"truth")
    sha, _ = store.put(f)
    pool.corrupt_reads = True
    out = tmp_path / "out.bin"
    with pytest.raises(awshare.store.VerificationFailedError):
        store.materialize(sha, out)
    assert not out.exists()


def test_snapshot_and_restore_round_trip_through_the_pool(pool, tmp_path):
    src = tmp_path / "src"
    (src / "d").mkdir(parents=True)
    (src / "d" / "a.txt").write_bytes(b"a" * 100)
    (src / "b.txt").write_bytes(b"b")
    store = st.strata_object_store("acme", target=_target(pool, bearer=BEARER))
    m1 = awshare.snapshot_tree(src, tmp_path / "meta", "s1", object_store=store)
    assert m1["new_objects"] == 2
    assert not (tmp_path / "meta" / "objects").exists()  # nothing kept locally
    m2 = awshare.snapshot_tree(src, tmp_path / "meta", "s2", previous=m1,
                               object_store=st.strata_object_store(
                                   "acme", target=_target(pool, bearer=BEARER)))
    assert m2["new_objects"] == 0 and m2["new_bytes"] == 0
    dest = tmp_path / "dest"
    awshare.restore_tree(m2, tmp_path / "meta", dest, object_store=store)
    assert (dest / "d" / "a.txt").read_bytes() == b"a" * 100
    assert (dest / "b.txt").read_bytes() == b"b"


def test_another_tenant_cannot_read_acme_objects(pool, tmp_path):
    store = st.strata_object_store("acme", target=_target(pool, bearer=BEARER))
    f = tmp_path / "f.bin"
    f.write_bytes(b"private")
    sha, _ = store.put(f)
    other = st.strata_object_store("acme", target=_target(pool, bearer="tok-" + "other"))
    assert other.has(sha) is False  # the path nests inside the OTHER tenant's subtree


# ------------------------------------------------------------------ archive hooks

def test_archive_hooks_are_absent_without_a_credential():
    assert st.archive_hooks({}) == (None, None)


def test_archive_hooks_write_then_read_back_independently(pool, tmp_path):
    f = tmp_path / "big.log"
    f.write_bytes(b"L" * 2048)
    sha = hashlib.sha256(f.read_bytes()).hexdigest()
    put, back = st.archive_hooks({st.KEY_ENV: KEY},
                                 target_factory=lambda tier: _target(pool, tier, key=KEY))
    spath = "aither://cold/disk-archive/n1/c/big.log"
    assert put(f, strata_path=spath, sha256=sha, size=2048, tier="cold")["sha256"] == sha
    assert back(spath) == {"sha256": sha, "size": 2048}
    pool.corrupt_reads = True
    assert back(spath)["sha256"] != sha  # a read that hashes, not a stat that echoes


def test_archive_hook_refuses_a_file_that_changed(pool, tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"now")
    put, _ = st.archive_hooks({st.KEY_ENV: KEY},
                              target_factory=lambda tier: _target(pool, tier, key=KEY))
    with pytest.raises(RuntimeError):
        put(f, strata_path="aither://cold/x/f", sha256="0" * 64, size=3, tier="cold")
    assert pool.writes == []


def test_split_virtual():
    assert st.split_virtual("aither://cold/a/b") == ("cold", "a/b")
    for bad in ("cold/a", "aither://lukewarm/a", "aither://cold"):
        with pytest.raises(ValueError):
            st.split_virtual(bad)


def test_object_store_reads_the_tenant_from_env(pool):
    store = st.strata_object_store(env={st.TENANT_ENV: "acme"},
                                   target=_target(pool, bearer=BEARER))
    assert store.prefix == "__t__/acme/objects"


# ------------------------------------------------------------- transport guards

def test_get_raises_on_a_non_200_instead_of_returning_the_error_body(pool):
    t = _target(pool, key=KEY)
    with pytest.raises(RuntimeError, match="HTTP 404"):
        t.get("never/written")
    put, back = st.archive_hooks({st.KEY_ENV: KEY},
                                 target_factory=lambda tier: _target(pool, tier, key=KEY))
    with pytest.raises(RuntimeError, match="HTTP 404"):
        back("aither://cold/never/written")  # not the sha256 of a JSON error


def test_archive_hook_refuses_a_file_over_its_cap_before_reading_it(pool, tmp_path):
    f = tmp_path / "big"
    f.write_bytes(b"B" * 64)
    put, _ = st.archive_hooks({st.KEY_ENV: KEY}, max_bytes=32,
                              target_factory=lambda tier: _target(pool, tier, key=KEY))
    with pytest.raises(RuntimeError, match="at most 32 bytes"):
        put(f, strata_path="aither://cold/x/big", sha256=_sha(b"B" * 64), size=64,
            tier="cold")
    assert pool.writes == []


@pytest.mark.parametrize("bad", ["a/b", "a\b", "..", ".hidden", "a b", "x" * 129, None])
def test_a_path_shaped_tenant_is_refused(bad):
    with pytest.raises(ValueError):
        st.objects_prefix(bad)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
