"""awstorage inventory: publish a node's index SIGNED to GitHub, pull + verify + query it.

GitHub is an in-memory fake (no network). awseal signs for real with throwaway keys.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

awseal = pytest.importorskip("awseal")
pytest.importorskip("awrtifact")

from awstorage import autoindex, cli  # noqa: E402
from awstorage import files as files_mod  # noqa: E402
from awstorage import inventory as inv  # noqa: E402

REPO = "Aitherium/inventory"
NODE = "box-7"


class FakeGitHub:
    """The inventory's GitHub surface, in memory."""

    def __init__(self, private=True):
        self.private = {REPO: private}
        self.releases: dict[str, dict[str, bytes]] = {}
        self.order: list[str] = []
        self.files: dict[str, str] = {}

    def repo_private(self, repo):
        return self.private.get(repo)

    def list_releases(self, repo, prefix=""):
        return [t for t in reversed(self.order) if t.startswith(prefix)]

    def release_exists(self, repo, tag):
        return tag in self.releases

    def create_release(self, repo, tag, title, notes):
        assert tag not in self.releases
        self.releases[tag] = {}
        self.order.append(tag)

    def upload(self, repo, tag, path):
        self.releases[tag][Path(path).name] = Path(path).read_bytes()

    def download(self, repo, tag, name, dest):
        data = self.releases[tag][name]
        Path(dest).write_bytes(data)
        return len(data)

    def assets(self, repo, tag):
        return set(self.releases.get(tag, {}))

    def get_file(self, repo, path):
        return self.files.get(path)

    def put_file(self, repo, path, content, message):
        if path in self.files:
            return "present"
        self.files[path] = content
        return "created"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "home" / "catalog.db"))
    monkeypatch.setenv(inv.CACHE_ENV, str(tmp_path / "cache"))
    monkeypatch.setenv(inv.ANNOUNCE_ENV, "0")
    key = tmp_path / "keys" / "node.key"
    awseal.keygen(key)
    monkeypatch.setenv("AWSEAL_KEY_PATH", str(key))
    root = tmp_path / "data"
    (root / "a" / "b").mkdir(parents=True)
    for i in range(40):
        (root / "a" / f"f{i:03}.txt").write_bytes(b"x" * (100 + i))
    for d in ("a", "a/b"):
        (root / d / "dup.bin").write_bytes(b"D" * 20000)
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_ed25519").write_bytes(b"k" * 5000)
    src = tmp_path / "idx" / "files.db"
    db = files_mod.open_index(src)
    try:
        files_mod.scan_files(db, [str(root)], node=NODE, hash_mode="full", min_hash_bytes=1)
    finally:
        db.close()
    return types.SimpleNamespace(tmp=tmp_path, src=src, root=files_mod.norm_path(root), key=key)


def _publish(env, gh, **kw):
    kw.setdefault("node", NODE)
    return inv.publish(repo=REPO, src=env.src, gh=gh, announce_channel=None, **kw)


def test_export_round_trip_keeps_rows_and_drops_secret_hashes(env):
    out = env.tmp / "out.db"
    st = inv.export_files(env.src, NODE, out)
    import sqlite3
    a, b = sqlite3.connect(str(env.src)), sqlite3.connect(str(out))
    q = "SELECT path, bytes, mtime_ns FROM files ORDER BY path"
    assert a.execute(q).fetchall() == b.execute(q).fetchall()
    assert st["rows"] == 43 and st["roots"] == 1 and st["scanned_at"]
    sens = b.execute("SELECT sha256, partial_hash FROM files WHERE sensitive = 1").fetchall()
    assert sens and all(r == (None, None) for r in sens)
    assert b.execute("SELECT COUNT(*) FROM dupe_groups").fetchone()[0] == 1
    assert b.execute("SELECT COUNT(*) FROM roots WHERE last_push_at IS NOT NULL").fetchone()[0] == 0


def test_publish_then_pull_verifies_and_query_matches_files_tree(env, capsys):
    gh = FakeGitHub()
    res = _publish(env, gh)
    assert res["rows"] == 43 and res["registry_state"] == "created"
    assert gh.files[f"nodes/{NODE}.pub"].strip() == res["public_key"]
    assets = gh.releases[res["release"]]
    assert {"awseal.json", "inventory.json", "files.db.gz.manifest.json"} <= set(assets)
    assert json.loads(gh.releases[f"{NODE}-latest"]["latest.json"])["release"] == res["release"]
    got = inv.pull(node=NODE, repo=REPO, gh=gh)
    assert got["ok"] and got["release"] == res["release"] and got["rows"] == 43

    for verb, extra in (("tree", [env.root, "--depth", "2"]), ("find", ["dup"]),
                        ("dupes", ["--min-bytes", "1"])):
        assert cli.main(["files", verb, *extra, "--node", NODE, "--index", str(env.src),
                         "--local", "--json"]) == 0
        local = json.loads(capsys.readouterr().out)
        assert inv.main(["query", verb, *extra, "--node", NODE, "--json"]) == 0
        pulled = json.loads(capsys.readouterr().out)
        assert pulled == local, verb
    assert cli.main(["files", "tree", env.root, "--node", NODE, "--index", str(env.src),
                     "--local"]) == 0
    text_local = capsys.readouterr().out
    assert inv.main(["query", "tree", env.root, "--node", NODE]) == 0
    assert capsys.readouterr().out == text_local


def test_files_tree_for_an_absent_node_answers_from_the_pulled_inventory(env, capsys):
    gh = FakeGitHub()
    _publish(env, gh)
    inv.pull(node=NODE, repo=REPO, gh=gh)
    other = env.tmp / "other" / "catalog.db"           # this node's own index: no box-7
    assert cli.main(["files", "tree", env.root, "--node", NODE, "--catalog", str(other),
                     "--local", "--json"]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["source"].startswith("inventory:") and res["children"]


def test_tampered_artifact_is_refused_and_cache_untouched(env):
    gh = FakeGitHub()
    tag = _publish(env, gh)["release"]
    rel = gh.releases[tag]
    part = "files.db.gz.part0"
    import gzip
    import hashlib
    raw = bytearray(gzip.decompress(rel[part]))
    raw[-10] ^= 0xFF
    rel[part] = gzip.compress(bytes(raw))
    man = json.loads(rel["files.db.gz.manifest.json"])
    man["parts"][0].update(size=len(rel[part]), sha256=hashlib.sha256(rel[part]).hexdigest())
    man["total"], man["sha256"] = len(rel[part]), hashlib.sha256(rel[part]).hexdigest()
    rel["files.db.gz.manifest.json"] = json.dumps(man).encode()
    with pytest.raises(inv.RefusedError, match="FAILED verification"):
        inv.pull(node=NODE, repo=REPO, gh=gh)
    assert inv.cached_index(NODE) is None


def test_part_not_matching_its_manifest_is_refused(env):
    gh = FakeGitHub()
    tag = _publish(env, gh)["release"]
    gh.releases[tag]["files.db.gz.part0"] += b"junk"
    with pytest.raises(inv.RefusedError, match="does not match its manifest"):
        inv.pull(node=NODE, repo=REPO, gh=gh)


def test_unknown_key_and_foreign_signer_are_refused(env, monkeypatch):
    gh = FakeGitHub()
    _publish(env, gh)
    real = gh.files.pop(f"nodes/{NODE}.pub")
    with pytest.raises(inv.RefusedError, match="unknown key"):
        inv.pull(node=NODE, repo=REPO, gh=gh)
    # An attacker with repo write access publishes under their own key: the registry
    # still names the node's key, so the seal verifies against the WRONG key -> refused.
    attacker = env.tmp / "keys" / "attacker.key"
    awseal.keygen(attacker)
    monkeypatch.setenv("AWSEAL_KEY_PATH", str(attacker))
    gh.files.clear()
    _publish(env, gh, now=2_000_000_000)
    gh.files[f"nodes/{NODE}.pub"] = real
    with pytest.raises(inv.RefusedError, match="key not trusted"):
        inv.pull(node=NODE, repo=REPO, gh=gh)


def test_publish_refuses_a_key_the_registry_does_not_name(env):
    gh = FakeGitHub()
    gh.files[f"nodes/{NODE}.pub"] = "ab" * 32 + "\n"
    with pytest.raises(inv.RefusedError, match="registry does not name"):
        _publish(env, gh)
    assert gh.releases == {}


def test_public_repo_refused_without_the_flag(env, capsys):
    gh = FakeGitHub(private=False)
    with pytest.raises(inv.RefusedError, match="NOT private"):
        _publish(env, gh)
    assert gh.releases == {} and gh.files == {}
    rc = inv.main(["publish", "--index", str(env.src), "--node", NODE, "--no-announce"],
                  gh_factory=lambda: gh)
    assert rc == 1 and "NOT private" in capsys.readouterr().err
    assert _publish(env, gh, allow_public=True)["ok"]


def test_pull_picks_the_newest_release(env):
    gh = FakeGitHub()
    old = _publish(env, gh, now=1_900_000_000)["release"]
    new = _publish(env, gh, now=1_950_000_000)["release"]
    gh.order = [new, old]                         # listing order must not matter
    gh.releases[f"{NODE}-latest"]["latest.json"] = json.dumps({"release": old}).encode()
    assert inv.pull(node=NODE, repo=REPO, gh=gh)["release"] == new
    assert inv.newest_release([f"{NODE}-x-20990101T000000Z", old], NODE) == old
    assert inv.remote_nodes([old, new, "smoke-test-20261107T000000Z", "box-7-latest"]) == {
        NODE: new, "smoke-test": "smoke-test-20261107T000000Z"}


def test_a_replayed_release_under_a_new_tag_is_refused(env):
    gh = FakeGitHub()
    old = _publish(env, gh, now=1_900_000_000)["release"]
    forged = f"{NODE}-20990101T000000Z"
    gh.releases[forged] = dict(gh.releases[old])
    gh.order.append(forged)
    with pytest.raises(inv.RefusedError, match="signed release"):
        inv.pull(node=NODE, repo=REPO, gh=gh)


def test_a_changed_registry_key_is_refused_once_pinned(env):
    gh = FakeGitHub()
    _publish(env, gh)
    inv.pull(node=NODE, repo=REPO, gh=gh)
    gh.files[f"nodes/{NODE}.pub"] = "cd" * 32
    with pytest.raises(inv.RefusedError, match="changed since this machine first trusted"):
        inv.pull(node=NODE, repo=REPO, gh=gh)
    with pytest.raises(inv.RefusedError, match="key not trusted"):
        inv.pull(node=NODE, repo=REPO, gh=gh, accept_key_change=True)


def test_pull_cli_exit_codes(env, capsys):
    gh = FakeGitHub()
    _publish(env, gh)
    assert inv.main(["pull", "--all", "--json"], gh_factory=lambda: gh) == 0
    assert json.loads(capsys.readouterr().out)["results"][0]["ok"] is True
    gh.files.clear()
    assert inv.main(["pull", NODE], gh_factory=lambda: gh) == 1
    assert inv.main(["pull", "ghost"], gh_factory=lambda: gh) == 2


def test_announce_is_best_effort(env):
    gh = FakeGitHub()

    def boom(text, channel):
        raise RuntimeError("relay down")
    res = inv.publish(node=NODE, repo=REPO, src=env.src, gh=gh, announcer=boom)
    assert res["ok"] and res["announce"].startswith("failed")
    seen = []
    res = inv.publish(node=NODE, repo=REPO, src=env.src, gh=gh, now=2_100_000_000,
                      announcer=lambda t, c: seen.append((t, c)) or "sent")
    assert seen == [(f"{NODE} published inventory kind=files rows=43 release={res['release']}",
                     "#agents")]


def test_large_artifact_is_chunked_and_reassembled(env):
    gh = FakeGitHub()
    res = _publish(env, gh, part_size=1000)
    assert res["parts"] > 1
    assert inv.pull(node=NODE, repo=REPO, gh=gh)["rows"] == 43


# ---------------------------------------------------------------- files sync receipt

def _runner(codes: dict, calls: list):
    def run(argv, stdout=None, stderr=None, env=None):
        step = argv[4]
        calls.append(step)
        rc = codes.get(step, 0)
        if rc:
            stderr.write(f"{step} broke".encode())
        elif step == "publish":
            stdout.write(json.dumps({"release": "box-7-x", "rows": 3, "repo": REPO}).encode())
        return types.SimpleNamespace(returncode=rc)
    return run


def test_sync_publishes_after_push_and_surfaces_a_publish_failure(tmp_path):
    cfg = {"index_dir": str(tmp_path / "i"), "node": NODE, "inventory_publish": True}
    calls: list = []
    rec = autoindex.run_pass(cfg, run=_runner({}, calls), python="py")
    assert calls == ["scan", "push", "publish"] and rec["exit_code"] == 0
    assert rec["published"]["release"] == "box-7-x"
    rec = autoindex.run_pass(cfg, run=_runner({"publish": 1}, []), python="py")
    assert rec["exit_code"] == 1 and rec["failed_step"] == "publish"
    assert "publish broke" in rec["error"]
    calls = []
    rec = autoindex.run_pass(cfg, run=_runner({"push": 3}, calls), python="py")
    assert calls == ["scan", "push", "publish"]
    assert rec["failed_step"] == "push" and rec["exit_code"] == 3 and rec["publish_exit"] == 0


def test_enrolled_config_defaults_publish_on(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"node": NODE}), encoding="utf-8")
    assert autoindex.load_config(p)["inventory_publish"] is True
    p.write_text(json.dumps({"node": NODE, "inventory_publish": False}), encoding="utf-8")
    assert autoindex.load_config(p)["inventory_publish"] is False
    assert autoindex.load_config(tmp_path / "missing.json") == {}


def test_github_adapter_names_only_awrtifact_calls():
    gh = inv.GitHub()
    assert gh.gh.__name__ == "awrtifact.gh"

