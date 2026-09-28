"""guards (sensitive + never sets), whoami (node identity order), volumes, the junction
refusal in every walker (a REAL `mklink /J` on Windows), and `awstorage manage`."""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path

import pytest
from awstorage import _fs, identity, policy
from awstorage import files as F
from awstorage.guards import Guards, is_sensitive, never_roots_from_topology, redact


@pytest.mark.parametrize("path,want", [
    ("C:/Users/x/.ssh/config", True), ("/home/x/.aws/credentials", True),
    ("/srv/app/.env.production", True), ("D:/keys/id_ed25519.pub", True),
    ("E:/certs/server.pem", True), ("E:/vault/db.kdbx", True),
    ("/home/x/.docker/config.json", True), ("/opt/app/my-credentials.txt", True),
    ("E:/Media/movie.mkv", False), ("/home/x/environment.md", False),
    ("C:/Users/x/sshd_notes.txt", False),
])
def test_sensitive_set(path, want):
    assert is_sensitive(path) is want


def test_never_set_and_topology_roots():
    topo = {"planes": {
        "source": {"canonical": {"deploy_root": "C:/src/app", "dev_tree": "E:/src/app"}},
        "data": {"canonical": {"library": "C:/AitherOS-Data/Library",
                               "db_volumes_ext4": "Debian:/var/lib/aither/volumes"}},
        "backups": {"canonical": {"root": "D:/Backups"}},
        "archive": {"canonical": {"root": "E:/Archive", "strata_cold": "aither://cold"}},
        "cache": {"canonical": {"hf": "D:/Caches"}},
    }}
    roots = never_roots_from_topology(topo)
    assert "C:/src/app" in roots and "D:/Backups" in roots
    assert "E:/Archive" not in roots and "D:/Caches" not in roots, "only data/source/backups"
    assert not any("://" in r or r.startswith("Debian:") for r in roots)
    g = Guards(topology=topo)
    assert g.is_never("C:/src/app/lib/x.py")
    assert g.is_never("c:/src/app/x"), "Windows paths compare case-insensitively"
    assert not g.is_never("C:/src/app-old/x"), "a name prefix is not the root"
    assert g.is_never("E:/stuff/Library/Data/state.db")
    assert g.is_never("/var/lib/postgresql/16/main/base/1")
    assert g.is_never("E:/repo/.git/objects/ab/cdef")
    assert g.is_never("E:/vms/fleet.vhdx")
    assert g.is_never("E:/proj/node_modules/react/index.js")
    assert g.is_never("/usr/lib/libc.so") and g.is_never("/nix/store/abc-x/bin/y")
    assert not g.is_never("E:/Media/movie.mkv")
    assert g.refusal("E:/Media/movie.mkv") is None
    assert "sensitive" in g.refusal("E:/x/.ssh/id_rsa")
    assert redact("E:/x/.ssh/id_rsa") == "E:/x/.ssh/[redacted]"


def test_whoami_order(tmp_path, monkeypatch):
    f = tmp_path / "node-id"
    monkeypatch.delenv("AWSTORAGE_NODE", raising=False)
    assert identity.whoami(f) == identity.socket.gethostname()
    assert identity.whoami_source(f) == "hostname"
    f.write_text("local\n", encoding="utf-8")
    assert identity.whoami(f) == "local" and identity.whoami_source(f).startswith("file:")
    monkeypatch.setenv("AWSTORAGE_NODE", "dgx-spark")
    assert identity.whoami(f) == "dgx-spark"
    monkeypatch.setenv("AWSTORAGE_NODE", "")
    f.write_text("not a valid id!", encoding="utf-8")
    assert identity.whoami(f) == identity.socket.gethostname()


def test_posix_volume_parse(monkeypatch):
    text = ("/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n"
            "/dev/sdb1 /mnt/data\\040disk xfs rw 0 0\n/dev/sda1 /bind ext4 rw 0 0\n"
            "//nas/s /mnt/nas cifs rw 0 0\n")
    monkeypatch.setattr(identity, "_usage", lambda m: (100, 40))
    vols = {v["mount"]: v for v in identity._posix_volumes(text)}
    assert set(vols) == {"/", "/mnt/data disk", "/mnt/nas"}
    assert vols["/mnt/nas"]["kind"] == "network"
    assert identity.list_volumes() is not None


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows reparse point")
def test_real_junction_is_refused_by_every_walker(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "big.bin").write_bytes(b"x" * 100_000)
    root = tmp_path / "root"
    root.mkdir()
    (root / "own.txt").write_bytes(b"y" * 1000)
    link = root / "link"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0 or not link.exists():
        pytest.skip(f"mklink /J unavailable here: {r.stdout} {r.stderr}")
    assert (link / "big.bin").exists(), "the junction really points at the target"
    snap = _fs.scan(root, max_depth=2, node="t")
    assert next(t for t in snap["trees"] if t["depth"] == 0)["bytes"] == 1000
    assert policy._tree_bytes(root) == 1000
    before = policy._current_fingerprint(root)
    (target / "more.bin").write_bytes(b"z" * 10)
    assert policy._current_fingerprint(root) == before, "a change behind a junction is not ours"
    db = F.open_index(tmp_path / "files.db")
    try:
        st = F.scan_files(db, [root], node="t", hash_mode="none")
        assert st["files_seen"] == 1
    finally:
        db.close()


def test_manage_passthrough_defaults_the_catalog(monkeypatch, tmp_path):
    from awstorage.cli import main
    got = {}
    fake = types.ModuleType("awstorage.manage")

    def fake_main(argv):
        got["argv"] = argv
        return 7
    fake.main = fake_main
    monkeypatch.setitem(sys.modules, "awstorage.manage", fake)
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "cat.db"))
    assert main(["manage", "shares", "--owner", "u1"]) == 7
    assert got["argv"] == ["--db", str(tmp_path / "cat.db"), "shares", "--owner", "u1"]
    assert main(["manage", "--db", "x.db", "apply", "3", "--root", "E:/", "--card",
                 "c.json"]) == 7
    assert got["argv"][:2] == ["--db", "x.db"]


def test_manage_absent_is_exit_2(monkeypatch):
    from awstorage.cli import main
    monkeypatch.setitem(sys.modules, "awstorage.manage", None)  # import -> ImportError
    assert main(["manage", "shares"]) == 2


def test_files_scan_all_volumes_skips_never_roots(monkeypatch, tmp_path, capsys):
    from awstorage import cli
    vol = tmp_path / "vol"
    (vol / "keep").mkdir(parents=True)
    (vol / "keep" / "a.txt").write_bytes(b"a")
    (vol / "node_modules").mkdir()
    (vol / "node_modules" / "b.js").write_bytes(b"b")
    monkeypatch.setattr(cli, "list_volumes", lambda: [
        {"mount": str(vol), "kind": "fixed"}, {"mount": "Z:/nope", "kind": "network"}])
    monkeypatch.setenv("AWSTORAGE_NODE", "n")
    idx = str(Path(tmp_path) / "f.db")
    assert cli.main(["files", "scan", "--all-volumes", "--index", idx, "--json",
                     "--hash", "none"]) == 0
    import json
    st = json.loads(capsys.readouterr().out)
    assert [r["root"] for r in st["roots"]] == [F.norm_root(vol)]
    assert st["files_seen"] == 2  # node_modules is INDEXED (never != excluded) ...
    db = F.open_index(idx)
    try:
        nm = db.execute("SELECT never FROM files WHERE name = 'b.js'").fetchone()[0]
        assert nm == 1  # ... but flagged never
    finally:
        db.close()
