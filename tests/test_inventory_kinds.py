"""awstorage 0.10.0: inventory retention + the hardware / software / services kinds.

GitHub is an in-memory fake (no network); collectors read fixture tool output.
"""

from __future__ import annotations

import gzip
import json
import subprocess
import types
from pathlib import Path

import pytest
from awstorage import autoindex
from awstorage import host_inventory as hi
from awstorage import inventory as inv

REPO = "Aitherium/inventory"
NODE = "box-7"
SECRET = "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"


class FakeGitHub:
    def __init__(self, tags=(), private=True, list_error=None):
        self.private = {REPO: private}
        self.releases: dict[str, dict[str, bytes]] = {t: {} for t in tags}
        self.order: list[str] = list(tags)
        self.files: dict[str, str] = {}
        self.deleted: list[str] = []
        self.list_error = list_error
        self.fail_delete: set[str] = set()

    def repo_private(self, repo):
        return self.private.get(repo)

    def list_releases(self, repo, prefix=""):
        if self.list_error:
            raise self.list_error
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

    def delete_release(self, repo, tag):
        if tag in self.fail_delete:
            raise RuntimeError("HTTP 500")
        self.deleted.append(tag)
        self.releases.pop(tag)
        self.order.remove(tag)


def _stamp(i: int) -> str:
    return f"202611{i:02d}T000000Z"


# ---------------------------------------------------------------- retention

def test_retention_keeps_newest_n_and_never_touches_latest_other_nodes_or_odd_names():
    own = [f"{NODE}-{_stamp(i)}" for i in range(1, 9)]              # 8 of ours
    others = [f"box-70-{_stamp(1)}", f"box-{_stamp(2)}", f"{NODE}-hardware-{_stamp(1)}",
              f"{NODE}-latest", f"{NODE}-{_stamp(3)}-manual", f"{NODE}-backup",
              f"{NODE}-2026-11-01", f"x{NODE}-{_stamp(1)}"]
    gh = FakeGitHub(own + others)
    res = inv.prune(node=NODE, repo=REPO, gh=gh, keep=5)
    assert res["pruned"] == own[:3] and gh.deleted == own[:3]
    assert set(own[3:]) <= set(gh.releases) and set(others) <= set(gh.releases)
    assert res["kept"] == own[3:] and not res["failed"]


def test_retention_per_kind_only_touches_that_kind():
    hw = [f"{NODE}-hardware-{_stamp(i)}" for i in range(1, 5)]
    files = [f"{NODE}-{_stamp(i)}" for i in range(1, 5)]
    gh = FakeGitHub(hw + files + [f"{NODE}-hardware-latest"])
    res = inv.prune(node=NODE, repo=REPO, gh=gh, kind="hardware", keep=2)
    assert res["pruned"] == hw[:2]
    assert set(files) <= set(gh.releases) and f"{NODE}-hardware-latest" in gh.releases


def test_failed_listing_deletes_nothing():
    gh = FakeGitHub([f"{NODE}-{_stamp(i)}" for i in range(1, 9)],
                    list_error=RuntimeError("gh release list: HTTP 502"))
    res = inv.prune(node=NODE, repo=REPO, gh=gh, keep=1)
    assert res["pruned"] == [] and gh.deleted == [] and "nothing deleted" in res["error"]


def test_failed_delete_is_reported_and_the_rest_continue():
    own = [f"{NODE}-{_stamp(i)}" for i in range(1, 5)]
    gh = FakeGitHub(own)
    gh.fail_delete = {own[0]}
    res = inv.prune(node=NODE, repo=REPO, gh=gh, keep=2)
    assert res["pruned"] == [own[1]] and res["failed"][0]["release"] == own[0]


def test_keep_env_default_and_floor(monkeypatch):
    monkeypatch.delenv(inv.KEEP_ENV, raising=False)
    assert inv.keep_count() == 5
    monkeypatch.setenv(inv.KEEP_ENV, "3")
    assert inv.keep_count() == 3
    monkeypatch.setenv(inv.KEEP_ENV, "junk")
    assert inv.keep_count() == 5
    assert inv.keep_count(0) == 1                      # the new release always survives


def test_protected_release_survives_even_with_clock_skew():
    own = [f"{NODE}-{_stamp(i)}" for i in range(1, 5)]
    gh = FakeGitHub(own)
    res = inv.prune(node=NODE, repo=REPO, gh=gh, keep=1, protect=own[0])
    assert own[0] in gh.releases and res["pruned"] == own[1:3]


def test_node_ids_that_collide_with_kind_naming_are_refused():
    for bad in ("db-hardware", "x-services", "y-software", "z-latest"):
        with pytest.raises(inv.InventoryError):
            inv._check_node(bad)
    assert inv._check_node("hardware-box") == "hardware-box"


def test_remote_nodes_separates_kinds():
    tags = [f"{NODE}-{_stamp(1)}", f"{NODE}-hardware-{_stamp(2)}", f"b-software-{_stamp(1)}"]
    assert inv.remote_nodes(tags) == {NODE: tags[0]}
    assert inv.remote_nodes(tags, "hardware") == {NODE: tags[1]}
    assert inv.remote_nodes(tags, "software") == {"b": tags[2]}
    assert inv.newest_release(tags, NODE, "hardware") == tags[1]


# ---------------------------------------------------------------- collectors

def _proc(stdout="", rc=0, stderr=""):
    return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


def _ctx(outputs: dict, *, have=None, system="Linux", winreg=None, files=None):
    """outputs: {argv[0]: stdout | Exception | (rc, stderr)}"""
    have = set(outputs) if have is None else set(have)

    def run(argv, **kw):
        got = outputs[argv[0]]
        if isinstance(got, Exception):
            raise got
        if isinstance(got, tuple):
            return _proc("", got[0], got[1])
        return _proc(got)

    def read_text(path):
        if files and path in files:
            return files[path]
        raise OSError(path)

    return hi.Ctx(run=run, which=lambda n: f"/usr/bin/{n}" if n in have else None,
                  winreg=winreg, system=system, psutil=None, read_text=read_text)


NVIDIA = "NVIDIA GeForce RTX 5090, 32607, 581.57\nNVIDIA RTX A2000, 6138, 581.57\n"
DPKG = ("bash\t5.2.15-2+b7\tii \n"
        "removed-pkg\t1.0\trc \n"
        "libssl3\t3.0.15-1~deb12u1\tii \n"
        f"evil\t{SECRET}\tii \n")
SYSTEMCTL = ("ssh.service loaded active running OpenBSD Secure Shell server\n"
             f"leaky.service loaded failed failed Runs with {SECRET} in its description\n"
             "cron.service loaded inactive dead Regular background program processing\n"
             "dev-sda1.device loaded active plugged /dev/sda1\n")
SC_QUERY = ("\nSERVICE_NAME: Appinfo\nDISPLAY_NAME: Application Information\n"
            "        TYPE               : 30  WIN32\n"
            "        STATE              : 4  RUNNING\n"
            "\nSERVICE_NAME: wuauserv\n        STATE              : 1  STOPPED\n")
PODMAN = "aitheros-genesis-a\trunning\naitheros-veil\texited\n"


def test_parse_nvidia_smi_csv():
    g = hi.parse_nvidia_smi(NVIDIA)
    assert g == [{"name": "NVIDIA GeForce RTX 5090", "vram_mb": 32607, "driver": "581.57"},
                 {"name": "NVIDIA RTX A2000", "vram_mb": 6138, "driver": "581.57"}]


def test_parse_dpkg_query_keeps_installed_only():
    rows = hi.parse_dpkg_query(DPKG)
    assert [r["name"] for r in rows] == ["bash", "libssl3", "evil"]
    assert rows[0] == {"source": "dpkg", "name": "bash", "version": "5.2.15-2+b7"}


def test_parse_systemctl_drops_descriptions_and_non_services():
    rows = hi.parse_systemctl(SYSTEMCTL)
    assert [r["name"] for r in rows] == ["ssh.service", "leaky.service", "cron.service"]
    assert rows[0] == {"source": "systemd", "name": "ssh.service", "load": "loaded",
                       "state": "active", "sub": "running"}
    assert "Secure" not in json.dumps(rows) and "ghp_" not in json.dumps(rows)


def test_parse_sc_query_and_container_ps():
    assert hi.parse_sc_query(SC_QUERY) == [
        {"source": "windows", "name": "Appinfo", "state": "running"},
        {"source": "windows", "name": "wuauserv", "state": "stopped"}]
    assert hi.parse_container_ps(PODMAN, "podman")[1] == {
        "source": "podman", "name": "aitheros-veil", "state": "exited"}


class FakeWinreg:
    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"

    def __init__(self, tree):
        self.tree = tree          # {(hive, path): {subkey: {value: data}}}

    def OpenKey(self, parent, sub):  # noqa: N802 - winreg's names
        if isinstance(parent, tuple):
            vals = self.tree[parent].get(sub)
            if vals is None:
                raise OSError(sub)
            return ("leaf", vals)
        if (parent, sub) not in self.tree:
            raise FileNotFoundError(sub)
        return (parent, sub)

    def EnumKey(self, key, i):  # noqa: N802
        subs = list(self.tree[key])
        if i >= len(subs):
            raise OSError("no more")
        return subs[i]

    def QueryValueEx(self, key, name):  # noqa: N802
        vals = key[1]
        if name not in vals:
            raise FileNotFoundError(name)
        return vals[name], 1

    def CloseKey(self, key):  # noqa: N802
        pass


UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


def test_winreg_uninstall_keys_never_read_command_lines():
    reg = FakeWinreg({("HKLM", UNINSTALL): {
        "{A}": {"DisplayName": "7-Zip 24.08", "DisplayVersion": "24.08", "Publisher": "Igor",
                "UninstallString": f"C:\\7z\\uninst.exe --{SECRET}"},
        "{B}": {"UninstallString": "no name, skipped"},
        "{C}": {"DisplayName": "Leaky", "DisplayVersion": SECRET}},
        ("HKCU", UNINSTALL): {"{D}": {"DisplayName": "7-Zip 24.08", "DisplayVersion": "24.08"}}})
    rows = hi.read_uninstall_keys(reg)
    assert [r["name"] for r in rows] == ["7-Zip 24.08", "Leaky"]          # deduped
    assert rows[0] == {"source": "windows", "name": "7-Zip 24.08", "version": "24.08",
                       "publisher": "Igor"}
    doc = hi.collect("software", _ctx({}, system="Windows", winreg=reg))
    text = json.dumps(doc)
    assert "uninst.exe" not in text and "ghp_" not in text and "TOKEN" not in text
    assert any(p["name"] == "7-Zip 24.08" for p in doc["packages"])


def test_hardware_collects_gpus_and_degrades_without_nvidia_smi():
    doc = hi.collect("hardware", _ctx({"nvidia-smi": NVIDIA}, files={
        "/proc/cpuinfo": "processor\t: 0\nmodel name\t: AMD Ryzen 9 9950X\n",
        "/proc/meminfo": "MemTotal:       65536000 kB\n", "/proc/mounts": ""}))
    assert doc["gpus"][0]["vram_mb"] == 32607 and doc["cpu"]["model"] == "AMD Ryzen 9 9950X"
    assert doc["ram_bytes"] == 65536000 * 1024 and doc["hostname"]
    doc = hi.collect("hardware", _ctx({}, files={"/proc/mounts": ""}))
    assert doc["gpus"] == []
    assert {"source": "gpu:nvidia-smi", "reason": "nvidia-smi not found"} in doc["unavailable"]


def test_missing_failing_and_hanging_tools_are_recorded_not_raised():
    ctx = _ctx({"systemctl": (1, "Failed to connect to bus"),
                "podman": subprocess.TimeoutExpired("podman", 20)},
               have={"systemctl", "podman"})
    doc = hi.collect("services", ctx)
    srcs = {u["source"]: u["reason"] for u in doc["unavailable"]}
    assert "exit 1" in srcs["systemd"] and "Failed to connect" in srcs["systemd"]
    assert "TimeoutExpired" in srcs["podman"] and srcs["docker"] == "docker not found"
    doc = hi.collect("software", _ctx({}, have=()))
    assert {"source": "dpkg", "reason": "dpkg-query not found"} in doc["unavailable"]
    assert doc["pip"]                                     # the interpreter still answers


def test_a_collector_that_raises_never_crashes_the_publish(monkeypatch):
    def boom(ctx):
        raise RuntimeError("parser surprise")
    monkeypatch.setitem(hi.COLLECTORS, "services", boom)
    doc = hi.collect("services", _ctx({}))
    assert doc["rows"] == 0 and "parser surprise" in doc["unavailable"][0]["reason"]


def test_secrets_never_appear_in_any_kind():
    ctx = _ctx({"dpkg-query": DPKG, "systemctl": SYSTEMCTL,
                "podman": f"web\trunning\n{SECRET}\trunning\n", "nvidia-smi": NVIDIA},
               files={"/proc/mounts": ""})
    for kind in hi.KIND_NAMES:
        text = json.dumps(hi.collect(kind, ctx))
        assert "ghp_" not in text and "TOKEN=" not in text, kind
    assert hi.scrub({"a": ["ok", "API_KEY: x", "sk-ant-123", "FOO=bar"]}) == {
        "a": ["ok", hi.REDACTED, hi.REDACTED, hi.REDACTED]}


def test_services_collects_systemd_and_containers():
    doc = hi.collect("services", _ctx({"systemctl": SYSTEMCTL, "podman": PODMAN},
                                      have={"systemctl", "podman"}))
    assert len(doc["services"]) == 3 and len(doc["containers"]) == 2 and doc["rows"] == 5


# ---------------------------------------------------------------- end to end (awseal)

@pytest.fixture()
def env(tmp_path, monkeypatch):
    awseal = pytest.importorskip("awseal")
    pytest.importorskip("awrtifact")
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "home" / "catalog.db"))
    monkeypatch.setenv(inv.CACHE_ENV, str(tmp_path / "cache"))
    monkeypatch.setenv(inv.ANNOUNCE_ENV, "0")
    monkeypatch.delenv(inv.KEEP_ENV, raising=False)
    key = tmp_path / "keys" / "node.key"
    awseal.keygen(key)
    monkeypatch.setenv("AWSEAL_KEY_PATH", str(key))
    fixture = _ctx({"nvidia-smi": NVIDIA, "systemctl": SYSTEMCTL, "podman": PODMAN,
                    "dpkg-query": DPKG}, files={"/proc/mounts": ""})
    for k in hi.KIND_NAMES:
        monkeypatch.setattr(inv.KINDS[k], "export", hi.make_export(k, lambda: fixture))
    return types.SimpleNamespace(tmp=tmp_path, src=tmp_path / "idx" / "files.db")


def test_hardware_publish_pull_show_and_retention(env, capsys):
    gh = FakeGitHub([f"{NODE}-{_stamp(1)}"])                # a files release, untouched
    tags = []
    for i in range(7):
        res = inv.publish(node=NODE, repo=REPO, src=env.src, gh=gh, kind="hardware",
                          announce_channel=None, now=1_900_000_000 + i * 3600)
        tags.append(res["release"])
    assert all(t.startswith(f"{NODE}-hardware-") for t in tags)
    assert res["retention"]["pruned"] == [tags[1]] and res["retention"]["keep"] == 5
    assert set(tags[2:]) <= set(gh.releases) and tags[0] not in gh.releases
    assert f"{NODE}-{_stamp(1)}" in gh.releases
    ptr = json.loads(gh.releases[f"{NODE}-hardware-latest"]["latest.json"])
    assert ptr["release"] == tags[-1] and ptr["kind"] == "hardware"
    with pytest.raises(inv.InventoryError):
        inv.pull(node=NODE, repo=REPO, gh=gh)       # the files release has no assets

    got = inv.pull(node=NODE, repo=REPO, gh=gh, kind="hardware")
    assert got["release"] == tags[-1] and got["kind"] == "hardware"
    assert inv.main(["query", "show", NODE, "--kind", "hardware", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["gpus"][0]["name"] == "NVIDIA GeForce RTX 5090" and doc["node"] == NODE
    assert inv.main(["query", "show", NODE, "--kind", "hardware"]) == 0
    assert "RTX 5090" in capsys.readouterr().out
    assert inv.main(["query", "show", NODE, "--kind", "software"]) == 2


def test_pull_refuses_a_release_of_another_kind(env):
    gh = FakeGitHub()
    res = inv.publish(node=NODE, repo=REPO, src=env.src, gh=gh, kind="services",
                      announce_channel=None)
    with pytest.raises(inv.RefusedError):
        inv.pull(node=NODE, repo=REPO, gh=gh, kind="software", release=res["release"])


def test_software_and_services_publish_carry_no_secrets(env):
    gh = FakeGitHub()
    for kind in ("software", "services"):
        res = inv.publish(node=NODE, repo=REPO, src=env.src, gh=gh, kind=kind,
                          announce_channel=None)
        assets = gh.releases[res["release"]]
        blob = b"".join(v for n, v in assets.items() if ".part" in n)
        text = gzip.decompress(blob).decode()
        assert "ghp_" not in text and "TOKEN=" not in text
        assert json.loads(text)["kind"] == kind


# ---------------------------------------------------------------- files sync cadence

def _runner(calls: list, fail: set | None = None):
    def run(argv, stdout=None, stderr=None, env=None):
        step = argv[4] + (f":{argv[argv.index('--kind') + 1]}" if "--kind" in argv else "")
        calls.append(step)
        rc = 1 if fail and step in fail else 0
        if rc:
            stderr.write(f"{step} broke".encode())
        elif argv[4] == "publish":
            stdout.write(json.dumps({"release": f"r-{step}", "rows": 3,
                                     "retention": {"pruned": []}}).encode())
        return types.SimpleNamespace(returncode=rc)
    return run


def test_sync_publishes_host_kinds_at_most_daily(tmp_path, monkeypatch):
    monkeypatch.delenv(autoindex.KINDS_EVERY_ENV, raising=False)
    cfg = {"index_dir": str(tmp_path / "i"), "node": NODE, "inventory_publish": True}
    calls: list = []
    rec = autoindex.run_pass(cfg, run=_runner(calls, {"publish:software"}), python="py")
    assert calls == ["scan", "push", "publish", "publish:hardware", "publish:software",
                     "publish:services"]
    assert rec["exit_code"] == 0 and rec["kinds"]["hardware"]["release"] == "r-publish:hardware"
    assert rec["kinds"]["software"]["exit"] == 1
    calls.clear()
    rec = autoindex.run_pass(cfg, run=_runner(calls), python="py")
    assert calls == ["scan", "push", "publish", "publish:software"]   # only the failed one
    assert rec["kinds"]["hardware"]["skipped"] == "not due"
    calls.clear()
    autoindex.run_pass(cfg, run=_runner(calls), python="py")
    assert calls == ["scan", "push", "publish"]
    state = json.loads((tmp_path / "i" / autoindex.KINDS_STATE).read_text())
    state["services"] -= 25 * 3600
    (tmp_path / "i" / autoindex.KINDS_STATE).write_text(json.dumps(state))
    calls.clear()
    autoindex.run_pass(cfg, run=_runner(calls), python="py")
    assert calls == ["scan", "push", "publish", "publish:services"]


def test_sync_without_publish_runs_no_kinds(tmp_path):
    calls: list = []
    autoindex.run_pass({"index_dir": str(tmp_path / "i"), "node": NODE}, run=_runner(calls),
                       python="py")
    assert calls == ["scan", "push"]
