"""Mesh auto file index (2026-11-07): an enrolled device indexes itself as the node id it
REGISTERED with, pushes with its OWN enrolment token (never a tenant it names), and a
failed scan or push is a non-zero exit with a receipt -- never a silent success.

Every test here fails on the code before this change: `whoami` returned the hostname for
an enrolled device, there was no node-token transport, and no `files sync`/`schedule`.
"""

from __future__ import annotations

import io
import json
import types
import urllib.error
from pathlib import Path

import pytest
from awstorage import autoindex, cli, identity, remote
from awstorage.remote import GatewayError, NodeTokenClient, load_node_credential


def _enrolled(tmp_path: Path, node: str = "adk-1e1233bd-e4b01ad2",
              token: str = "tok.sig") -> Path:
    aither = tmp_path / ".aither"
    aither.mkdir(parents=True, exist_ok=True)
    (aither / "node_auth.json").write_text(json.dumps(
        {"node_id": node, "bearer_token": token, "tenant_id": "tnt_x"}), encoding="utf-8")
    return aither / "node-id"  # absent on purpose: enrolment never wrote it


# ---------------------------------------------------------------- node id = registered id

def test_whoami_is_the_registered_id_not_the_hostname(tmp_path, monkeypatch):
    monkeypatch.delenv("AWSTORAGE_NODE", raising=False)
    f = _enrolled(tmp_path)
    assert identity.whoami(f) == "adk-1e1233bd-e4b01ad2"
    assert identity.whoami_source(f).startswith("registration:")
    assert identity.whoami(f) != identity.socket.gethostname()


def test_join_sh_node_token_file_is_read(tmp_path):
    f = tmp_path / "node-token"
    f.write_text("AITHER_NODE_TOKEN=abc.def\nAITHER_NODE_ID=box-7\n"
                 "AITHER_NODE_TOKEN_EXPIRES=2026-12-01\n", encoding="utf-8")
    assert identity.read_registration(f) == {"node_id": "box-7", "token": "abc.def",
                                             "tenant_id": ""}


def test_unenrolled_device_still_falls_back_to_hostname(tmp_path, monkeypatch):
    monkeypatch.delenv("AWSTORAGE_NODE", raising=False)
    f = tmp_path / ".aither" / "node-id"
    assert identity.whoami(f) == identity.socket.gethostname()
    with pytest.raises(GatewayError, match="no enrollment credential"):
        load_node_credential(f)


# ---------------------------------------------------------------- node-token transport

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(record: list, status: int = 200, body: dict | None = None):
    def _open(req, timeout=None, context=None):
        record.append(req)
        payload = json.dumps(body if body is not None else {"written": 2}).encode()
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "x", {}, io.BytesIO(payload))
        return _Resp(payload)
    return _open


def test_push_carries_only_the_node_token_and_names_no_tenant():
    seen: list = []
    c = NodeTokenClient("box-7", "tok.sig", base_url="https://api.example",
                        opener=_opener(seen))
    out = c.call_tool("storage_ingest_files", {"node_id": "box-7",
                                               "body_json": json.dumps({"upserts": []})})
    assert out == {"written": 2}
    req = seen[0]
    assert req.full_url == "https://api.example/v1/storage/files/box-7"
    assert req.get_method() == "POST"
    hdrs = {k.lower(): v for k, v in req.header_items()}
    assert hdrs["authorization"] == "Bearer tok.sig"
    assert not any("tenant" in k or "internal" in k for k in hdrs)
    assert "tenant" not in json.loads(req.data)


def test_push_refuses_another_node_and_plain_http_and_other_tools():
    c = NodeTokenClient("box-7", "t", base_url="https://api.example", opener=_opener([]))
    with pytest.raises(GatewayError, match="credential is for node 'box-7'"):
        c.call_tool("storage_ingest_files", {"node_id": "optiplex", "body_json": "{}"})
    with pytest.raises(GatewayError, match="only index pushes"):
        c.call_tool("storage_ingest_scan", {"node_id": "box-7"})
    with pytest.raises(GatewayError, match="must be https"):
        NodeTokenClient("box-7", "t", base_url="http://api.example")


def test_refused_push_raises_and_409_is_a_resync():
    c = NodeTokenClient("box-7", "t", base_url="https://api.example",
                        opener=_opener([], 403, {"detail": "not a device of its tenant"}))
    with pytest.raises(GatewayError, match="HTTP 403: not a device"):
        c.call_tool("storage_ingest_files", {"node_id": "box-7", "body_json": "{}"})
    c = NodeTokenClient("box-7", "t", base_url="https://api.example",
                        opener=_opener([], 409, {"detail": {"resync": True, "last_seq": 4}}))
    assert remote._is_resync(c.call_tool("storage_ingest_files",
                                         {"node_id": "box-7", "body_json": "{}"}))


def test_cli_push_uses_the_device_credential_and_refuses_a_foreign_node(tmp_path, monkeypatch,
                                                                        capsys):
    f = _enrolled(tmp_path, node="box-7")
    monkeypatch.setattr(identity, "NODE_ID_FILE", f)
    monkeypatch.setattr(remote, "DEFAULT_BEARER_FILE", tmp_path / "no-session-bearer")
    monkeypatch.delenv("AWSTORAGE_GATEWAY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    rc = cli.main(["files", "push", "--index", str(tmp_path / "files.db"), "--node", "optiplex"])
    assert rc == 1 and "enrolled as 'box-7'" in capsys.readouterr().out
    assert cli._push_via_node_token(types.SimpleNamespace(
        node_token=False, api=None, gateway=None, bearer_file=None))


# ---------------------------------------------------------------- files sync receipt

def _runner(codes: dict, calls: list):
    def run(argv, stdout=None, stderr=None, env=None):
        step = argv[4]  # python -m awstorage files <step>
        calls.append((step, env.get("AWSTORAGE_NODE"), env.get("SQLITE_TMPDIR")))
        rc = codes.get(step, 0)
        if rc:
            stderr.write(f"{step} broke: disk on fire".encode())
        return types.SimpleNamespace(returncode=rc)
    return run


def test_sync_scan_failure_is_reported_and_push_never_runs(tmp_path):
    calls: list = []
    rec = autoindex.run_pass({"index_dir": str(tmp_path / "idx"), "node": "box-7"},
                             run=_runner({"scan": 3}, calls), python="py")
    assert rec["exit_code"] == 3 and rec["failed_step"] == "scan"
    assert "disk on fire" in rec["error"] and rec["push_exit"] is None
    assert [c[0] for c in calls] == ["scan"]
    on_disk = json.loads((tmp_path / "idx" / "last_run.json").read_text(encoding="utf-8"))
    assert on_disk["exit_code"] == 3 and on_disk["failed_step"] == "scan"


def test_sync_push_failure_is_reported(tmp_path):
    rec = autoindex.run_pass({"index_dir": str(tmp_path / "idx"), "node": "box-7"},
                             run=_runner({"push": 1}, []), python="py")
    assert rec["exit_code"] == 1 and rec["failed_step"] == "push" and rec["scan_exit"] == 0


def test_sync_ok_pins_node_and_keeps_sqlite_temp_beside_the_index(tmp_path):
    calls: list = []
    rec = autoindex.run_pass({"index_dir": str(tmp_path / "idx"), "node": "box-7"},
                             run=_runner({}, calls), python="py")
    assert rec["exit_code"] == 0 and rec["failed_step"] is None
    assert {c[1] for c in calls} == {"box-7"}
    assert {c[2] for c in calls} == {str(tmp_path / "idx" / "tmp")}


# ---------------------------------------------------------------- files schedule

def _ok_run(calls: list):
    def run(argv, **kw):
        calls.append(list(argv))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


@pytest.fixture()
def enrolled_home(tmp_path, monkeypatch):
    f = _enrolled(tmp_path, node="box-7")
    monkeypatch.setattr(identity, "NODE_ID_FILE", f)
    monkeypatch.delenv("AWSTORAGE_NODE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path


def test_schedule_refuses_an_unenrolled_device(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "NODE_ID_FILE", tmp_path / ".aither" / "node-id")
    monkeypatch.delenv("AWSTORAGE_NODE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    calls: list = []
    out = autoindex.schedule(index_dir=str(tmp_path / "i"), run=_ok_run(calls),
                             which=lambda _n: None, platform="windows",
                             cfg_path=tmp_path / "cfg.json")
    assert out["ok"] is False and "not enrolled" in out["detail"] and calls == []


def test_schedule_windows_task_runs_sync_as_the_registered_node(enrolled_home):
    calls: list = []
    cfg = enrolled_home / "cfg.json"
    out = autoindex.schedule(index_dir=str(enrolled_home / "i"), run=_ok_run(calls),
                             which=lambda _n: None, platform="windows", python="py",
                             cfg_path=cfg)
    assert out["ok"] and out["scheduler"] == "windows-task" and out["node"] == "box-7"
    task = calls[-1]
    assert task[:2] == ["schtasks", "/create"] and "AitherFileIndex" in task
    assert "files sync" in task[task.index("/tr") + 1]
    assert json.loads(cfg.read_text(encoding="utf-8"))["node"] == "box-7"


def test_schedule_prefers_awrise_where_present(enrolled_home):
    calls: list = []
    out = autoindex.schedule(index_dir=str(enrolled_home / "i"), run=_ok_run(calls),
                             which=lambda n: "/x/awrise" if n == "awrise" else None,
                             platform="linux", python="py",
                             cfg_path=enrolled_home / "cfg.json")
    assert out["scheduler"] == "awrise" and out["ok"]
    add = next(c for c in calls if c[:2] == ["awrise", "add"])
    assert add[add.index("--every") + 1] == "6h" and "files sync" in add[add.index("--run") + 1]


def test_schedule_scheduler_failure_is_returned_not_swallowed(enrolled_home):
    def run(argv, **kw):
        return types.SimpleNamespace(returncode=1, stdout="", stderr="Access is denied.")
    out = autoindex.schedule(index_dir=str(enrolled_home / "i"), run=run,
                             which=lambda _n: None, platform="windows", python="py",
                             cfg_path=enrolled_home / "cfg.json")
    assert out["ok"] is False and "Access is denied" in out["detail"]


def test_systemd_and_launchd_units_run_sync():
    service, timer = autoindex.systemd_units(["py", "-m", "awstorage", "files", "sync"], 6)
    assert "ExecStart=py -m awstorage files sync" in service and "OnUnitActiveSec=6h" in timer
    plist = autoindex.launchd_plist(["py", "-m", "awstorage", "files", "sync"], 6)
    assert "<integer>21600</integer>" in plist and "<string>sync</string>" in plist


def test_index_dir_moves_off_a_low_system_drive():
    home = autoindex._home_mount()
    free = {home: 8 * 1024 ** 3}
    vols = [{"mount": home, "free_bytes": 8 * 1024 ** 3},
            {"mount": "D:/", "free_bytes": 170 * 1024 ** 3},
            {"mount": "Z:/", "free_bytes": 900 * 1024 ** 3, "kind": "network"}]
    idx, why = autoindex.pick_index_dir(vols, free_of=lambda m: free.get(m, 0))
    assert idx == Path("D:/") / "AitherOS-Data" / "awstorage" and "low" in why
    idx, _ = autoindex.pick_index_dir(vols, free_of=lambda m: 500 * 1024 ** 3)
    assert idx == autoindex.default_index_dir()
