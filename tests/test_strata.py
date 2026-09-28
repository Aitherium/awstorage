"""`--harvest-to strata:<tier>` against a local stub of the AitherStrata routes.

The stub is plain http, reachable ONLY through the explicit
`strata_insecure_http_for_tests=True` switch; the same URL without it must be
refused (the real service is TLS-only and a key must never cross in the clear).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import awstorage
import pytest
from awstorage.strata import StrataTarget, StrataUnavailableError, find_ca, parse_spec

KEY = "test-" + "internal-key"  # not a credential: the stub compares it literally


class _Stub:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.keys_seen: list[str] = []
        self.callers: list[str] = []
        self.size_skew = 0
        self.hash_override: str | None = None
        self.report_hash = True
        handler = self._handler()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def _handler(self):
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *_a):  # quiet
                pass

            def _send(self, code: int, body: dict) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authed(self) -> bool:
                stub.keys_seen.append(self.headers.get("X-Internal-Key", ""))
                stub.callers.append(self.headers.get("X-Caller-Service", ""))
                return self.headers.get("X-Internal-Key") == KEY

            def do_GET(self):  # noqa: N802
                if self.path == "/health":
                    return self._send(200, {"status": "healthy"})
                if not self._authed():
                    return self._send(401, {"detail": "Authentication required"})
                if self.path.startswith("/strata/stat/"):
                    vp = "aither://" + urllib.parse.unquote(self.path[len("/strata/stat/"):])
                    if vp not in stub.objects:
                        return self._send(404, {"detail": "Not found"})
                    data = stub.objects[vp]
                    body = {"path": vp, "size": len(data) + stub.size_skew}
                    if stub.report_hash:
                        body["hash"] = stub.hash_override or hashlib.sha256(data).hexdigest()
                    return self._send(200, body)
                return self._send(404, {"detail": "no route"})

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
                if not self._authed():
                    return self._send(401, {"detail": "Authentication required"})
                if self.path == "/strata/write":
                    stub.objects[body["path"]] = base64.b64decode(body["content"])
                    return self._send(200, {"success": True, "meta": {"path": body["path"]}})
                return self._send(404, {"detail": "no route"})

        return H

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def stub():
    s = _Stub()
    yield s
    s.close()


def _mk(p: Path, data: bytes, age_h: float = 30.0) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    t = time.time() - age_h * 3600
    os.utime(p, (t, t))


def _world(tmp_path: Path) -> Path:
    root = tmp_path / "r"
    _mk(root / "sess" / "REPORT.md", b"# report")
    _mk(root / "sess" / "big.bin", b"\x00" * 64)
    return root


def _pol(root: Path) -> dict:
    return {"retention": [{"name": "t", "paths": [root.as_posix() + "/*"],
                           "class": "build-temp", "max_idle": "10h", "action": "delete"}]}


def _sweep(root: Path, tmp_path: Path, url: str, **kw):
    kw.setdefault("env", {"AWSTORAGE_STRATA_KEY": KEY})
    kw.setdefault("strata_insecure_http_for_tests", True)
    return awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to="strata:cold",
                           strata_url=url, seal=False, strata_staging=tmp_path / "stage",
                           receipt=tmp_path / "rc.json", **kw)


def test_parse_spec():
    assert parse_spec("strata:cold") == "cold" and parse_spec("strata:HOT") == "hot"
    assert parse_spec("strata") == "cold" and parse_spec("strata:") == "cold"
    assert parse_spec("E:/harvest") is None and parse_spec(None) is None
    assert parse_spec("strata-shelf") is None
    with pytest.raises(ValueError):
        parse_spec("strata:lukewarm")


def test_upload_verified_then_removal_allowed(stub, tmp_path):
    root = _world(tmp_path)
    rec = _sweep(root, tmp_path, stub.url)
    assert rec["exit_code"] == 0, rec["errors"] + rec["could_not_judge"]
    assert not (root / "sess").exists()
    names = sorted(k.rsplit("/", 1)[1] for k in stub.objects)
    assert names == ["REPORT.md", "manifest.json"]
    [report] = [k for k in stub.objects if k.endswith("REPORT.md")]
    assert report.startswith("aither://cold/awstorage/harvest/")
    assert stub.objects[report] == b"# report"
    assert set(stub.keys_seen) == {KEY} and set(stub.callers) == {"awstorage"}
    assert rec["strata"]["uploaded"] == 2 and rec["harvest_to"] == "strata:cold"
    assert not any((tmp_path / "stage").rglob("REPORT.md"))  # staging copy dropped


def test_size_mismatch_keeps_the_item(stub, tmp_path):
    root = _world(tmp_path)
    stub.size_skew = 1
    rec = _sweep(root, tmp_path, stub.url)
    assert rec["exit_code"] == 1 and (root / "sess" / "REPORT.md").exists()
    assert "size" in rec["errors"][0]


def test_hash_mismatch_keeps_the_item_and_no_hash_checks_size_only(stub, tmp_path):
    root = _world(tmp_path)
    stub.hash_override = "0" * 64
    rec = _sweep(root, tmp_path, stub.url)
    assert rec["exit_code"] == 1 and (root / "sess").exists() and "sha256" in rec["errors"][0]
    stub.hash_override = None
    stub.report_hash = False
    rec = _sweep(root, tmp_path, stub.url)
    assert rec["exit_code"] == 0 and not (root / "sess").exists()


def test_unreachable_keeps_items_and_exits_2(tmp_path):
    root = _world(tmp_path)
    with socket.socket() as s:  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    rec = _sweep(root, tmp_path, f"http://127.0.0.1:{port}")
    assert rec["exit_code"] == 2 and (root / "sess").exists()
    assert "strata target unavailable" in rec["could_not_judge"][0]
    got = json.loads((tmp_path / "rc.json").read_text(encoding="utf-8"))
    assert got["exit_code"] == 2


def test_missing_key_and_plain_http_without_the_test_switch_fail_closed(stub, tmp_path):
    root = _world(tmp_path)
    rec = _sweep(root, tmp_path, stub.url, env={})
    assert rec["exit_code"] == 2 and "AWSTORAGE_STRATA_KEY" in rec["could_not_judge"][0]
    rec = _sweep(root, tmp_path, stub.url, strata_insecure_http_for_tests=False)
    assert rec["exit_code"] == 2 and "plain http" in rec["could_not_judge"][0]
    assert (root / "sess").exists() and stub.objects == {}


def test_https_without_a_ca_bundle_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    t = StrataTarget("cold", url="https://127.0.0.1:1", key=KEY, env={}, ca="")
    with pytest.raises(StrataUnavailableError, match="CA bundle"):
        t.check()
    assert find_ca({"AITHER_CA_BUNDLE": str(tmp_path / "missing.pem")}) is None


def test_strata_down_mid_pass_stops_further_removals(stub, tmp_path):
    root = tmp_path / "r"
    for n in ("a", "b", "c"):
        _mk(root / n / "R.md", n.encode())
    calls = {"n": 0}
    orig = StrataTarget.put

    def flaky(self, rel, data, metadata=None):
        calls["n"] += 1
        if calls["n"] > 2:  # first item (R.md + manifest) lands, then the service dies
            raise StrataUnavailableError("connection refused")
        return orig(self, rel, data, metadata)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(StrataTarget, "put", flaky)
    try:
        rec = _sweep(root, tmp_path, stub.url)
    finally:
        monkeypatch.undo()
    assert rec["exit_code"] == 2
    assert not (root / "a").exists() and (root / "b").exists() and (root / "c").exists()


def test_seal_travels_with_the_upload(stub, tmp_path):
    awseal = pytest.importorskip("awseal")
    try:
        key = awseal.keygen(tmp_path / "k" / "signing.key")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"awseal cannot generate a key: {exc}")
    root = _world(tmp_path)
    rec = awstorage.sweep(policy=_pol(root), dry_run=False, harvest_to="strata:warm",
                          strata_url=stub.url, seal_key=key, env={"AWSTORAGE_STRATA_KEY": KEY},
                          strata_insecure_http_for_tests=True, strata_staging=tmp_path / "st")
    assert rec["exit_code"] == 0, rec["errors"] + rec["could_not_judge"]
    names = sorted(k.rsplit("/", 1)[1] for k in stub.objects)
    assert names == ["REPORT.md", "awseal.json", "manifest.json"]
    assert all(k.startswith("aither://warm/") for k in stub.objects)
