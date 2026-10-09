"""A local stand-in for the Strata data routes, with tenant namespacing.

Plain http on 127.0.0.1, reachable only through the explicit
`insecure_http_for_tests=True` switch. It mirrors what the real service does with
a tenant bearer: the logical path `aither://<tier>/<rest>` is stored physically at
`aither://<tier>/__t__/<tenant>/<rest>`, and a path already carrying that segment
is left alone. The internal key keeps the flat namespace.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

KEY = "test-" + "internal-key"  # not a credential: compared literally
BEARERS = {"tok-" + "acme": "acme", "tok-" + "other": "other"}


def ns_encode(vp: str, tenant: Optional[str]) -> str:
    if not tenant:
        return vp
    raw = vp[len("aither://"):]
    tier, _, rest = raw.partition("/")
    seg = f"__t__/{tenant}"
    if rest == seg or rest.startswith(seg + "/"):
        return vp
    return f"aither://{tier}/{seg}/{rest}" if rest else f"aither://{tier}/{seg}"


class PoolStub:
    def __init__(self) -> None:
        self.objects: Dict[str, bytes] = {}
        self.headers_seen: List[dict] = []
        self.writes: List[str] = []
        self.corrupt_reads = False
        self.stat_status: Optional[int] = None
        handler = self._handler()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def _handler(self):
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *_a):  # quiet
                return

            def _send(self, code: int, body, raw: bool = False) -> None:
                data = body if raw else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type",
                                 "application/octet-stream" if raw else "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _caller(self):
                """(authed, tenant-or-None)."""
                stub.headers_seen.append(dict(self.headers.items()))
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    t = BEARERS.get(auth[len("Bearer "):])
                    return (t is not None), t
                return self.headers.get("X-Internal-Key") == KEY, None

            def do_GET(self):  # noqa: N802
                ok, tenant = self._caller()
                if not ok:
                    return self._send(401, {"detail": "Authentication required"})
                if self.path.startswith("/strata/stat/"):
                    if stub.stat_status:
                        return self._send(stub.stat_status, {"detail": "boom"})
                    vp = "aither://" + urllib.parse.unquote(self.path[len("/strata/stat/"):])
                    phys = ns_encode(vp, tenant)
                    if phys not in stub.objects:
                        return self._send(404, {"detail": "Not found"})
                    data = stub.objects[phys]
                    return self._send(200, {"path": vp, "size": len(data),
                                            "hash": hashlib.sha256(data).hexdigest()})
                if self.path.startswith("/strata/read?"):
                    q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    phys = ns_encode(q["path"][0], tenant)
                    if phys not in stub.objects:
                        return self._send(404, {"detail": "File not found"})
                    data = stub.objects[phys]
                    if stub.corrupt_reads:
                        data = b"rot" + data
                    return self._send(200, data, raw=True)
                return self._send(404, {"detail": "no route"})

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
                ok, tenant = self._caller()
                if not ok:
                    return self._send(401, {"detail": "Authentication required"})
                if self.path == "/strata/write":
                    phys = ns_encode(body["path"], tenant)
                    stub.objects[phys] = base64.b64decode(body["content"])
                    stub.writes.append(phys)
                    return self._send(200, {"success": True, "meta": {"path": body["path"]}})
                return self._send(404, {"detail": "no route"})

        return H

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
