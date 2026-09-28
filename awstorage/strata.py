"""AitherStrata as a harvest target: `--harvest-to strata:<tier>`.

Strata is the platform's tiered storage service, not a brick, so this speaks its
HTTP API with the stdlib (urllib + ssl) and nothing else. The routes are the ones
the SERVER serves (services/infrastructure/AitherStrata.py), read 2026-09-27:

    POST /strata/write        {"path": "aither://<tier>/...", "content": <b64>,
                               "tier": <tier>, "file_type": "unknown",
                               "tags": [...], "metadata": {...}}
                              -> 200 {"success": true, "meta": {...}}
    GET  /strata/stat/<tier>/<path>
                              -> 200 {"size": N, "hash": <sha256 hex>, ...}

(The monorepo client also names GET /strata/metadata; the server has no such
route, so it is not used here.)

Auth is `X-Internal-Key` read from AWSTORAGE_STRATA_KEY -- the env var ONLY, never
a file this package would have to invent a location for -- plus
`X-Caller-Service: awstorage`, which Strata's path RBAC keys on.

TLS is verified, always. The URL comes from AITHERSTRATA_URL (default
https://127.0.0.1:8136; plain http to that port fails -- the service is TLS-only),
the CA from AITHER_CA_BUNDLE or <repo>/AitherOS/Library/Data/tls/ca-chain.pem when
one is found. No CA = unavailable. There is no verify=False anywhere; the only
plain-http path is an explicit test switch that the CLI does not expose.

Every upload is VERIFIED by reading the object's stat back: size must match, and
the sha256 must match when the server reports one. Until that holds for every
file of an item, the item is not removed.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

TIERS = ("hot", "warm", "cold")
DEFAULT_URL = "https://127.0.0.1:8136"
KEY_ENV = "AWSTORAGE_STRATA_KEY"
URL_ENV = "AITHERSTRATA_URL"
CA_ENV = "AITHER_CA_BUNDLE"
CA_REL = Path("AitherOS") / "Library" / "Data" / "tls" / "ca-chain.pem"


class StrataUnavailableError(RuntimeError):
    """The target cannot be used at all (config, CA, key, or unreachable)."""


def parse_spec(spec: str | os.PathLike | None) -> Optional[str]:
    """'strata:cold' -> 'cold'; 'strata:' / 'strata' -> 'cold'; a path -> None."""
    if spec is None:
        return None
    s = str(spec)
    if not s.lower().startswith("strata"):
        return None
    rest = s[len("strata"):]
    if rest and not rest.startswith(":"):
        return None  # e.g. a directory literally named "strata-shelf"
    tier = rest[1:].strip().lower() or "cold"
    if tier not in TIERS:
        raise ValueError(f"strata tier {tier!r} is not one of {TIERS}")
    return tier


def find_ca(env: Mapping[str, str] | None = None) -> Optional[str]:
    """AITHER_CA_BUNDLE, else <repo>/AitherOS/Library/Data/tls/ca-chain.pem found by
    walking up from the CWD, AITHER_REPO_ROOT, and this package's own location."""
    e = os.environ if env is None else env
    explicit = (e.get(CA_ENV) or "").strip()
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    starts = [Path.cwd(), Path(__file__).resolve().parent]
    if e.get("AITHER_REPO_ROOT"):
        starts.insert(0, Path(e["AITHER_REPO_ROOT"]))
    for start in starts:
        for d in [start, *start.parents]:
            cand = d / CA_REL
            if cand.is_file():
                return str(cand)
    return None


class StrataTarget:
    """One tier of one Strata endpoint, used by a single sweep pass."""

    def __init__(self, tier: str = "cold", *, url: str | None = None, key: str | None = None,
                 ca: str | None = None, env: Mapping[str, str] | None = None,
                 timeout: float = 30.0, insecure_http_for_tests: bool = False) -> None:
        e = os.environ if env is None else env
        if tier not in TIERS:
            raise ValueError(f"strata tier {tier!r} is not one of {TIERS}")
        self.tier = tier
        self.url = (url or e.get(URL_ENV) or DEFAULT_URL).rstrip("/")
        self.key = key if key is not None else (e.get("AWSTORAGE_STRATA_KEY") or "")
        self.timeout = timeout
        self._insecure_http = insecure_http_for_tests
        self._ca = ca if ca is not None else find_ca(e)
        self._ctx: Optional[ssl.SSLContext] = None

    # -- plumbing ------------------------------------------------------------------

    def _context(self) -> Optional[ssl.SSLContext]:
        scheme = urllib.parse.urlsplit(self.url).scheme
        if scheme == "http":
            if not self._insecure_http:
                raise StrataUnavailableError(
                    f"{self.url} is plain http; Strata is TLS-only and awstorage never "
                    "sends a key in the clear")
            return None
        if scheme != "https":
            raise StrataUnavailableError(f"{self.url}: unsupported scheme {scheme!r}")
        if self._ctx is None:
            if not self._ca or not os.path.isfile(self._ca):
                raise StrataUnavailableError(
                    f"no CA bundle (set {CA_ENV}, or run inside an AitherOS checkout that "
                    f"has {CA_REL.as_posix()}); refusing to talk TLS unverified")
            self._ctx = ssl.create_default_context(cafile=self._ca)
        return self._ctx

    def _request(self, method: str, route: str, body: Optional[dict] = None
                 ) -> Tuple[int, Any]:
        ctx = self._context()
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.url + route, data=data, method=method)
        req.add_header("Accept", "application/json")
        req.add_header("X-Caller-Service", "awstorage")
        if self.key:
            req.add_header("X-Internal-Key", self.key)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            status = exc.code
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", exc)
            raise StrataUnavailableError(f"{self.url} unreachable: {reason}") from exc
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            return status, {"raw": raw[:200].decode("utf-8", "replace")}

    # -- API -----------------------------------------------------------------------

    def check(self) -> None:
        """Raise StrataUnavailableError unless the target is usable right now."""
        if not self.key:
            raise StrataUnavailableError(f"{KEY_ENV} is not set; Strata writes need the "
                                         "internal key (read from that env var only)")
        status, body = self._request("GET", "/health")
        if status != 200:
            raise StrataUnavailableError(f"{self.url}/health answered {status}: {body}")

    def virtual_path(self, rel: str) -> str:
        return f"aither://{self.tier}/{rel.lstrip('/')}"

    def put(self, rel: str, data: bytes, metadata: Dict[str, Any] | None = None) -> None:
        status, body = self._request("POST", "/strata/write", {
            "path": self.virtual_path(rel),
            "content": base64.b64encode(data).decode("ascii"),
            "tier": self.tier,
            "file_type": "unknown",
            "tags": ["awstorage", "harvest"],
            "metadata": metadata or {},
        })
        if status != 200 or not (isinstance(body, dict) and body.get("success", True)):
            raise RuntimeError(f"write {rel}: HTTP {status}: {str(body)[:200]}")

    def stat(self, rel: str) -> Dict[str, Any]:
        quoted = urllib.parse.quote(f"{self.tier}/{rel.lstrip('/')}", safe="/")
        status, body = self._request("GET", f"/strata/stat/{quoted}")
        if status != 200 or not isinstance(body, dict):
            raise RuntimeError(f"stat {rel}: HTTP {status}: {str(body)[:200]}")
        return body

    def upload_verified(self, rel: str, data: bytes, sha256: str,
                        metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Write, then PROVE it landed: size always, sha256 when the server reports one."""
        self.put(rel, data, metadata)
        st = self.stat(rel)
        size = st.get("size", st.get("size_bytes"))
        if size is None or int(size) != len(data):
            raise RuntimeError(f"verify {rel}: Strata reports size {size}, sent {len(data)}")
        remote_hash = st.get("hash") or st.get("content_hash") or st.get("sha256")
        if remote_hash and str(remote_hash).lower() != sha256.lower():
            raise RuntimeError(f"verify {rel}: Strata sha256 {str(remote_hash)[:16]}... "
                               f"!= local {sha256[:16]}...")
        return {"path": self.virtual_path(rel), "bytes": len(data),
                "hash_checked": bool(remote_hash)}
