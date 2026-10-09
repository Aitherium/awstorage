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

Auth is ONE of two credentials, read from the env var ONLY, never a file this
package would have to invent a location for:

- AWSTORAGE_STRATA_BEARER -- a tenant-scoped bearer. Strata derives the tenant from
  the token and keeps the caller's objects under `<tier>/__t__/<tenant>/`. When a
  bearer is set the internal key is NEVER sent alongside it: a node that holds a
  tenant credential has no business carrying the platform's.
- AWSTORAGE_STRATA_KEY -- the platform's internal key, for platform nodes, sent as
  `X-Internal-Key` with `X-Caller-Service: awstorage` (Strata's path RBAC keys on
  the name).

    GET  /strata/read?path=aither://<tier>/<path>
                              -> 200 <the object's bytes>

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
import hashlib
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

TIERS = ("hot", "warm", "cold")
DEFAULT_URL = "https://127.0.0.1:8136"
KEY_ENV = "AWSTORAGE_STRATA_KEY"
BEARER_ENV = "AWSTORAGE_STRATA_BEARER"
TENANT_ENV = "AWSTORAGE_STRATA_TENANT"
NS_MARK = "__t__"
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
                 timeout: float = 30.0, insecure_http_for_tests: bool = False,
                 bearer: str | None = None) -> None:
        e = os.environ if env is None else env
        if tier not in TIERS:
            raise ValueError(f"strata tier {tier!r} is not one of {TIERS}")
        self.tier = tier
        self.url = (url or e.get(URL_ENV) or DEFAULT_URL).rstrip("/")
        self.key = key if key is not None else (e.get("AWSTORAGE_STRATA_KEY") or "")
        self.bearer = (bearer if bearer is not None else (e.get(BEARER_ENV) or "")).strip()
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

    def auth_headers(self) -> Dict[str, str]:
        """The credential headers for one request: the bearer XOR the internal key."""
        if self.bearer:
            return {"Authorization": f"Bearer {self.bearer}"}
        if self.key:
            return {"X-Internal-Key": self.key, "X-Caller-Service": "awstorage"}
        return {"X-Caller-Service": "awstorage"}

    def _raw(self, method: str, route: str, body: Optional[dict] = None,
             accept: str = "application/json") -> Tuple[int, bytes]:
        ctx = self._context()
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.url + route, data=data, method=method)
        req.add_header("Accept", accept)
        for name, value in self.auth_headers().items():
            req.add_header(name, value)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, (exc.read() if hasattr(exc, "read") else b"")
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", exc)
            raise StrataUnavailableError(f"{self.url} unreachable: {reason}") from exc

    def _request(self, method: str, route: str, body: Optional[dict] = None
                 ) -> Tuple[int, Any]:
        status, raw = self._raw(method, route, body)
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            return status, {"raw": raw[:200].decode("utf-8", "replace")}

    # -- API -----------------------------------------------------------------------

    def check(self) -> None:
        """Raise StrataUnavailableError unless the target is usable right now."""
        if not self.key and not self.bearer:
            raise StrataUnavailableError(f"neither {BEARER_ENV} nor {KEY_ENV} is set; "
                                         "Strata writes need a tenant bearer or the "
                                         "internal key (read from those env vars only)")
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
        body = self.stat_or_none(rel)
        if body is None:
            raise RuntimeError(f"stat {rel}: HTTP 404")
        return body

    def stat_or_none(self, rel: str) -> Optional[Dict[str, Any]]:
        """The object's stat, None on 404; any other answer raises -- an outage
        must never read as "not stored"."""
        quoted = urllib.parse.quote(f"{self.tier}/{rel.lstrip('/')}", safe="/")
        status, body = self._request("GET", f"/strata/stat/{quoted}")
        if status == 404:
            return None
        if status != 200 or not isinstance(body, dict):
            raise RuntimeError(f"stat {rel}: HTTP {status}: {str(body)[:200]}")
        return body

    def get(self, rel: str) -> bytes:
        """The object's bytes, as Strata serves them (decrypted at rest)."""
        q = urllib.parse.urlencode({"path": self.virtual_path(rel)})
        status, raw = self._raw("GET", f"/strata/read?{q}", accept="*/*")
        if status != 200:
            raise RuntimeError(f"read {rel}: HTTP {status}: "
                               f"{raw[:200].decode('utf-8', 'replace')}")
        return raw

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


# ---------------------------------------------------------------------------------
# The pool as an object store, and the archive hooks a node's card orders use
# ---------------------------------------------------------------------------------

def _safe_tenant(tenant: Optional[str]) -> str:
    t = str(tenant or "").strip()
    if (not t or len(t) > 128 or t.startswith(".")
            or not all(c.isalnum() or c in "-_." for c in t)):
        raise ValueError(f"tenant {tenant!r} is not a plain tenant id; every pooled "
                         "object lives under exactly one tenant")
    return t


def objects_prefix(tenant: str) -> str:
    """`__t__/<tenant>/objects` -- Strata's own tenant namespace, spelled out so an
    internal-key caller lands in the same subtree a tenant bearer is confined to
    (Strata leaves an already-namespaced path alone)."""
    return f"{NS_MARK}/{_safe_tenant(tenant)}/objects"


def strata_object_store(tenant: Optional[str] = None, tier: str = "warm", *,
                        target: Optional[StrataTarget] = None,
                        env: Mapping[str, str] | None = None, **target_kw: Any) -> Any:
    """An awshare object store whose objects live in the Strata pool.

    Objects are `aither://<tier>/__t__/<tenant>/objects/<ab>/<sha256>`: content
    addressed, so a second snapshot of an unchanged tree sends nothing. The tenant
    is required (AWSTORAGE_STRATA_TENANT when not passed): there is no flat,
    untenanted pool object. Raises StrataUnavailableError when no credential is
    configured -- an unconfigured pool is refused, never silently local.
    """
    try:
        from awshare import RemoteObjectStore  # noqa: PLC0415 -- optional sibling
    except ImportError as exc:  # pragma: no cover - exercised only without awshare
        raise StrataUnavailableError("the Strata object store needs `awshare`") from exc
    e = os.environ if env is None else env
    t = _safe_tenant(tenant if tenant is not None else e.get(TENANT_ENV))
    tgt = target if target is not None else StrataTarget(tier, env=e, **target_kw)
    if not tgt.key and not tgt.bearer:
        raise StrataUnavailableError(f"neither {BEARER_ENV} nor {KEY_ENV} is set")
    prefix = objects_prefix(t)
    return RemoteObjectStore(tgt, prefix, describe=tgt.virtual_path(prefix))


def split_virtual(strata_path: str) -> Tuple[str, str]:
    """'aither://cold/a/b' -> ('cold', 'a/b'); anything else raises."""
    p = str(strata_path or "")
    if not p.startswith("aither://"):
        raise ValueError(f"{strata_path!r} is not an aither:// path")
    tier, _, rel = p[len("aither://"):].partition("/")
    if tier not in TIERS or not rel:
        raise ValueError(f"{strata_path!r}: tier must be one of {TIERS} and a path given")
    return tier, rel


def archive_hooks(env: Mapping[str, str] | None = None, *,
                  max_bytes: int = 256 * 1024 * 1024,
                  target_factory: Optional[Callable[[str], Any]] = None
                  ) -> Tuple[Optional[Callable[..., Dict[str, Any]]],
                             Optional[Callable[[str], Dict[str, Any]]]]:
    """`(strata_hook, readback_hook)` for an `archive` card order, or `(None, None)`
    when this node has no Strata credential -- the order is then REFUSED and
    ledgered, never run against nothing.

    The write hook uploads and checks the stat (size, and sha256 when Strata
    reports one); the read-back hook is independent of it: it fetches the object's
    bytes and hashes them, so a stat that echoes what was sent cannot pass it.
    """
    e = os.environ if env is None else env
    if not ((e.get(BEARER_ENV) or "").strip() or (e.get(KEY_ENV) or "").strip()):
        return None, None

    def make(tier: str) -> Any:
        if target_factory is not None:
            return target_factory(tier)
        return StrataTarget(tier, env=e)

    def strata_hook(path: Any, *, strata_path: str, sha256: str, size: int,
                    tier: str) -> Dict[str, Any]:
        vtier, rel = split_virtual(strata_path)
        if int(size) > max_bytes:
            raise RuntimeError(f"{path} is {size} bytes; the archive hook sends one "
                               f"object of at most {max_bytes} bytes")
        data = Path(path).read_bytes()
        got = hashlib.sha256(data).hexdigest()
        if got != sha256 or len(data) != int(size):
            raise RuntimeError(f"{path} changed before upload; nothing sent")
        make(vtier).upload_verified(rel, data, sha256,
                                    metadata={"sha256": sha256, "awstorage": "archive"})
        return {"sha256": got, "size": len(data), "strata_path": strata_path}

    def readback_hook(strata_path: str) -> Dict[str, Any]:
        vtier, rel = split_virtual(strata_path)
        data = make(vtier).get(rel)
        return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    return strata_hook, readback_hook
