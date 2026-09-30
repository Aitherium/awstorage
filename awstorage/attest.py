"""Signed answer receipts: the ONLY evidence that a human owner approved a card.

A decision card's ``answered_by`` / ``answered_via`` / ``answer_attested`` fields live
in files and stores an agent on the same host can write, so none of them is proof.
The platform's answering surface (Genesis) signs a RECEIPT with an Ed25519 key that
exists only in its vault, and stores it on the card as ``answer_receipt``::

    {"alg": "ed25519", "kid": "<first 16 hex of the public key>",
     "receipt": {"v": 1, "card_id": ..., "choice": ..., "answered_by": ...,
                 "answered_at": <epoch s>, "nonce": "<32 hex>", "surface": ...,
                 "auth_method": ..., "auth_time": <epoch s>,
                 "facts_sha256": "<sha256 of the card's normalised facts>"},
     "sig": "<128 hex>"}

:func:`verify_receipt` is what every approval path calls. It refuses (raises
:class:`~awstorage.policy.ApplyRefused`) unless ALL hold:

* awseal is importable (it carries the Ed25519 verifier) -- absent: refuse;
* a public key is provisioned in a FILE named by ``$AWSTORAGE_ATTEST_PUBKEY_FILE`` (or
  ``$AWSTORAGE_ATTEST_PUBKEY``, also a path) that passes :func:`pubkey_file_refusal`
  -- absent, a raw hex key in the env, or an agent-writable file: refuse;
* the signature verifies over the canonical JSON of the receipt;
* the receipt names THIS card, THIS answer, THIS card's facts;
* ``auth_method`` is an interactive, human-present sign-in (:data:`ATTEST_AUTH_METHODS`)
  that happened at most :func:`max_auth_age` seconds before the answer;
* ``answered_by`` is an owner principal;
* ``answered_at`` falls inside the card's window (created .. deadline) and within
  :data:`CLOCK_SKEW_S` of the store's own ``answered_at``;
* the receipt is at most :func:`max_receipt_age` old (default 7 days,
  ``$AWSTORAGE_ATTEST_MAX_RECEIPT_AGE_S``) by the REAL clock -- there is no injectable
  clock, an injectable clock is an injectable bypass;
* the nonce is not reused: a catalog table binds each nonce to one card and one
  receipt digest, and each card to one nonce. Re-verifying the SAME receipt is
  idempotent (the platform and the node both verify one answer).

The boolean ``answer_attested`` on a card is advisory and is never read here.

**The public key must be owner-provisioned OUTSIDE the agents' reach.** Whoever can
replace the verifier key can sign their own "owner approved" receipts. So
``$AWSTORAGE_ATTEST_PUBKEY_FILE`` is refused when it resolves under the user's
``~/.aither`` (every agent on the host writes there) or when the file or its directory
is world-writable (POSIX); provision it root/owner-owned, e.g. ``/etc/aither/`` or
``%ProgramData%/Aither/`` with an ACL agents cannot write.

THREAT MODEL (read before relying on this). On a single-user host agents run as the
owner's OS user: they can delete files directly, read the browser's localStorage
session and, with ``podman exec``, service state. A verified receipt therefore proves
"an owner passkey/TOTP session existed within 15 minutes of this answer", NOT "the
owner saw this card and chose this answer". Approvals are a governance gate plus a
tamper-evident audit trail for agents that USE the tools -- not a security boundary
against a hostile local agent; that needs OS isolation (agents under a separate OS user
or in a container without podman or vault access). Follow-up that closes the gap: a
per-answer WebAuthn step-up whose assertion signs the digest of the RENDERED card.

Stdlib-only at import: awseal is imported inside :func:`verify_receipt`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .policy import ApplyRefused

#: Env naming the PATH of the verifier-key file (0.4.1: a raw hex key here is refused).
PUBKEY_ENV = "AWSTORAGE_ATTEST_PUBKEY"
#: Env naming a FILE holding the hex key (64 hex, Ed25519 raw; the owner provisions it).
PUBKEY_FILE_ENV = "AWSTORAGE_ATTEST_PUBKEY_FILE"
#: Env overriding the maximum age of the sign-in behind an answer (seconds).
MAX_AUTH_AGE_ENV = "AWSTORAGE_ATTEST_MAX_AUTH_AGE_S"
DEFAULT_MAX_AUTH_AGE_S = 900
#: Env overriding the maximum age of a RECEIPT itself (seconds since answered_at).
MAX_RECEIPT_AGE_ENV = "AWSTORAGE_ATTEST_MAX_RECEIPT_AGE_S"
DEFAULT_MAX_RECEIPT_AGE_S = 7 * 86400
#: Clamp for the override: never below an hour, never above 30 days.
MAX_RECEIPT_AGE_BOUNDS = (3600, 30 * 86400)
#: Clamp for the override: never below a minute, never above an hour.
MAX_AUTH_AGE_BOUNDS = (60, 3600)
#: Allowed disagreement between the signer's clock and the store's.
CLOCK_SKEW_S = 300
RECEIPT_VERSION = 1

#: Interactive sign-ins that prove a human was present. Mirrors the platform's
#: ``lib/security/owner_proof.OWNER_AUTH_METHODS``. Deliberately absent: password
#: (agents can read the admin password), OAuth, magic links, email OTP, device
#: flow (every agent bearer), PATs, API keys, OIDC access tokens, internal mints.
ATTEST_AUTH_METHODS = frozenset({"totp_2fa", "webauthn"})

_HEX = re.compile(r"^[0-9a-f]+$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_FIELDS = {"v": int, "card_id": str, "choice": str, "answered_by": str, "answered_at": int,
           "nonce": str, "surface": str, "auth_method": str, "auth_time": int,
           "facts_sha256": str}

_NONCE_DDL = """
CREATE TABLE IF NOT EXISTS attest_nonces (
  nonce TEXT PRIMARY KEY,
  card_id TEXT NOT NULL UNIQUE,
  digest TEXT NOT NULL,
  first_seen TEXT NOT NULL
);
"""


def canonical(obj: Any) -> bytes:
    """The one serialisation signer and verifier agree on (same as awseal's)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def normalize_facts(facts: Iterable[Any] | None) -> list[str]:
    return [" ".join(str(f).split()) for f in (facts or [])]


def facts_digest(facts: Iterable[Any] | None) -> str:
    """sha256 hex of the card's facts, whitespace-normalised -- binds a receipt to
    the proposal the card names (``proposal_id: <id>``)."""
    return hashlib.sha256(canonical(normalize_facts(facts))).hexdigest()


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(dict(receipt))).hexdigest()


def key_id(pubkey_hex: str) -> str:
    return pubkey_hex.strip().lower()[:16]


def _is_under(child: Path, parent: Path) -> bool:
    c = os.path.normcase(str(child)).replace("\\", "/")
    p = os.path.normcase(str(parent)).replace("\\", "/").rstrip("/")
    return c == p or c.startswith(p + "/")


def pubkey_file_refusal(path: str | Path) -> str | None:
    """Why the verifier-key FILE at ``path`` is not trusted, or None.

    Refused: a path that resolves under the user's ``~/.aither`` (agents write there),
    or -- on POSIX -- a file or directory that is world-writable, or an ancestor
    directory that is world-writable without the sticky bit (anyone could swap it).
    Windows ACLs are not judged here; provision the file where agents cannot write.
    """
    import stat  # noqa: PLC0415

    try:
        real = Path(os.path.realpath(os.path.expanduser(str(path))))
        home_aither = Path(os.path.realpath(Path.home() / ".aither"))
    except (OSError, RuntimeError, ValueError) as exc:
        return f"cannot resolve {path}: {exc}"
    if _is_under(real, home_aither):
        return (f"{real} is under {home_aither}, which every agent on this host can write; "
                "provision the key root/owner-owned outside ~/.aither")
    if os.name == "posix":
        try:
            if os.stat(real).st_mode & stat.S_IWOTH:
                return f"{real} is world-writable"
            parent = real.parent
            if os.stat(parent).st_mode & stat.S_IWOTH:
                return f"its directory {parent} is world-writable"
            for anc in parent.parents:
                mode = os.stat(anc).st_mode
                if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                    return f"its ancestor {anc} is world-writable without the sticky bit"
        except OSError as exc:
            return f"cannot stat {real}: {exc}"
    return None


def _pubkey_and_why(env: Mapping[str, str] | None = None) -> tuple[str | None, str]:
    """The verifier key and, when there is none, why. Both env vars name a FILE PATH:
    the key itself in an env var is refused -- any process that starts the verifier
    (an agent included) can set an env var, and the file's location is what
    :func:`pubkey_file_refusal` judges."""
    e = os.environ if env is None else env
    name = PUBKEY_ENV
    path = (e.get(PUBKEY_ENV) or "").strip()
    if not path:
        name, path = PUBKEY_FILE_ENV, (e.get(PUBKEY_FILE_ENV) or "").strip()
    if not path:
        return None, (f"no attestation public key configured (${PUBKEY_FILE_ENV} = the "
                      "path of a root/owner-provisioned key file)")
    if len(path) == 64 and _HEX.match(path.lower()):
        return None, (f"${name} holds a raw key, which is refused: an env var is set by "
                      "whoever starts the verifier. Write the key to a root/owner-owned "
                      f"file outside ~/.aither and set ${PUBKEY_FILE_ENV} to its path")
    why = pubkey_file_refusal(path)
    if why:
        return None, f"${name} refused: {why}"
    try:
        raw = Path(os.path.expanduser(path)).read_text(encoding="utf-8").strip()
    except OSError as exc:
        return None, f"${name} unreadable: {exc}"
    raw = raw.lower()
    if len(raw) == 64 and _HEX.match(raw):
        return raw, ""
    return None, "the configured attestation public key is not 64 hex chars"


def configured_pubkey(env: Mapping[str, str] | None = None) -> str | None:
    """The provisioned verifier key (hex), or None. A file that cannot be read -- or
    that sits where agents can write it (:func:`pubkey_file_refusal`) -- is None too;
    the caller refuses; nothing here guesses a key."""
    return _pubkey_and_why(env)[0]


def max_auth_age(env: Mapping[str, str] | None = None) -> int:
    e = os.environ if env is None else env
    try:
        v = int(float((e.get(MAX_AUTH_AGE_ENV) or "").strip() or DEFAULT_MAX_AUTH_AGE_S))
    except ValueError:
        v = DEFAULT_MAX_AUTH_AGE_S
    lo, hi = MAX_AUTH_AGE_BOUNDS
    return max(lo, min(hi, v))


def max_receipt_age(env: Mapping[str, str] | None = None) -> int:
    """Seconds after ``answered_at`` a receipt stops approving anything."""
    e = os.environ if env is None else env
    try:
        v = int(float((e.get(MAX_RECEIPT_AGE_ENV) or "").strip() or DEFAULT_MAX_RECEIPT_AGE_S))
    except ValueError:
        v = DEFAULT_MAX_RECEIPT_AGE_S
    lo, hi = MAX_RECEIPT_AGE_BOUNDS
    return max(lo, min(hi, v))


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _num(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return None


def _db_path(store: Any) -> Path | None:
    if store is None:
        return None
    if isinstance(store, (str, Path)):
        return Path(os.path.expanduser(str(store)))
    p = getattr(store, "path", None)
    if p is None and getattr(store, "catalog", None) is not None:
        p = getattr(store.catalog, "path", None)
    return Path(p) if p is not None else None


def record_nonce(store: Any, receipt: Mapping[str, Any]) -> None:
    """Bind the receipt's nonce to its card (once). Refuses a reused nonce or a card
    that already carries a DIFFERENT receipt; the same receipt again is a no-op."""
    path = _db_path(store)
    if path is None:
        raise ApplyRefused("no nonce store: cannot prove the receipt is not a replay")
    nonce, cid, dig = str(receipt["nonce"]), str(receipt["card_id"]), receipt_digest(receipt)
    try:
        db = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    except sqlite3.Error as exc:
        raise ApplyRefused(f"nonce store {path} unavailable: {exc}") from exc
    try:
        db.executescript(_NONCE_DDL)
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute("SELECT nonce, card_id, digest FROM attest_nonces"
                          " WHERE nonce = ? OR card_id = ?", (nonce, cid)).fetchall()
        for n, c, d in rows:
            if (n, c, d) == (nonce, cid, dig):
                db.execute("COMMIT")
                return
        if rows:
            db.execute("ROLLBACK")
            n, c, _d = rows[0]
            if n == nonce and c != cid:
                raise ApplyRefused(f"receipt nonce reused: already bound to card {c}")
            if c == cid and n != nonce:
                raise ApplyRefused(f"card {cid} already carries a different receipt")
            raise ApplyRefused("receipt nonce reused with a different receipt")
        db.execute("INSERT INTO attest_nonces(nonce, card_id, digest, first_seen)"
                   " VALUES (?,?,?,?)",
                   (nonce, cid, dig, datetime.now(timezone.utc).isoformat(timespec="seconds")))
        db.execute("COMMIT")
    except sqlite3.Error as exc:
        raise ApplyRefused(f"nonce store {path} failed: {exc}") from exc
    finally:
        db.close()


def _verifier():
    """awseal's public-key loader, or refuse. Guarded: awstorage stays stdlib-only."""
    try:
        from awseal.keys import load_public_key  # noqa: PLC0415
    except ImportError as exc:
        raise ApplyRefused("awseal is not installed (pip install awstorage[attest]): the "
                           "answer receipt cannot be verified, so it is refused") from exc
    return load_public_key


def verify_receipt(card: Any, *, owners: Iterable[str], pubkey: str | None = None,
                   nonce_store: Any = None, record: bool = True,
                   now: float | None = None, env: Mapping[str, str] | None = None
                   ) -> dict:
    """Return the verified receipt of ``card``'s answer; raise ApplyRefused otherwise.

    ``nonce_store`` is a Catalog / ManageStore / sqlite path; with ``record`` False
    the nonce is not recorded (a read-only pre-check -- the authoritative check that
    acts must record it). ``now`` is accepted for compatibility and IGNORED: the real
    clock (``time.time()``) always judges freshness.
    """
    del now  # an injectable clock would be an injectable bypass (0.4.1 review, c4)
    real_now = time.time()
    cid = str(_get(card, "id") or _get(card, "card_id") or "?")
    env_ = os.environ if env is None else env
    envelope = _get(card, "answer_receipt")
    if not isinstance(envelope, Mapping):
        raise ApplyRefused(f"card {cid}: no signed answer receipt (only an answer signed "
                           "by the platform's attestation key counts)")
    if envelope.get("alg") != "ed25519":
        raise ApplyRefused(f"card {cid}: receipt alg {envelope.get('alg')!r} is not ed25519")
    receipt, sig = envelope.get("receipt"), envelope.get("sig")
    if not isinstance(receipt, Mapping) or not isinstance(sig, str) \
            or len(sig) != 128 or not _HEX.match(sig.lower()):
        raise ApplyRefused(f"card {cid}: malformed receipt envelope")
    key = (pubkey or "").strip().lower()
    if not key:
        key, why = _pubkey_and_why(env_)
        if not key:
            raise ApplyRefused(f"{why}; every answer is refused")
    load_public_key = _verifier()
    try:
        load_public_key(key).verify(bytes.fromhex(sig), canonical(dict(receipt)))
    except Exception as exc:  # noqa: BLE001 -- any failure is a failed verification
        raise ApplyRefused(f"card {cid}: receipt signature does not verify with the "
                           f"configured key {key_id(key)} ({type(exc).__name__})") from exc
    # -- the signed facts, checked against the card ---------------------------------
    for name, typ in _FIELDS.items():
        v = receipt.get(name)
        if not isinstance(v, typ) or isinstance(v, bool):
            raise ApplyRefused(f"card {cid}: receipt field {name!r} missing or not {typ.__name__}")
    if receipt["v"] != RECEIPT_VERSION:
        raise ApplyRefused(f"card {cid}: receipt version {receipt['v']} not supported")
    if receipt["card_id"] != cid:
        raise ApplyRefused(f"receipt names card {receipt['card_id']!r}, not {cid!r}")
    if str(_get(card, "status") or "") != "answered":
        raise ApplyRefused(f"card {cid} is not answered")
    answer = str(_get(card, "answer") or "").strip().lower()
    if receipt["choice"].strip().lower() != answer:
        raise ApplyRefused(f"card {cid}: recorded answer {answer!r} is not the signed "
                           f"choice {receipt['choice']!r}")
    if receipt["facts_sha256"] != facts_digest(_get(card, "facts")):
        raise ApplyRefused(f"card {cid}: facts changed after the owner answered")
    method = receipt["auth_method"].strip().lower()
    if method not in ATTEST_AUTH_METHODS:
        raise ApplyRefused(f"card {cid}: signed auth_method {method!r} is not an interactive "
                           f"human sign-in {sorted(ATTEST_AUTH_METHODS)}")
    allowed = frozenset(str(o).strip() for o in owners if str(o).strip())
    who = receipt["answered_by"].strip()
    if not who or who not in allowed:
        raise ApplyRefused(f"card {cid}: signed answerer {who or 'nobody'!r} is not an "
                           "owner principal")
    at, auth = float(receipt["answered_at"]), float(receipt["auth_time"])
    age = max_auth_age(env_)
    if auth > at + CLOCK_SKEW_S or at - auth > age:
        raise ApplyRefused(f"card {cid}: the sign-in behind the answer is "
                           f"{int(at - auth)} s old (> {age} s): not a fresh human answer")
    created = _num(_get(card, "created_at"))
    deadline = _num(_get(card, "deadline"))
    stored_at = _num(_get(card, "answered_at"))
    if created is not None and at < created - CLOCK_SKEW_S:
        raise ApplyRefused(f"card {cid}: signed answer predates the card")
    if deadline is not None and at > deadline + CLOCK_SKEW_S:
        raise ApplyRefused(f"card {cid}: signed answer is after the card's deadline")
    if stored_at is not None and abs(stored_at - at) > CLOCK_SKEW_S:
        raise ApplyRefused(f"card {cid}: signed answered_at is {int(abs(stored_at - at))} s "
                           "from the store's (a receipt moved from another answer)")
    if at > real_now + CLOCK_SKEW_S:
        raise ApplyRefused(f"card {cid}: signed answer is in the future")
    max_age = max_receipt_age(env_)
    if real_now - at > max_age:
        raise ApplyRefused(f"card {cid}: the receipt is {int((real_now - at) // 3600)} h old "
                           f"(> {max_age // 3600} h): re-ask the owner")
    if not _NONCE.match(receipt["nonce"]):
        raise ApplyRefused(f"card {cid}: malformed receipt nonce")
    if record:
        record_nonce(nonce_store, receipt)
    return dict(receipt)


__all__ = [
    "ATTEST_AUTH_METHODS",
    "CLOCK_SKEW_S",
    "DEFAULT_MAX_AUTH_AGE_S",
    "DEFAULT_MAX_RECEIPT_AGE_S",
    "MAX_AUTH_AGE_ENV",
    "MAX_RECEIPT_AGE_ENV",
    "PUBKEY_ENV",
    "PUBKEY_FILE_ENV",
    "RECEIPT_VERSION",
    "canonical",
    "configured_pubkey",
    "facts_digest",
    "key_id",
    "max_auth_age",
    "max_receipt_age",
    "normalize_facts",
    "pubkey_file_refusal",
    "receipt_digest",
    "record_nonce",
    "verify_receipt",
]
