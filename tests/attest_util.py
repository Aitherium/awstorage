"""Test-only signer for decision-card answer receipts (the platform's half, in miniature).

The real signer is Genesis (``lib/security/decision_attest.py``) holding a vault key.
Tests generate a throwaway Ed25519 key per process; ``PUB`` goes into a key FILE named
by ``$AWSTORAGE_ATTEST_PUBKEY_FILE`` through the ``pubkey_env`` helper (0.4.1: a raw
hex key in the env is refused).
"""

from __future__ import annotations

import hashlib
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("awseal", reason="awseal verifies receipts (awstorage[attest])")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from awstorage import attest  # noqa: E402

OWNER = "owner@test"


def new_key() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                        format=serialization.PublicFormat.Raw).hex()
    return key, pub


KEY, PUB = new_key()
#: One clock for every receipt of this run, so re-signing the same card yields the
#: SAME receipt (the nonce store treats that as idempotent, a new one as a replay).
T0 = int(time.time())


def receipt_for(card: dict, **over: Any) -> dict:
    at = int(card.get("answered_at") or T0)
    seed = f"{card.get('id')}|{card.get('answer')}|{attest.facts_digest(card.get('facts'))}"
    r = {"v": 1, "card_id": str(card.get("id")), "choice": str(card.get("answer") or ""),
         "answered_by": OWNER, "answered_at": at,
         "nonce": hashlib.sha256(seed.encode()).hexdigest()[:32],
         "surface": "desk", "auth_method": "webauthn", "auth_time": at - 60,
         "facts_sha256": attest.facts_digest(card.get("facts"))}
    r.update(over)
    return r


def envelope(receipt: dict, key: Ed25519PrivateKey = KEY, pub: str = PUB) -> dict:
    sig = key.sign(attest.canonical(receipt)).hex()
    return {"alg": "ed25519", "kid": pub[:16], "receipt": receipt, "sig": sig}


def sign_card(card: dict, *, key: Ed25519PrivateKey = KEY, pub: str = PUB, **over: Any
              ) -> dict:
    """Attach a receipt signed over ``card`` as it stands (``over`` edits the receipt)."""
    card["answer_receipt"] = envelope(receipt_for(card, **over), key, pub)
    return card


def pubkey_file(pub: str = PUB) -> str:
    """A fresh key file holding ``pub`` (a private temp dir, never under ~/.aither)."""
    f = Path(tempfile.mkdtemp(prefix="awstorage-attest-")) / "attest.pub"
    f.write_text(pub + "\n", encoding="utf-8")
    return str(f)


def pubkey_env(monkeypatch, pub: str = PUB) -> None:
    """Provision the verifier key the way an owner does: a key file, named by the env."""
    monkeypatch.setenv(attest.PUBKEY_FILE_ENV, pubkey_file(pub))
    monkeypatch.delenv(attest.PUBKEY_ENV, raising=False)
