"""0.4.1 fail-closed paths that need NO crypto: runs where awseal is absent too.

Without awseal (or without a provisioned key, or without a receipt) no card approves --
checked with the real ``manage.verify_card``, never a mock of the verifier.
"""

from __future__ import annotations

import sys
import time

import pytest

from awstorage import attest, manage
from awstorage.catalog import Catalog
from awstorage.policy import ApplyRefused

OWNER = "owner@test"


def _card(**over) -> dict:
    facts = manage.card_facts(3)
    card = {"id": "d-3", "status": "answered", "answer": "approve", "answered_via": "desk",
            "answered_by": OWNER, "answer_attested": True, "facts": facts,
            "answer_receipt": {"alg": "ed25519", "kid": "0" * 16, "sig": "ab" * 64,
                               "receipt": {"v": 1, "card_id": "d-3", "choice": "approve",
                                           "answered_by": OWNER,
                                           "answered_at": int(time.time()),
                                           "nonce": "c" * 32, "surface": "desk",
                                           "auth_method": "webauthn",
                                           "auth_time": int(time.time()),
                                           "facts_sha256": attest.facts_digest(facts)}}}
    card.update(over)
    return card


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv(manage.OWNERS_ENV, OWNER)
    key_file = tmp_path / "attest.pub"
    key_file.write_text("ab" * 32, encoding="utf-8")
    monkeypatch.setenv(attest.PUBKEY_FILE_ENV, str(key_file))
    monkeypatch.delenv(attest.PUBKEY_ENV, raising=False)
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "c.db"))


def test_without_awseal_a_card_never_approves(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "awseal", None)
    monkeypatch.setitem(sys.modules, "awseal.keys", None)
    cat = Catalog(tmp_path / "cat.db")
    try:
        with pytest.raises(ApplyRefused, match="awseal is not installed"):
            manage.verify_card(_card(), 3, catalog=cat)
    finally:
        cat.close()


def test_a_boolean_without_a_receipt_never_approves():
    with pytest.raises(ApplyRefused, match="no signed answer receipt"):
        manage.verify_card(_card(answer_receipt=None), 3)


def test_no_public_key_never_approves(monkeypatch):
    monkeypatch.delenv(attest.PUBKEY_FILE_ENV)
    with pytest.raises(ApplyRefused, match="no attestation public key"):
        manage.verify_card(_card(), 3)


def test_a_forged_signature_never_approves():
    with pytest.raises(ApplyRefused):
        manage.verify_card(_card(), 3)
