"""0.4.1, third security review.

s3  the verifier key is read ONLY from a file: a raw 64-hex key in
    ``$AWSTORAGE_ATTEST_PUBKEY`` (or ``..._FILE``) skipped the location check and is
    refused; a path in either env gets the same ~/.aither / world-writable check.
s4  a card carrying several ``proposal_id`` or ``content_sha256`` facts approves
    nothing -- an answer names exactly one proposal and one content.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from awstorage import attest, manage
from awstorage.catalog import Catalog
from awstorage.policy import ApplyRefused

from tests.attest_util import OWNER, PUB, pubkey_env, pubkey_file, sign_card


@pytest.fixture(autouse=True)
def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for k in (attest.PUBKEY_ENV, attest.PUBKEY_FILE_ENV, attest.MAX_AUTH_AGE_ENV,
              attest.MAX_RECEIPT_AGE_ENV):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(manage.OWNERS_ENV, OWNER)
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "default.db"))


@pytest.fixture
def cat(tmp_path: Path):
    c = Catalog(tmp_path / "cat.db")
    yield c
    c.close()


def _card(pid: int = 7, extra_facts=(), cid: str = "c-1") -> dict:
    now = int(time.time())
    card = {"id": cid, "status": "answered", "answer": "approve", "answered_via": "desk",
            "answered_by": OWNER, "created_at": now - 60, "answered_at": now,
            "facts": [f"proposal_id: {pid}", "content_sha256: " + "a" * 64,
                      *extra_facts]}
    return sign_card(card)


# -- s3 ----------------------------------------------------------------------------------

@pytest.mark.parametrize("env_name", ["AWSTORAGE_ATTEST_PUBKEY", "AWSTORAGE_ATTEST_PUBKEY_FILE"])
def test_raw_hex_key_in_env_is_refused(env_name, monkeypatch, cat):
    monkeypatch.setenv(env_name, PUB)
    assert attest.configured_pubkey() is None
    with pytest.raises(ApplyRefused, match="raw key, which is refused"):
        attest.verify_receipt(_card(), owners=[OWNER], nonce_store=cat)


def test_pubkey_env_as_a_path_gets_the_location_check(tmp_path, monkeypatch, cat):
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    bad = home / ".aither" / "attest.pub"
    bad.parent.mkdir(parents=True)
    bad.write_text(PUB, encoding="utf-8")
    monkeypatch.setenv(attest.PUBKEY_ENV, str(bad))
    assert attest.configured_pubkey() is None
    with pytest.raises(ApplyRefused, match="AWSTORAGE_ATTEST_PUBKEY refused: .*under"):
        attest.verify_receipt(_card(), owners=[OWNER], nonce_store=cat)
    monkeypatch.setenv(attest.PUBKEY_ENV, pubkey_file())
    assert attest.configured_pubkey() == PUB


def test_key_file_still_verifies(monkeypatch, cat):
    pubkey_env(monkeypatch)
    assert attest.verify_receipt(_card(), owners=[OWNER], nonce_store=cat)


# -- s4 ----------------------------------------------------------------------------------

def test_card_with_two_proposal_ids_is_refused(monkeypatch, cat):
    pubkey_env(monkeypatch)
    card = _card(7, extra_facts=["proposal_id: 8"])
    for pid in (7, 8):
        with pytest.raises(ApplyRefused, match="2 'proposal_id' facts"):
            manage.card_decision(card, pid, owners=[OWNER], catalog=cat)


def test_card_with_a_differently_spaced_second_proposal_id_is_refused(monkeypatch, cat):
    pubkey_env(monkeypatch)
    card = _card(7, extra_facts=["Proposal_ID :8"])
    with pytest.raises(ApplyRefused, match="2 'proposal_id' facts"):
        manage.card_decision(card, 7, owners=[OWNER], catalog=cat)


def test_single_proposal_id_still_decides(monkeypatch, cat):
    pubkey_env(monkeypatch)
    assert manage.card_decision(_card(7), 7, owners=[OWNER], catalog=cat) == ("c-1",
                                                                             "approve")


def test_card_with_two_content_digests_is_refused():
    d1, d2 = "a" * 64, "b" * 64
    card = {"id": "c-2", "facts": ["proposal_id: 7", manage.content_fact(d1),
                                   manage.content_fact(d2)]}
    for d in (d1, d2):
        with pytest.raises(ApplyRefused, match="2 'content_sha256' facts"):
            manage.require_content(card, d)
    manage.require_content({"id": "c-3", "facts": [manage.content_fact(d1)]}, d1)
    with pytest.raises(ApplyRefused, match="changed after the owner answered"):
        manage.require_content({"id": "c-3", "facts": [manage.content_fact(d1)]}, d2)
