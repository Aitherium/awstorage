"""0.4.1: a card approval is a SIGNED receipt, never a flag (awstorage.attest).

Every negative is a way an agent on the owner's host could try to fake "the owner
said yes": edit the card JSON, reuse a receipt, sign with its own key, answer from
a session-bearer / PAT / device-flow sign-in, or run where awseal is missing.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from awstorage import attest, manage
from awstorage.catalog import Catalog
from awstorage.policy import ApplyRefused

from tests.attest_util import OWNER, PUB, envelope, new_key, pubkey_env, receipt_for, sign_card

OWNERS = [OWNER]


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for k in (attest.MAX_AUTH_AGE_ENV, attest.PUBKEY_FILE_ENV):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(manage.OWNERS_ENV, OWNER)
    monkeypatch.setenv("AWSTORAGE_CATALOG", str(tmp_path / "default.db"))
    pubkey_env(monkeypatch)


@pytest.fixture
def cat(tmp_path):
    c = Catalog(tmp_path / "cat.db")
    yield c
    c.close()


def _card(cid: str = "d-1", pid: int = 1, **over) -> dict:
    now = time.time()
    card = {"id": cid, "status": "answered", "answer": "approve", "answered_via": "desk",
            "answered_by": "daemon:genesis", "facts": manage.card_facts(pid),
            "created_at": now - 600, "answered_at": now}
    card.update(over)
    return card


def _verify(card, cat, **kw):
    return attest.verify_receipt(card, owners=OWNERS, nonce_store=cat, **kw)


# -- the one good path -----------------------------------------------------------------

def test_a_valid_receipt_verifies_and_is_idempotent(cat):
    card = sign_card(_card())
    r = _verify(card, cat)
    assert r["card_id"] == "d-1" and r["auth_method"] == "webauthn"
    assert _verify(card, cat)["nonce"] == r["nonce"]          # the node re-verifies: fine
    assert manage.verify_card(card, 1, catalog=cat) == "d-1"


# -- forgeries ----------------------------------------------------------------------------

def test_receipt_signed_by_another_key_is_refused(cat):
    other, _pub = new_key()
    card = sign_card(_card(), key=other)
    with pytest.raises(ApplyRefused, match="does not verify"):
        _verify(card, cat)


def test_wrong_configured_key_is_refused(cat, monkeypatch):
    _k, other_pub = new_key()
    pubkey_env(monkeypatch, other_pub)
    with pytest.raises(ApplyRefused, match="does not verify"):
        _verify(sign_card(_card()), cat)


def test_tampered_choice_is_refused(cat):
    card = sign_card(_card(answer="reject"))
    card["answer"] = "approve"                     # edited after the owner said reject
    with pytest.raises(ApplyRefused, match="not the signed choice"):
        _verify(card, cat)


def test_tampered_receipt_body_is_refused(cat):
    card = sign_card(_card(answer="reject"))
    card["answer"] = "approve"
    card["answer_receipt"]["receipt"]["choice"] = "approve"   # sig no longer matches
    with pytest.raises(ApplyRefused, match="does not verify"):
        _verify(card, cat)


def test_edited_json_boolean_is_not_attestation(cat):
    card = _card(answer_attested=True, answered_by=OWNER)   # what 0.4.0 trusted
    with pytest.raises(ApplyRefused, match="no signed answer receipt"):
        _verify(card, cat)


def test_facts_edited_after_the_answer_are_refused(cat):
    card = sign_card(_card())
    card["facts"] = manage.card_facts(99)
    with pytest.raises(ApplyRefused, match="facts changed"):
        _verify(card, cat)


def test_receipt_moved_to_another_card_is_refused(cat):
    a = sign_card(_card("d-1"))
    b = _card("d-2")
    b["answer_receipt"] = a["answer_receipt"]
    with pytest.raises(ApplyRefused, match="names card"):
        _verify(b, cat)


# -- replay -----------------------------------------------------------------------------

def test_reused_nonce_on_another_card_is_refused(cat):
    a = sign_card(_card("d-1"))
    _verify(a, cat)
    b = sign_card(_card("d-2"), nonce=a["answer_receipt"]["receipt"]["nonce"])
    with pytest.raises(ApplyRefused, match="nonce reused"):
        _verify(b, cat)


def test_a_second_different_receipt_for_one_card_is_refused(cat):
    a = sign_card(_card("d-1"))
    _verify(a, cat)
    b = sign_card(_card("d-1"), nonce="f" * 32)
    with pytest.raises(ApplyRefused, match="different receipt"):
        _verify(b, cat)


def test_no_nonce_store_refuses_unless_read_only(cat):
    card = sign_card(_card())
    with pytest.raises(ApplyRefused, match="no nonce store"):
        attest.verify_receipt(card, owners=OWNERS, nonce_store=None)
    assert attest.verify_receipt(card, owners=OWNERS, record=False)["card_id"] == "d-1"


# -- who may attest ---------------------------------------------------------------------

@pytest.mark.parametrize("method", ["device_code", "password", "oidc_password",
                                    "oauth_browser", "magic_link", "email_otp",
                                    "internal_mint", "local_handoff", "backup_code", ""])
def test_non_interactive_sign_ins_are_refused(cat, method):
    card = sign_card(_card(), auth_method=method)
    with pytest.raises(ApplyRefused, match="auth_method"):
        _verify(card, cat)


def test_totp_2fa_counts(cat):
    assert _verify(sign_card(_card(), auth_method="totp_2fa"), cat)


def test_signed_non_owner_is_refused(cat):
    with pytest.raises(ApplyRefused, match="not an owner"):
        _verify(sign_card(_card(), answered_by="atlas"), cat)
    with pytest.raises(ApplyRefused, match="not an owner"):
        attest.verify_receipt(sign_card(_card()), owners=[], nonce_store=cat)


def test_stale_sign_in_is_refused_and_the_window_is_clamped(cat, monkeypatch):
    now = int(time.time())
    stale = sign_card(_card(), answered_at=now, auth_time=now - 901)
    with pytest.raises(ApplyRefused, match="not a fresh human answer"):
        _verify(stale, cat)
    monkeypatch.setenv(attest.MAX_AUTH_AGE_ENV, "999999")
    assert attest.max_auth_age() == 3600
    monkeypatch.setenv(attest.MAX_AUTH_AGE_ENV, "1")
    assert attest.max_auth_age() == 60


@pytest.mark.parametrize("card_over,receipt_over,why", [
    ({"created_at": time.time() + 3600}, {}, "predates the card"),
    ({"deadline": time.time() - 3600}, {}, "after the card's deadline"),
    ({"answered_at": time.time() - 7200}, {}, "from the store's"),
])
def test_answer_outside_the_cards_window_is_refused(cat, card_over, receipt_over, why):
    card = _card()
    sign_card(card, **receipt_over)
    card.update(card_over)
    with pytest.raises(ApplyRefused, match=why):
        _verify(card, cat)


# -- malformed ----------------------------------------------------------------------------

@pytest.mark.parametrize("mutate,why", [
    (lambda e: e.update(alg="hs256"), "not ed25519"),
    (lambda e: e.update(sig="00"), "malformed"),
    (lambda e: e.update(receipt="x"), "malformed"),
])
def test_malformed_envelopes_are_refused(cat, mutate, why):
    card = sign_card(_card())
    mutate(card["answer_receipt"])
    with pytest.raises(ApplyRefused, match=why):
        _verify(card, cat)


@pytest.mark.parametrize("over,why", [
    ({"v": 2}, "version"),
    ({"answered_at": True}, "answered_at"),
    ({"nonce": "not-hex"}, "nonce"),
    ({"surface": 5}, "surface"),
])
def test_malformed_receipt_fields_are_refused_even_when_signed(cat, over, why):
    card = _card()
    r = receipt_for(card, **over)
    card["answer_receipt"] = envelope(r)
    with pytest.raises(ApplyRefused, match=why):
        _verify(card, cat)


# -- provisioning / fail closed -----------------------------------------------------------

def test_missing_public_key_refuses(cat, monkeypatch):
    monkeypatch.delenv(attest.PUBKEY_FILE_ENV)
    with pytest.raises(ApplyRefused, match="no attestation public key"):
        _verify(sign_card(_card()), cat)


def test_public_key_from_a_file(cat, monkeypatch, tmp_path):
    monkeypatch.delenv(attest.PUBKEY_FILE_ENV)
    f = tmp_path / "attest.pub"
    f.write_text(PUB + "\n", encoding="utf-8")
    monkeypatch.setenv(attest.PUBKEY_FILE_ENV, str(f))
    assert _verify(sign_card(_card()), cat)
    monkeypatch.setenv(attest.PUBKEY_FILE_ENV, str(tmp_path / "missing.pub"))
    assert attest.configured_pubkey() is None
    monkeypatch.setenv(attest.PUBKEY_ENV, "not-a-key")
    assert attest.configured_pubkey() is None


def test_without_awseal_every_receipt_is_refused(cat, monkeypatch):
    monkeypatch.setitem(sys.modules, "awseal", None)
    monkeypatch.setitem(sys.modules, "awseal.keys", None)
    with pytest.raises(ApplyRefused, match="awseal is not installed"):
        _verify(sign_card(_card()), cat)


def test_the_package_imports_without_awseal():
    code = ("import sys; sys.modules['awseal'] = None; sys.modules['awseal.keys'] = None; "
            "import awstorage, awstorage.attest, awstorage.manage; print('ok')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       cwd=str(Path(__file__).resolve().parents[1]), timeout=60, check=False)
    assert r.returncode == 0 and "ok" in r.stdout, r.stderr


def test_master_switch_off_refuses_a_valid_receipt(cat, monkeypatch):
    monkeypatch.setattr(manage, "STORE_ATTESTS_ANSWERER", False)
    with pytest.raises(ApplyRefused, match="switched off"):
        manage.verify_card(sign_card(_card()), 1, catalog=cat)
