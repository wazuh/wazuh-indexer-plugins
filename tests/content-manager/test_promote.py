"""Promotion lifecycle coverage (draft -> test -> custom).

NOTE: promotion permanently mutates the test and custom spaces, which the API
cannot reset (only draft is resettable). To stay repeatable on a long-lived
cluster, this module names its resources uniquely per run.
"""

import uuid

import pytest

from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.promote]


@pytest.fixture
def promotable(client, reset_draft):
    """Build a unique integration + decoder + rule in draft and wire the policy."""
    uid = uuid.uuid4().hex[:8]
    title = f"ct-promote-{uid}"
    iid = client.create(C.INTEGRATIONS, P.make_integration(title=title))
    did = client.create(
        C.DECODERS, P.make_decoder(name=f"decoder/{title}/0"), integration=iid
    )
    rid = client.create(
        C.RULES, P.make_rule(product=title, title=f"rule-{uid}"), integration=iid
    )
    resp = client.put(
        f"{C.POLICY}/{C.SPACE_DRAFT}",
        json=P.policy_body(root_decoder=did, integrations=[iid]),
    )
    assert resp.status_code == 200, resp.text
    return {"title": title, "integration": iid, "decoder": did, "rule": rid}


def _promote(client, space):
    preview = client.get(C.PROMOTE, params={"space": space})
    assert preview.status_code == 200, preview.text
    changes = preview.json()["changes"]
    resp = client.post(C.PROMOTE, json={"space": space, "changes": changes})
    assert resp.status_code == 200, resp.text
    return changes


def test_preview_reports_changes(client, promotable):
    preview = client.get(C.PROMOTE, params={"space": C.SPACE_DRAFT})
    assert preview.status_code == 200, preview.text
    changes = preview.json()["changes"]

    # Policy operations are update-only.
    assert all(op["operation"] == "update" for op in changes.get("policy", []))
    rule_ids = [c["id"] for c in changes.get("rules", [])]
    assert promotable["rule"] in rule_ids


def test_promote_draft_to_test_then_custom(client, promotable):
    iid = promotable["integration"]

    _promote(client, C.SPACE_DRAFT)
    test_doc = client.get_doc_in_space(C.INDEX_INTEGRATIONS, iid, C.SPACE_TEST)
    assert test_doc is not None, "integration not present in test after promotion"

    # Promoted hash matches the source draft hash.
    draft_doc = client.get_doc_in_space(C.INDEX_INTEGRATIONS, iid, C.SPACE_DRAFT)
    assert draft_doc["hash"]["sha256"] == test_doc["hash"]["sha256"]

    _promote(client, C.SPACE_TEST)
    custom_doc = client.get_doc_in_space(C.INDEX_INTEGRATIONS, iid, C.SPACE_CUSTOM)
    assert custom_doc is not None, "integration not present in custom after promotion"
    assert test_doc["hash"]["sha256"] == custom_doc["hash"]["sha256"]


def test_promote_unknown_space_rejected(client, reset_draft):
    resp = client.get(C.PROMOTE, params={"space": "bogus"})
    assert resp.status_code == 400, resp.text
