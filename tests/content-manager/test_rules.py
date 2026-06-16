"""Rule CRUD coverage."""

import pytest

from lib import assertions as A
from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.crud]


def test_create_rule(client, integration):
    before = A.space_hash(client, C.SPACE_DRAFT)

    rid = client.create(
        C.RULES, P.make_rule(product=integration["title"]), integration=integration["id"]
    )

    source = A.assert_in_index(client, C.INDEX_RULES, rid, space=C.SPACE_DRAFT)
    A.assert_hash_present(source)
    A.assert_in_integration_list(client, integration["id"], "rules", rid)
    A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))


def test_create_rule_product_mismatch_rejected(client, integration):
    body = P.make_rule(product="does-not-match-integration-title")
    resp = client.post(C.RULES, json={"integration": integration["id"], **body})
    assert resp.status_code == 400, resp.text


def test_update_rule(client, integration, rule):
    body = P.make_rule(product=integration["title"], title="Rule updated", level="medium")
    resp = client.put(f"{C.RULES}/{rule}", json=body)
    assert resp.status_code == 200, resp.text

    updated = client.get_doc(C.INDEX_RULES, rule)["document"]
    assert updated["metadata"]["title"] == "Rule updated"


def test_delete_rule(client, integration, rule):
    resp = client.delete(f"{C.RULES}/{rule}")
    assert resp.status_code == 200, resp.text

    A.assert_not_in_index(client, C.INDEX_RULES, rule)
    source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
    assert rule not in source.get("rules", [])
