"""Draft policy update coverage."""

import pytest

from lib import assertions as A
from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.policy]


def test_update_draft_policy(client, integration, decoder):
    before = A.space_hash(client, C.SPACE_DRAFT)

    body = P.policy_body(root_decoder=decoder, integrations=[integration["id"]], enabled=True)
    resp = client.put(f"{C.POLICY}/{C.SPACE_DRAFT}", json=body)
    assert resp.status_code == 200, resp.text

    policy = client.get_draft_policy()["document"]
    assert policy["enabled"] is True
    assert policy["root_decoder"] == decoder
    A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))


def test_policy_reorder_integrations_ok(client, integration, decoder):
    # Single integration, but sending the current list (reorder-only) must succeed.
    body = P.policy_body(root_decoder=decoder, integrations=[integration["id"]])
    resp = client.put(f"{C.POLICY}/{C.SPACE_DRAFT}", json=body)
    assert resp.status_code == 200, resp.text


def test_policy_add_integration_rejected(client, integration, decoder):
    body = P.policy_body(
        root_decoder=decoder,
        integrations=[integration["id"], "00000000-0000-0000-0000-000000000000"],
    )
    resp = client.put(f"{C.POLICY}/{C.SPACE_DRAFT}", json=body)
    assert resp.status_code == 400, resp.text
