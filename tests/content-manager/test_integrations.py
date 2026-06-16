"""Integration CRUD coverage."""

import pytest

from lib import assertions as A
from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.crud]


def test_create_integration(client, reset_draft):
    before = A.space_hash(client, C.SPACE_DRAFT)

    iid = client.create(C.INTEGRATIONS, P.make_integration(title="ct-create"))

    source = A.assert_in_index(client, C.INDEX_INTEGRATIONS, iid, space=C.SPACE_DRAFT)
    A.assert_hash_present(source)
    A.assert_listed_in_draft_policy(client, "integrations", iid)
    A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))


def test_create_duplicate_title_rejected(client, integration):
    resp = client.post(C.INTEGRATIONS, json=P.make_integration(title=integration["title"]))
    assert resp.status_code == 400, resp.text
    assert "already exists" in resp.text


def test_create_missing_title_rejected(client, reset_draft):
    body = P.make_integration()
    del body["resource"]["metadata"]["title"]
    resp = client.post(C.INTEGRATIONS, json=body)
    assert resp.status_code == 400, resp.text


def test_update_integration(client, integration):
    source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
    body = P.integration_update(source)
    body["resource"]["metadata"]["description"] = "updated description"

    resp = client.put(f"{C.INTEGRATIONS}/{integration['id']}", json=body)
    assert resp.status_code == 200, resp.text

    updated = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
    assert updated["metadata"]["description"] == "updated description"


def test_update_rejects_dependency_add(client, integration):
    source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
    body = P.integration_update(source, decoders=["00000000-0000-0000-0000-000000000000"])

    resp = client.put(f"{C.INTEGRATIONS}/{integration['id']}", json=body)
    assert resp.status_code == 400, resp.text
    assert "cannot be added or removed" in resp.text


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "00000000-0000-0000-0000-000000000000"])
def test_update_unknown_id_not_found(client, reset_draft, bad_id):
    resp = client.put(f"{C.INTEGRATIONS}/{bad_id}", json=P.make_integration())
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "00000000-0000-0000-0000-000000000000"])
def test_delete_unknown_id_not_found(client, reset_draft, bad_id):
    resp = client.delete(f"{C.INTEGRATIONS}/{bad_id}")
    assert resp.status_code == 404, resp.text


def test_delete_integration(client, integration):
    before = A.space_hash(client, C.SPACE_DRAFT)

    resp = client.delete(f"{C.INTEGRATIONS}/{integration['id']}")
    assert resp.status_code == 200, resp.text

    A.assert_not_in_index(client, C.INDEX_INTEGRATIONS, integration["id"])
    A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))


def test_delete_with_dependencies_rejected(client, integration, decoder):
    resp = client.delete(f"{C.INTEGRATIONS}/{integration['id']}")
    assert resp.status_code == 400, resp.text
    assert "Cannot delete integration" in resp.text
