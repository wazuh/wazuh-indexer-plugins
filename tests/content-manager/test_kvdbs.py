"""KVDB CRUD coverage."""

import pytest

from lib import assertions as A
from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.crud]


def test_create_kvdb(client, integration):
    before = A.space_hash(client, C.SPACE_DRAFT)

    kid = client.create(C.KVDBS, P.make_kvdb(), integration=integration["id"])

    source = A.assert_in_index(client, C.INDEX_KVDBS, kid, space=C.SPACE_DRAFT)
    A.assert_hash_present(source)
    A.assert_in_integration_list(client, integration["id"], "kvdbs", kid)
    A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))


def test_create_kvdb_without_integration_rejected(client, reset_draft):
    resp = client.post(C.KVDBS, json=P.make_kvdb())
    assert resp.status_code == 400, resp.text


def test_update_kvdb(client, integration, kvdb):
    body = P.make_kvdb(content={"key1": "updated"})
    resp = client.put(f"{C.KVDBS}/{kvdb}", json=body)
    assert resp.status_code == 200, resp.text

    updated = client.get_doc(C.INDEX_KVDBS, kvdb)["document"]
    assert updated["content"]["key1"] == "updated"


def test_delete_kvdb(client, integration, kvdb):
    resp = client.delete(f"{C.KVDBS}/{kvdb}")
    assert resp.status_code == 200, resp.text

    A.assert_not_in_index(client, C.INDEX_KVDBS, kvdb)
    source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
    assert kvdb not in source.get("kvdbs", [])
