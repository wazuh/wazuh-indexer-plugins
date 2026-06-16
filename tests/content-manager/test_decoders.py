"""Decoder CRUD coverage."""

import pytest

from lib import assertions as A
from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.crud]


def test_create_decoder(client, integration):
    before = A.space_hash(client, C.SPACE_DRAFT)

    did = client.create(C.DECODERS, P.make_decoder(), integration=integration["id"])

    source = A.assert_in_index(client, C.INDEX_DECODERS, did, space=C.SPACE_DRAFT)
    A.assert_hash_present(source)
    A.assert_in_integration_list(client, integration["id"], "decoders", did)
    A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))


def test_create_decoder_without_integration_rejected(client, reset_draft):
    resp = client.post(C.DECODERS, json=P.make_decoder())
    assert resp.status_code == 400, resp.text


def test_update_decoder(client, integration, decoder):
    body = P.make_decoder()
    body["resource"]["metadata"]["title"] = "Decoder updated"
    resp = client.put(f"{C.DECODERS}/{decoder}", json=body)
    assert resp.status_code == 200, resp.text

    updated = client.get_doc(C.INDEX_DECODERS, decoder)["document"]
    assert updated["metadata"]["title"] == "Decoder updated"


def test_delete_decoder(client, integration, decoder):
    resp = client.delete(f"{C.DECODERS}/{decoder}")
    assert resp.status_code == 200, resp.text

    A.assert_not_in_index(client, C.INDEX_DECODERS, decoder)
    source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
    assert decoder not in source.get("decoders", [])


def test_delete_decoder_unknown_not_found(client, reset_draft):
    resp = client.delete(f"{C.DECODERS}/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404, resp.text
