"""Filter CRUD coverage (previously untested)."""

import pytest

from lib import assertions as A
from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.crud]


def test_create_and_delete_filter(client, reset_draft):
    fid = client.create(C.FILTERS, P.make_filter(space=C.SPACE_DRAFT))

    A.assert_in_index(client, C.INDEX_FILTERS, fid, space=C.SPACE_DRAFT)

    resp = client.delete(f"{C.FILTERS}/{fid}")
    assert resp.status_code == 200, resp.text
    A.assert_not_in_index(client, C.INDEX_FILTERS, fid)


def test_create_filter_missing_title_rejected(client, reset_draft):
    body = P.make_filter(space=C.SPACE_DRAFT)
    del body["resource"]["metadata"]["title"]
    resp = client.post(C.FILTERS, json=body)
    assert resp.status_code == 400, resp.text
