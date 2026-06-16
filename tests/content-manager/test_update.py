"""On-demand content update endpoint coverage (previously untested).

``POST /update`` is asynchronous: it returns 202 immediately, or 409 if an
update is already running. It kicks off a background CTI sync, so it runs as its
own (alphabetically late) module.
"""

import pytest

from lib import constants as C

pytestmark = [pytest.mark.smoke]


def test_update_accepted(client):
    resp = client.post(C.UPDATE)
    assert resp.status_code in (202, 409), resp.text
