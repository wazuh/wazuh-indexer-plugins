"""Version-check endpoint coverage (previously untested)."""

import pytest

from lib import constants as C

pytestmark = [pytest.mark.smoke]


def test_version_check(client):
    resp = client.get(C.VERSION_CHECK)
    assert resp.status_code == 200, resp.text
    message = resp.json()["message"]
    assert "current_version" in message
    # last_available_{major,minor,patch} are always present (possibly empty objects).
    assert "last_available_major" in message
