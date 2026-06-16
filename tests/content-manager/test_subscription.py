"""CTI subscription endpoint coverage (previously untested)."""

import pytest

from lib import constants as C

pytestmark = [pytest.mark.smoke]


def test_get_subscription(client):
    resp = client.get(C.SUBSCRIPTION)
    assert resp.status_code == 200, resp.text
    message = resp.json()["message"]
    assert "is_registered" in message
    assert "plan" in message


def test_post_then_delete_credentials(client):
    """Round-trip credential storage, but only when the instance is unregistered
    (so a real registration is never clobbered)."""
    status = client.get(C.SUBSCRIPTION).json()["message"]
    if status.get("is_registered"):
        pytest.skip("instance is registered; not modifying credentials")

    resp = client.post(C.SUBSCRIPTION, json={"access_token": "component-test-dummy-token"})
    # 412 if the credentials index isn't declared a system index on this cluster.
    assert resp.status_code in (201, 412), resp.text

    if resp.status_code == 201:
        deleted = client.delete(C.SUBSCRIPTION)
        assert deleted.status_code == 200, deleted.text
