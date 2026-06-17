"""Management endpoints: subscription, on-demand update, version check."""

import pytest

from lib import constants as C

pytestmark = [pytest.mark.smoke]


class TestSubscription:
    def test_get_subscription(self, client):
        resp = client.get(C.SUBSCRIPTION)
        assert resp.status_code == 200, resp.text
        message = resp.json()["message"]
        assert "is_registered" in message
        assert "plan" in message

    def test_post_then_delete_credentials(self, client):
        """Round-trip credential storage, only when unregistered (never clobber a
        real registration)."""
        status = client.get(C.SUBSCRIPTION).json()["message"]
        if status.get("is_registered"):
            pytest.skip("instance is registered; not modifying credentials")

        resp = client.post(C.SUBSCRIPTION, json={"access_token": "component-test-dummy-token"})
        # 412 if the credentials index isn't declared a system index on this cluster.
        assert resp.status_code in (201, 412), resp.text
        if resp.status_code == 201:
            deleted = client.delete(C.SUBSCRIPTION)
            assert deleted.status_code == 200, deleted.text


class TestUpdate:
    def test_update_accepted(self, client):
        # Asynchronous: 202 accepted, or 409 if an update is already running.
        resp = client.post(C.UPDATE)
        assert resp.status_code in (202, 409), resp.text


class TestVersionCheck:
    def test_version_check(self, client):
        resp = client.get(C.VERSION_CHECK)
        assert resp.status_code == 200, resp.text
        message = resp.json()["message"]
        assert "current_version" in message
        assert "last_available_major" in message
