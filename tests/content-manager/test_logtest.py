"""Logtest endpoint input-validation smoke tests.

Full detection coverage lives in ``test_logtest_modifiers.py`` (it needs a
promoted pipeline). Here we only assert request handling, which also pins two
openapi drifts: ``/logtest/normalization`` requires ``event`` (not ``input``),
and the valid ``trace_level`` values are NONE / ASSET_ONLY / ALL.
"""

import pytest

from lib import constants as C

pytestmark = [pytest.mark.logtest]


def test_logtest_without_integration_skips_detection(client, reset_draft):
    """``/logtest`` with no integration normalizes only; detection is skipped."""
    body = {
        "space": C.SPACE_TEST,
        "queue": 1,
        "location": "/var/log/test.log",
        "event": "some raw event",
        "trace_level": "NONE",
    }
    resp = client.post(C.LOGTEST, json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["message"]["detection"]["status"] == "skipped"


def test_normalization_requires_event(client, reset_draft):
    body = {"space": C.SPACE_TEST, "queue": 1, "location": "/var/log/test.log", "trace_level": "NONE"}
    resp = client.post(C.LOGTEST_NORMALIZATION, json=body)
    assert resp.status_code == 400, resp.text
    assert "event" in resp.text.lower()


def test_invalid_trace_level_rejected(client, reset_draft):
    body = {
        "space": C.SPACE_TEST,
        "queue": 1,
        "location": "/var/log/test.log",
        "event": "some raw event",
        "trace_level": "BASIC",  # openapi documents BASIC/FULL, but the engine rejects them
    }
    resp = client.post(C.LOGTEST_NORMALIZATION, json=body)
    assert resp.status_code == 400, resp.text
    assert "trace level" in resp.text.lower()
