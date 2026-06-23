"""Logtest scenario: request validation plus end-to-end Sigma-modifier detection.

The modifier suite builds one decoder + one rule per Sigma modifier in draft,
promotes draft -> test, then runs a PASS event (must match the target rule) and
a FAIL event (must not) through ``POST /logtest`` for each modifier.

Validation tests also pin two openapi drifts: ``/logtest/normalization`` requires
``event`` (not ``input``), and the valid ``trace_level`` values are
NONE / ASSET_ONLY / ALL.

Like promotion, the modifier setup permanently mutates the test space, so it
names its resources uniquely per run.
"""

import uuid

import pytest

from lib import constants as C
from lib import payloads as P
from lib.client import matched_titles

pytestmark = [pytest.mark.logtest]


# ── Request validation ─────────────────────────────────────────────────────


class TestLogtestValidation:
    def test_without_integration_skips_detection(self, client, reset_draft):
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

    def test_normalization_requires_event(self, client, reset_draft):
        body = {"space": C.SPACE_TEST, "queue": 1, "location": "/var/log/test.log", "trace_level": "NONE"}
        resp = client.post(C.LOGTEST_NORMALIZATION, json=body)
        assert resp.status_code == 400, resp.text
        assert "event" in resp.text.lower()

    def test_invalid_trace_level_rejected(self, client, reset_draft):
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


# ── Sigma modifier detection matrix ────────────────────────────────────────


@pytest.fixture(scope="module")
def promoted_env(client):
    """Reset draft, build the decoder + all modifier rules, promote to test."""
    resp = client.reset_space(C.SPACE_DRAFT)
    assert resp.status_code == 200, f"reset draft failed: {resp.text}"

    uid = uuid.uuid4().hex[:8]
    title = f"ct-logtest-{uid}"
    iid = client.create(C.INTEGRATIONS, P.make_integration(title=title))
    did = client.create(
        C.DECODERS, P.make_logtest_decoder(name=f"decoder/{title}/0"), integration=iid
    )

    rules = {}
    for spec in P.MODIFIER_RULES:
        rule_title = f"{spec['title']} [{uid}]"
        client.create(
            C.RULES,
            P.make_rule(product=title, title=rule_title, detection=spec["detection"]),
            integration=iid,
        )
        rules[spec["name"]] = rule_title

    resp = client.put(
        f"{C.POLICY}/{C.SPACE_DRAFT}", json=P.policy_body(root_decoder=did, integrations=[iid])
    )
    assert resp.status_code == 200, f"policy update failed: {resp.text}"

    preview = client.get(C.PROMOTE, params={"space": C.SPACE_DRAFT})
    assert preview.status_code == 200, preview.text
    promote = client.post(
        C.PROMOTE, json={"space": C.SPACE_DRAFT, "changes": preview.json()["changes"]}
    )
    assert promote.status_code == 200, promote.text

    return {"integration": iid, "rules": rules}


def _logtest(client, integration_id, event):
    body = {
        "integration": integration_id,
        "space": C.SPACE_TEST,
        "queue": 1,
        "location": "/var/log/logtest-validation.log",
        "event": event,
        "trace_level": "NONE",
    }
    resp = client.post(C.LOGTEST, json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.parametrize("spec", P.MODIFIER_RULES, ids=lambda s: s["name"])
def test_modifier_pass(client, promoted_env, spec):
    title = promoted_env["rules"][spec["name"]]
    titles = matched_titles(_logtest(client, promoted_env["integration"], P.logtest_event(**spec["pass"])))
    assert title in titles, f"PASS event did not match '{title}'; matched={titles}"


@pytest.mark.parametrize("spec", P.MODIFIER_RULES, ids=lambda s: s["name"])
def test_modifier_fail(client, promoted_env, spec):
    title = promoted_env["rules"][spec["name"]]
    titles = matched_titles(_logtest(client, promoted_env["integration"], P.logtest_event(**spec["fail"])))
    assert title not in titles, f"FAIL event unexpectedly matched '{title}'; matched={titles}"
