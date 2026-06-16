"""End-to-end logtest detection across every Sigma modifier type.

Builds one decoder + one rule per modifier in draft, promotes draft -> test,
then runs a PASS event (must match the target rule) and a FAIL event (must not)
through ``POST /logtest`` for each modifier.

Like ``test_promote``, this permanently mutates the test space, so resources are
named uniquely per run.
"""

import uuid

import pytest

from lib import constants as C
from lib import payloads as P
from lib.client import matched_titles

pytestmark = [pytest.mark.logtest]


@pytest.fixture(scope="module")
def promoted_env(client):
    """Reset draft, build the decoder + all modifier rules, promote to test."""
    resp = client.reset_space(C.SPACE_DRAFT)
    assert resp.status_code == 200, f"reset draft failed: {resp.text}"

    uid = uuid.uuid4().hex[:8]
    title = f"ct-logtest-{uid}"
    iid = client.create(C.INTEGRATIONS, P.make_integration(title=title))
    did = client.create(
        C.DECODERS,
        P.make_logtest_decoder(name=f"decoder/{title}/0"),
        integration=iid,
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
        f"{C.POLICY}/{C.SPACE_DRAFT}",
        json=P.policy_body(root_decoder=did, integrations=[iid]),
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
    event = P.logtest_event(**spec["pass"])
    titles = matched_titles(_logtest(client, promoted_env["integration"], event))
    assert title in titles, f"PASS event did not match '{title}'; matched={titles}"


@pytest.mark.parametrize("spec", P.MODIFIER_RULES, ids=lambda s: s["name"])
def test_modifier_fail(client, promoted_env, spec):
    title = promoted_env["rules"][spec["name"]]
    event = P.logtest_event(**spec["fail"])
    titles = matched_titles(_logtest(client, promoted_env["integration"], event))
    assert title not in titles, f"FAIL event unexpectedly matched '{title}'; matched={titles}"
