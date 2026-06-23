"""Findings-generation scenario: resources -> promote -> detector -> event -> finding.

Builds a Content Manager integration/decoder/rule, promotes it to custom (so the
rule syncs to Security Analytics), then creates a SAP detector over it, indexes a
matching event into the category's ``wazuh-events-v5-*`` data stream, runs the
detector's monitor on demand, and asserts a finding is produced.

Promotion alone does NOT create a detector for user content (only the CTI ruleset
sync does), so this scenario drives the detector via the SAP API. The detector's
``custom_rules`` references the **CTI rule id** (not the SAP rule ``_id``).

Like promotion, this mutates the test/custom spaces (not API-resettable) and
creates a detector, so it uses unique names per run and deletes the detector on
teardown.
"""

import datetime
import time
import uuid

import pytest

from lib import constants as C
from lib import payloads as P

pytestmark = [pytest.mark.findings]


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _wait_for(predicate, attempts=10, delay=3):
    """Poll ``predicate`` until truthy (returns it) or attempts run out (returns last)."""
    result = None
    for _ in range(attempts):
        result = predicate()
        if result:
            return result
        time.sleep(delay)
    return result


@pytest.fixture(scope="module")
def findings_env(client):
    """Promote a rule, create a detector over it, and yield the run context.

    The detector is deleted on teardown; the promoted custom content remains
    (the API cannot reset test/custom), which is why names are unique per run.
    """
    resp = client.reset_space(C.SPACE_DRAFT)
    assert resp.status_code == 200, f"reset draft failed: {resp.text}"

    uid = uuid.uuid4().hex[:6]
    title = f"ctfind{uid}"  # integration title == SAP log type == detector_type
    trigger = f"ct_trigger_{uid}"
    events_index = f"{C.EVENTS_INDEX_PREFIX}other"  # category 'other'

    iid = client.create(C.INTEGRATIONS, P.make_integration(title=title, category="other"))
    did = client.create(C.DECODERS, P.make_decoder(name=f"decoder/{title}/0"), integration=iid)
    detection = {"condition": "selection", "selection": {"event.action": trigger}}
    rid = client.create(
        C.RULES, P.make_rule(product=title, title=f"findrule-{uid}", detection=detection), integration=iid
    )
    resp = client.put(f"{C.POLICY}/{C.SPACE_DRAFT}", json=P.policy_body(root_decoder=did, integrations=[iid]))
    assert resp.status_code == 200, resp.text

    for space in (C.SPACE_DRAFT, C.SPACE_TEST):
        preview = client.get(C.PROMOTE, params={"space": space})
        assert preview.status_code == 200, preview.text
        promote = client.post(C.PROMOTE, json={"space": space, "changes": preview.json()["changes"]})
        assert promote.status_code == 200, promote.text

    resp = client.create_detector(P.sap_detector(title, events_index, cti_rule_id=rid))
    assert resp.status_code in (200, 201), f"detector create failed: {resp.text}"
    detector_id = resp.json()["_id"]

    monitors = client.detector_monitor_ids(detector_id)
    assert monitors, "detector created but no monitor id was assigned"

    context = {
        "title": title,
        "trigger": trigger,
        "events_index": events_index,
        "detector_id": detector_id,
        "monitors": monitors,
    }
    yield context

    client.delete_detector(detector_id)


def _index_and_run(client, ctx, action):
    """Index one event with ``event.action == action``, run the monitors, return doc id."""
    resp = client.index_event(ctx["events_index"], P.wcs_event(action, _now_iso()))
    doc_id = resp.json()["_id"]
    client.refresh(ctx["events_index"])
    for monitor_id in ctx["monitors"]:
        run = client.execute_monitor(monitor_id)
        assert run.status_code == 200, run.text
    return doc_id


@pytest.mark.findings
def test_matching_event_generates_finding(client, findings_env):
    doc_id = _index_and_run(client, findings_env, findings_env["trigger"])

    matched = _wait_for(lambda: doc_id in client.finding_doc_ids(findings_env["title"]))
    assert matched, f"no finding referenced the matching event {doc_id}"


@pytest.mark.findings
def test_non_matching_event_creates_no_finding(client, findings_env):
    doc_id = _index_and_run(client, findings_env, "ct_no_match_event")

    # Give the monitor the same chance to (incorrectly) produce a finding.
    time.sleep(6)
    assert doc_id not in client.finding_doc_ids(findings_env["title"]), (
        "a non-matching event unexpectedly produced a finding"
    )
