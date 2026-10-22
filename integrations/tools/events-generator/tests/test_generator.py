import base64
import csv
import hashlib
import json
from pathlib import Path

import pytest

import run

REPO_ROOT = Path(__file__).resolve().parents[4]
WCS_EVENTS = REPO_ROOT / "wcs" / "stateless" / "events"
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
SIGMA_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}


def wcs_fields(module: str) -> dict:
    """Fields of a WCS module, as {path: type}."""
    with open(WCS_EVENTS / module / "docs" / "fields.csv", newline="") as fd:
        return {row["Field"]: row["Type"] for row in csv.DictReader(fd)}


EVENT_FIELDS = wcs_fields("main")
FINDING_FIELDS = wcs_fields("findings")


def leaf_paths(document: dict, schema: dict, prefix: str = "") -> set:
    """Dotted paths of the values in a document. flat_object fields are leaves, whatever they hold."""
    paths = set()
    for key, value in document.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and schema.get(path) != "flat_object":
            paths |= leaf_paths(value, schema, f"{path}.")
        else:
            paths.add(path)
    return paths


@pytest.fixture(scope="module")
def samples():
    return run.load_samples()


@pytest.fixture(scope="module")
def agent(samples):
    return samples["agents"]["agents"][0]


def test_events_follow_wcs(samples, agent):
    for template in samples["events"]:
        event = run.build_event(template, agent, samples["agents"]["cluster"], run.now())
        unknown = leaf_paths(event, EVENT_FIELDS) - EVENT_FIELDS.keys()
        assert not unknown, f"fields not in the WCS events module: {sorted(unknown)}"


def test_findings_follow_wcs(samples, agent):
    for template in samples["events"]:
        event = run.build_event(template, agent, samples["agents"]["cluster"], run.now())
        for rule in run.rules_for(template, samples["rules"]):
            finding = run.build_finding(event, ".ds-wazuh-events-v5-x-000001", "doc-1", run.strip_rule(rule))
            unknown = leaf_paths(finding, FINDING_FIELDS) - FINDING_FIELDS.keys()
            assert not unknown, f"fields not in the WCS findings module: {sorted(unknown)}"


def test_every_category_has_events(samples):
    categories = {t["event"]["wazuh"]["integration"]["category"] for t in samples["events"]}
    assert categories == set(run.CATEGORIES)


def test_every_template_has_an_agent(samples):
    types = {a["host"]["os"]["type"] for a in samples["agents"]["agents"]}
    for template in samples["events"]:
        assert template.get("os", "any") in types | {"any"}


def test_rules(samples):
    integrations = {t["event"]["wazuh"]["integration"]["name"] for t in samples["events"]}
    ids = [rule["id"] for rule in samples["rules"]]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for rule in samples["rules"]:
        assert rule["level"] in SIGMA_LEVELS
        assert rule["status"] in SIGMA_STATUSES
        assert set(rule["integrations"]) <= integrations, f"rule {rule['id']} pairs with no event"
        for kind in rule.get("mitre", {}).values():
            assert len(kind["id"]) == len(kind["name"])


def test_finding_points_to_its_event(samples, agent):
    template = next(t for t in samples["events"] if run.rules_for(t, samples["rules"]))
    rule = run.strip_rule(run.rules_for(template, samples["rules"])[0])
    event = run.build_event(template, agent, samples["agents"]["cluster"], "2026-10-22T10:00:00.000Z")
    finding = run.build_finding(event, ".ds-wazuh-events-v5-security-000001", "abc", rule)
    assert finding["@timestamp"] == event["@timestamp"]
    assert finding["event"]["doc_id"] == "abc"
    assert finding["event"]["index"] == ".ds-wazuh-events-v5-security-000001"
    assert finding["wazuh"]["rule"] == rule
    assert "integrations" not in finding["wazuh"]["rule"]
    assert "rule" not in event["wazuh"], "building a finding must not modify the event"


def expected_id(key: str) -> str:
    """SHA-256 of the length-prefixed key, truncated to 128 bits, base64url without padding."""
    digest = hashlib.sha256(key.encode("utf-8")).digest()[:16]
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def test_dedup_id():
    one = run.dedup_id(".ds-wazuh-events-v5-security-000001", "doc-1", "rule-1")
    assert one == expected_id("35:.ds-wazuh-events-v5-security-0000015:doc-16:rule-1")
    assert len(one) == 22 and "=" not in one
    assert one != run.dedup_id(".ds-wazuh-events-v5-security-000001", "doc-1", "rule-2")
    assert one != run.dedup_id(".ds-wazuh-events-v5-security-000002", "doc-1", "rule-1")
    # Parts are length-prefixed: moving a character between parts changes the id.
    assert run.dedup_id("ab", "c", "r") != run.dedup_id("a", "bc", "r")
    # No rule is the empty string, as in the Security Analytics plugin.
    assert run.dedup_id("i", "d", None) == run.dedup_id("i", "d", "")


def test_dedup_id_counts_utf16_code_units():
    # Java's String.length() counts a character outside the BMP as two code units.
    assert run.dedup_id("i", "d", "\U0001F600") == expected_id("1:i1:d2:\U0001F600")


def test_stream_names():
    assert run.stream_name("events", "network-activity") == "wazuh-events-v5-network-activity"
    assert run.stream_name("findings", "security") == "wazuh-findings-v5-security"


def test_dry_run(capsys):
    run.main(["--dry-run", "--count", "20", "--time", "0", "--findings-ratio", "1", "--seed", "7"])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    events = [line for line in lines if "_id" not in line]
    findings = [line for line in lines if "_id" in line]
    assert len(events) == 20
    assert findings, "with a ratio of 1, events with rules must produce findings"
    for line in events:
        category = line["document"]["wazuh"]["integration"]["category"]
        assert line["stream"] == f"wazuh-events-v5-{category}"
    for line in findings:
        category = line["document"]["wazuh"]["integration"]["category"]
        assert line["stream"] == f"wazuh-findings-v5-{category}"


def test_categories_filter(capsys):
    run.main(["--dry-run", "--count", "10", "--time", "0", "--categories", "security", "--seed", "1"])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {line["stream"].split("-v5-")[1] for line in lines} == {"security"}


def test_rejects_unknown_categories():
    with pytest.raises(SystemExit):
        run.parse_args(["--dry-run", "--categories", "nope"])


class Recorder:
    """Client that records the documents instead of indexing them."""

    def __init__(self):
        self.indexed, self.created = [], []

    def index(self, stream, document):
        self.indexed.append(stream)
        return {"_index": f".ds-{stream}-000001", "_id": f"id-{len(self.indexed)}"}

    def create(self, stream, doc_id, document):
        self.created.append((stream, doc_id))
        return {"_index": f".ds-{stream}-000001", "_id": doc_id}


def test_delayed_findings_wait_until_due(samples):
    client, pending = Recorder(), run.Pending()
    run.generate(client, samples, ["security"], 1.0, run.random.Random(1), findings_delay=60, pending=pending)
    assert client.indexed and not client.created, "a delayed finding must not be indexed with its event"
    assert len(pending.items) == 1
    due = pending.items[0][0]
    pending.flush(client, due - 1)
    assert not client.created
    pending.flush(client, due)
    assert len(client.created) == 1 and client.created[0][0].startswith("wazuh-findings-v5-")
    assert not pending.items


def test_findings_without_delay_are_indexed_at_once(samples):
    client = Recorder()
    run.generate(client, samples, ["security"], 1.0, run.random.Random(1))
    assert len(client.created) == 1


def test_custom_stream_copies(samples):
    client = Recorder()
    run.generate(client, samples, ["security"], 0.0, run.random.Random(1), custom_stream="wazuh-custom-test", custom_ratio=1.0)
    assert client.indexed[0].startswith("wazuh-events-v5-")
    assert client.indexed[1] == "wazuh-custom-test"


def test_dry_run_flushes_delayed_findings_at_the_end(capsys):
    run.main(["--dry-run", "--count", "5", "--time", "0", "--findings-ratio", "1", "--findings-delay", "0.05",
              "--categories", "security", "--seed", "3"])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len([line for line in lines if "_id" in line]) == 5


def test_rejects_negative_delay():
    with pytest.raises(SystemExit):
        run.parse_args(["--dry-run", "--findings-delay", "-1"])
