import csv
import io
import json
import random
import sys
from pathlib import Path

import pyarrow.parquet as pq
import pytest

import lambda_function
import ocsf
import wazuh_ocsf_converter as converter

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "integrations" / "tools" / "events-generator"))
import run as generator  # noqa: E402

FINDING_FIELDS = {row["Field"] for row in csv.DictReader(
    open(REPO_ROOT / "wcs" / "stateless" / "events" / "findings" / "docs" / "fields.csv"))}
EXPORT = {"id": "f1nd1ng-1d", "data_stream": "wazuh-findings-v5-security"}


@pytest.fixture(scope="module")
def findings():
    """Every finding the events generator builds from its samples, as Logstash exports them."""
    samples = generator.load_samples()
    rng = random.Random(7)
    agent, cluster = samples["agents"]["agents"][0], samples["agents"]["cluster"]
    result = []
    for template in samples["events"]:
        for rule in generator.rules_for(template, samples["rules"]):
            event = generator.build_event(template, agent, cluster, "2026-10-22T10:00:00.123Z", generator.event_id(rng))
            finding = generator.build_finding(event, ".ds-wazuh-events-v5-security-000001", "ev3nt-1d", generator.strip_rule(rule))
            finding[converter.EXPORT_FIELD] = dict(EXPORT)
            result.append(finding)
    return result


def test_mapped_fields_are_wcs_fields():
    unknown = [field for field in converter.MAPPED_FIELDS if field not in FINDING_FIELDS]
    assert not unknown, f"fields not in the WCS findings module: {unknown}"


def test_every_sample_finding_converts_to_the_schema(findings):
    rows = [converter.to_detection_finding(f) for f in findings]
    assert rows and all(rows)
    table = pq.read_table(io.BytesIO(lambda_function.to_parquet(rows)))
    assert table.num_rows == len(findings)
    assert table.schema.equals(ocsf.SCHEMA)


def test_required_attributes(findings):
    row = converter.to_detection_finding(findings[0])
    assert (row["class_uid"], row["category_uid"], row["activity_id"], row["type_uid"]) == (2004, 2, 1, 200401)
    assert row["metadata"]["version"] == "1.1.0"
    assert row["metadata"]["product"]["name"] == "Wazuh"
    assert row["finding_info"]["uid"] == EXPORT["id"]
    assert row["metadata"]["uid"] == EXPORT["id"]
    assert row["metadata"]["log_name"] == EXPORT["data_stream"]
    assert row["finding_info"]["title"] == findings[0]["wazuh"]["rule"]["title"]
    assert row["severity_id"] in range(1, 6)


def test_time_is_in_milliseconds(findings):
    row = converter.to_detection_finding(findings[0])
    assert row["time"] == 1792663200123
    assert row["finding_info"]["created_time"] == row["time"]


@pytest.mark.parametrize("level,expected", [
    ("informational", 1), ("low", 2), ("medium", 3), ("high", 4), ("critical", 5), ("unexpected", 0),
])
def test_severity(findings, level, expected):
    finding = json.loads(json.dumps(findings[0]))
    finding["wazuh"]["rule"]["level"] = level
    assert converter.to_detection_finding(finding)["severity_id"] == expected


@pytest.mark.parametrize("case,expected", [
    (None, (1, "New")), ("active", (2, "In Progress")), ("acknowledged", (2, "In Progress")),
    ("completed", (4, "Resolved")), ("audit", (99, "audit")),
])
def test_status_from_the_case(findings, case, expected):
    finding = json.loads(json.dumps(findings[0]))
    if case:
        finding["wazuh"]["case"] = {"status": case}
    row = converter.to_detection_finding(finding)
    assert (row["status_id"], row["status"]) == expected


def test_attacks_pair_techniques_and_sub_techniques(findings):
    finding = next(f for f in findings if f["wazuh"]["rule"].get("mitre", {}).get("subtechnique"))
    attacks = converter.to_detection_finding(finding)["finding_info"]["attacks"]
    mitre = finding["wazuh"]["rule"]["mitre"]
    assert {a["technique"]["uid"] for a in attacks} == set(mitre["technique"]["id"])
    for attack in attacks:
        if attack["sub_technique"]:
            assert attack["sub_technique"]["uid"].startswith(attack["technique"]["uid"] + ".")
        assert attack["tactic"]["uid"] in mitre["tactic"]["id"]


def test_unmapped_keeps_every_other_field(findings):
    finding = findings[0]
    row = converter.to_detection_finding(finding)
    leaves = converter.flatten(finding)
    for field, value in leaves.items():
        if field in converter.MAPPED_FIELDS or field.startswith(converter.EXPORT_FIELD) or value is None:
            assert field not in row["unmapped"]
        else:
            assert field in row["unmapped"], field
    assert all(isinstance(v, str) for v in row["unmapped"].values())
    assert "event.original" not in row["unmapped"]


def test_evidences_and_observables():
    finding = {
        "@timestamp": "2026-10-22T10:00:00.000Z",
        "wazuh": {"rule": {"id": "r1", "title": "t", "level": "high"}, "agent": {"id": "001", "name": "web-01"}},
        "source": {"ip": "203.0.113.7", "port": 52100},
        "destination": {"ip": "10.0.0.5", "port": 22},
        "user": {"name": "root"},
        "process": {"name": "sshd", "pid": 4242},
    }
    row = converter.to_detection_finding(finding)
    evidence = row["evidences"][0]
    assert evidence["src_endpoint"] == {"ip": "203.0.113.7", "port": 52100}
    assert evidence["dst_endpoint"]["port"] == 22
    assert evidence["actor"]["user"]["name"] == "root"
    assert evidence["process"]["pid"] == 4242
    assert {(o["name"], o["value"]) for o in row["observables"]} == {
        ("resources.name", "web-01"), ("evidences.src_endpoint.ip", "203.0.113.7"),
        ("evidences.dst_endpoint.ip", "10.0.0.5"), ("evidences.actor.user.name", "root")}
    assert row["resources"] == [{"type": "Host", "uid": "001", "name": "web-01"}]
    lambda_function.to_parquet([row])


def test_cloud_profile():
    finding = {"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1"}},
               "cloud": {"provider": "aws", "region": "eu-west-1", "account": {"id": "123456789012"}}}
    row = converter.to_detection_finding(finding)
    assert row["cloud"] == {"provider": "aws", "region": "eu-west-1", "account": {"uid": "123456789012"}}
    assert row["metadata"]["profiles"] == ["cloud"]


def test_minimal_finding_converts():
    row = converter.to_detection_finding({"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1"}}})
    assert row["severity_id"] == 0 and row["evidences"] == [] and row["resources"] == []
    lambda_function.to_parquet([row])


def test_events_are_not_findings():
    assert converter.to_detection_finding({"@timestamp": "2026-10-22T10:00:00Z", "event": {"kind": "event"}}) is None


def test_transform_events_skips_bad_lines(findings):
    lines = [json.dumps(findings[0]), "not json", json.dumps({"@timestamp": "2026-10-22T10:00:00Z"}), ""]
    rows, skipped = converter.transform_events(lines)
    assert len(rows) == 1 and skipped == 2
