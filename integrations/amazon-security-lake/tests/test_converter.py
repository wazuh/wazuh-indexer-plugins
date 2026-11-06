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
    parquet, left_out = lambda_function.to_parquet(rows)
    assert left_out == 0
    table = pq.read_table(io.BytesIO(parquet))
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


def mitre_finding(**mitre):
    return {"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1", "mitre": mitre}}}


def attack_ids(row):
    return [tuple((a[k] or {}).get("uid") for k in ("tactic", "technique", "sub_technique"))
            for a in row["finding_info"]["attacks"]]


def test_attacks_keep_every_mitre_value_of_the_samples(findings):
    """Every tactic, technique and sub-technique of a rule is in an attack, and so is the parent of every sub-technique."""
    with_mitre = [f for f in findings if f["wazuh"]["rule"].get("mitre")]
    assert with_mitre
    for finding in with_mitre:
        mitre = finding["wazuh"]["rule"]["mitre"]
        row = converter.to_detection_finding(finding)
        attacks = row["finding_info"]["attacks"]
        for category, key in (("tactic", "tactic"), ("technique", "technique"), ("subtechnique", "sub_technique")):
            emitted = {a[key]["uid"] for a in attacks if a[key]}
            assert set(mitre.get(category, {}).get("id", [])) <= emitted, (finding["wazuh"]["rule"]["id"], category)
        for attack in attacks:
            if attack["sub_technique"]:
                assert attack["sub_technique"]["uid"].startswith(attack["technique"]["uid"] + ".")
        assert not [field for field in row["unmapped"] if field.startswith("wazuh.rule.mitre.")]


def test_attacks_with_a_single_tactic():
    """With one tactic, the rule says every technique belongs to it."""
    row = converter.to_detection_finding(mitre_finding(
        tactic={"id": ["TA0006"], "name": ["Credential Access"]},
        technique={"id": ["T1110", "T1003"], "name": ["Brute Force", "OS Credential Dumping"]},
        subtechnique={"id": ["T1110.001"], "name": ["Password Guessing"]}))
    assert attack_ids(row) == [("TA0006", "T1110", "T1110.001"), ("TA0006", "T1003", None)]


def test_attacks_do_not_pair_several_tactics_with_techniques():
    """With several tactics, the rule does not say which technique belongs to which: none is paired."""
    row = converter.to_detection_finding(mitre_finding(
        tactic={"id": ["TA0001", "TA0004"], "name": ["Initial Access", "Privilege Escalation"]},
        technique={"id": ["T1068", "T1190"], "name": ["Exploitation for Privilege Escalation", "Exploit Public-Facing Application"]}))
    assert attack_ids(row) == [("TA0001", None, None), ("TA0004", None, None), (None, "T1068", None), (None, "T1190", None)]
    assert row["finding_info"]["attacks"][3]["technique"]["name"] == "Exploit Public-Facing Application"


def test_attacks_keep_every_tactic_with_more_techniques():
    row = converter.to_detection_finding(mitre_finding(
        tactic={"id": ["TA0002", "TA0005"]}, technique={"id": ["T1027", "T1059", "T1140"]}))
    assert {a for a, _, _ in attack_ids(row)} == {"TA0002", "TA0005", None}


def test_a_sub_technique_without_its_technique():
    """The technique of a sub-technique is the part of its id before the dot."""
    row = converter.to_detection_finding(mitre_finding(
        tactic={"id": ["TA0003", "TA0010"]}, subtechnique={"id": ["T1505.003"], "name": ["Web Shell"]}))
    assert attack_ids(row) == [("TA0003", None, None), ("TA0010", None, None), (None, "T1505", "T1505.003")]


def test_mitre_ids_without_names():
    """Names are optional in the MITRE block of a rule: ids without names are still attacks."""
    row = converter.to_detection_finding(mitre_finding(tactic={"id": ["TA0006"]}, technique={"id": ["T1110"]}))
    attacks = row["finding_info"]["attacks"]
    assert attack_ids(row) == [("TA0006", "T1110", None)]
    assert attacks[0]["technique"]["name"] is None and attacks[0]["version"] is None
    assert not [field for field in row["unmapped"] if field.startswith("wazuh.rule.mitre.")]


def leaves(document: dict, prefix: str = "") -> dict:
    """Leaf fields of a document, by their dotted names: lists are leaves."""
    result = {}
    for name, value in document.items():
        if isinstance(value, dict) and value:
            result.update(leaves(value, f"{prefix}{name}."))
        else:
            result[f"{prefix}{name}"] = value
    return result


def assert_no_field_is_lost(finding):
    """
    What the manual promises: every field of the finding is in an OCSF attribute, or in `unmapped`
    under its name. Checked on the output, by value, with no help from the converter.
    """
    row = converter.to_detection_finding(finding)
    output = json.dumps({k: v for k, v in row.items() if k != "unmapped"}).lower()
    for field, value in leaves(finding).items():
        if value is None or field.startswith("_export") or field in row["unmapped"]:
            continue
        assert field in converter.MAPPED_FIELDS, f"{field} is neither mapped nor in unmapped"
        if field == "@timestamp":
            assert row["time"] == converter.to_epoch_ms(value)
            continue
        for item in value if isinstance(value, list) else [value]:
            text = item if isinstance(item, str) else json.dumps(item)
            assert json.dumps(text).lower()[1:-1] in output, f"{field}={item!r} is lost"
    assert all(isinstance(v, str) for v in row["unmapped"].values())
    return row


def test_no_field_of_the_samples_is_lost(findings):
    for finding in findings:
        row = assert_no_field_is_lost(finding)
        assert "event.original" not in row["unmapped"]


@pytest.mark.parametrize("extra,kept", [
    ({"cloud": {"region": "eu-west-1", "account": {"id": "123456789012"}}}, ["cloud.region", "cloud.account.id"]),
    ({"source": {"ip": ["203.0.113.7", "203.0.113.8"], "port": 52100}}, ["source.ip"]),
    ({"process": {"pid": 2 ** 40, "name": "sshd"}}, ["process.pid"]),
    ({"destination": {"port": "ssh"}}, ["destination.port"]),
    ({"destination": {"port": "--22"}}, ["destination.port"]),
    ({"destination": {"port": 22.5}}, ["destination.port"]),
    ({"user": {"name": {"first": "ana"}}}, ["user.name.first"]),
    ({"wazuh": {"rule": {"id": "r1", "level": "severe"}}}, ["wazuh.rule.level"]),
    ({"wazuh": {"rule": {"id": "r1"}, "case": {"status": "acknowledged"}}}, ["wazuh.case.status"]),
    ({"wazuh": {"rule": {"id": "r1", "mitre": {"tactic": {"name": ["Execution"]}}}}}, ["wazuh.rule.mitre.tactic.name"]),
])
def test_values_that_do_not_reach_their_attribute_are_kept(extra, kept):
    finding = {"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1"}}, **extra}
    row = assert_no_field_is_lost(finding)
    for field in kept:
        assert field in row["unmapped"]
    assert lambda_function.to_parquet([row])[1] == 0


def test_integers_as_text():
    row = converter.to_detection_finding({"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1"}},
                                          "source": {"ip": "203.0.113.7", "port": "52100"}})
    assert row["evidences"][0]["src_endpoint"] == {"ip": "203.0.113.7", "port": 52100}
    assert "source.port" not in row["unmapped"]


def test_cloud_without_a_provider():
    """OCSF requires the provider of a cloud: without one, there is no cloud attribute."""
    row = converter.to_detection_finding({"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1"}},
                                          "cloud": {"region": "eu-west-1"}})
    assert row["cloud"] is None and row["metadata"]["profiles"] == []
    assert row["unmapped"]["cloud.region"] == "eu-west-1"


def test_numeric_values_of_text_attributes():
    """A date in epoch milliseconds, or a numeric id, is text in OCSF."""
    row = converter.to_detection_finding({"@timestamp": 1792663200123, "wazuh": {"rule": {"id": "r1", "version": 2}},
                                          "event": {"start": 1792663200000}, "user": {"id": 1000}})
    assert row["metadata"]["original_time"] == "1792663200000"
    assert row["finding_info"]["analytic"]["version"] == "2"
    assert row["evidences"][0]["actor"]["user"]["uid"] == "1000"
    assert row["time"] == 1792663200123
    assert lambda_function.to_parquet([row])[1] == 0


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
    assert lambda_function.to_parquet([row])[1] == 0


def test_cloud_profile():
    finding = {"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1"}},
               "cloud": {"provider": "aws", "region": "eu-west-1", "account": {"id": "123456789012"}}}
    row = converter.to_detection_finding(finding)
    assert row["cloud"] == {"provider": "aws", "region": "eu-west-1", "account": {"uid": "123456789012"}}
    assert row["metadata"]["profiles"] == ["cloud"]


def test_minimal_finding_converts():
    row = converter.to_detection_finding({"@timestamp": "2026-10-22T10:00:00Z", "wazuh": {"rule": {"id": "r1"}}})
    assert row["severity_id"] == 0 and row["evidences"] == [] and row["resources"] == []
    assert lambda_function.to_parquet([row])[1] == 0


def test_events_are_not_findings():
    assert converter.to_detection_finding({"@timestamp": "2026-10-22T10:00:00Z", "event": {"kind": "event"}}) is None


def test_transform_events_skips_bad_lines(findings):
    lines = [json.dumps(findings[0]), "not json", json.dumps({"@timestamp": "2026-10-22T10:00:00Z"}), ""]
    rows, skipped = converter.transform_events(lines)
    assert len(rows) == 1 and skipped == 2
