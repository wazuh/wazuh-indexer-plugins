"""
Conversion of Wazuh findings, documents of the Wazuh Common Schema (WCS) read from the
wazuh-findings-v5-* data streams, into OCSF 1.1.0 Detection Findings (see ocsf.py).

The WCS fields that have an OCSF attribute are mapped to it. Every other field of the
finding is kept in `unmapped`, under its WCS name, so that no data is lost: lists and
objects as JSON, other values as text.

Logstash adds the `_export` object to every document: the id and the data stream of the
source document. It is not part of the finding.
"""
import json
import logging
from datetime import datetime

import ocsf

logger = logging.getLogger(__name__)

EXPORT_FIELD = "_export"

# WCS fields mapped to OCSF attributes. They are not repeated in `unmapped`.
MAPPED_FIELDS = (
    "@timestamp",
    "event.original",
    "event.start",
    "wazuh.rule.id",
    "wazuh.rule.title",
    "wazuh.rule.name",
    "wazuh.rule.description",
    "wazuh.rule.category",
    "wazuh.rule.version",
    "wazuh.rule.level",
    "wazuh.rule.mitre.tactic.id",
    "wazuh.rule.mitre.tactic.name",
    "wazuh.rule.mitre.technique.id",
    "wazuh.rule.mitre.technique.name",
    "wazuh.rule.mitre.subtechnique.id",
    "wazuh.rule.mitre.subtechnique.name",
    "wazuh.case.status",
    "wazuh.agent.id",
    "wazuh.agent.name",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "process.name",
    "process.pid",
    "process.command_line",
    "file.name",
    "file.path",
    "user.name",
    "user.id",
    "cloud.provider",
    "cloud.region",
    "cloud.account.id",
)

# Version of MITRE ATT&CK the rules refer to.
ATTACK_VERSION = "v13.1"


def get(document: dict, field: str):
    """Value of a field of a document, by its dotted name, from nested objects or dotted keys."""
    if field in document:
        return document[field]
    head, _, rest = field.partition(".")
    if rest and isinstance(document.get(head), dict):
        return get(document[head], rest)
    return None


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def to_epoch_ms(timestamp) -> int:
    """OCSF times are milliseconds since the epoch."""
    if isinstance(timestamp, (int, float)):
        return int(timestamp)
    return int(datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).timestamp() * 1000)


def flatten(document: dict, prefix: str = "") -> dict:
    """Leaf fields of a document, by their dotted names."""
    fields = {}
    for name, value in document.items():
        field = f"{prefix}{name}"
        if isinstance(value, dict) and value:
            fields.update(flatten(value, f"{field}."))
        else:
            fields[field] = value
    return fields


def unmapped(document: dict) -> dict:
    """Every leaf field of the finding that has no OCSF attribute, as text."""
    fields = {}
    for field, value in flatten(document).items():
        if field in MAPPED_FIELDS or field == EXPORT_FIELD or field.startswith(f"{EXPORT_FIELD}.") or value is None:
            continue
        fields[field] = value if isinstance(value, str) else json.dumps(value)
    return dict(sorted(fields.items()))


def attacks(document: dict) -> list:
    """
    MITRE ATT&CK of the rule: one attack per technique, with its sub-techniques. A rule lists
    its tactics apart from its techniques: with as many tactics as techniques they pair up in
    order, otherwise every technique takes the first tactic.
    """
    tactics = list(zip(as_list(get(document, "wazuh.rule.mitre.tactic.id")),
                       as_list(get(document, "wazuh.rule.mitre.tactic.name"))))
    techniques = list(zip(as_list(get(document, "wazuh.rule.mitre.technique.id")),
                          as_list(get(document, "wazuh.rule.mitre.technique.name"))))
    subtechniques = list(zip(as_list(get(document, "wazuh.rule.mitre.subtechnique.id")),
                             as_list(get(document, "wazuh.rule.mitre.subtechnique.name"))))
    if not techniques:
        return [{"tactic": {"uid": uid, "name": name}, "version": ATTACK_VERSION} for uid, name in tactics]
    result = []
    for i, (uid, name) in enumerate(techniques):
        tactic = tactics[i] if len(tactics) == len(techniques) else (tactics[0] if tactics else None)
        subs = [s for s in subtechniques if str(s[0]).startswith(f"{uid}.")] or [None]
        for sub in subs:
            result.append({
                "tactic": {"uid": tactic[0], "name": tactic[1]} if tactic else None,
                "technique": {"uid": uid, "name": name},
                "sub_technique": {"uid": sub[0], "name": sub[1]} if sub else None,
                "version": ATTACK_VERSION,
            })
    return result


def endpoint(document: dict, prefix: str):
    ip, port = get(document, f"{prefix}.ip"), as_int(get(document, f"{prefix}.port"))
    if ip is None and port is None:
        return None
    return {"ip": ip, "port": port}


def evidences(document: dict) -> list:
    """The entities of the event that matched the rule."""
    evidence = {
        "src_endpoint": endpoint(document, "source"),
        "dst_endpoint": endpoint(document, "destination"),
    }
    if any(get(document, f) is not None for f in ("process.name", "process.pid", "process.command_line")):
        evidence["process"] = {"name": get(document, "process.name"), "pid": as_int(get(document, "process.pid")),
                               "cmd_line": get(document, "process.command_line")}
    if get(document, "file.name") is not None or get(document, "file.path") is not None:
        evidence["file"] = {"name": get(document, "file.name"), "path": get(document, "file.path"), "type_id": 0}
    if get(document, "user.name") is not None or get(document, "user.id") is not None:
        evidence["actor"] = {"user": {"name": get(document, "user.name"), "uid": get(document, "user.id")}}
    return [evidence] if any(evidence.values()) else []


def observables(document: dict) -> list:
    result = []

    def add(name, kind, value):
        for item in as_list(value):
            if item is not None:
                result.append({"name": name, "type_id": kind[0], "type": kind[1], "value": str(item)})

    add("resources.name", ocsf.OBSERVABLE_HOSTNAME, get(document, "wazuh.agent.name"))
    add("evidences.src_endpoint.ip", ocsf.OBSERVABLE_IP, get(document, "source.ip"))
    add("evidences.dst_endpoint.ip", ocsf.OBSERVABLE_IP, get(document, "destination.ip"))
    add("evidences.actor.user.name", ocsf.OBSERVABLE_USER, get(document, "user.name"))
    return result


def cloud(document: dict):
    provider = get(document, "cloud.provider")
    if provider is None:
        return None
    account = get(document, "cloud.account.id")
    return {"provider": provider, "region": get(document, "cloud.region"),
            "account": {"uid": account} if account is not None else None}


def to_detection_finding(document: dict):
    """
    The OCSF Detection Finding of a Wazuh finding, or None if the document is not a finding
    (it has no `wazuh.rule`).
    """
    if not isinstance(get(document, "wazuh.rule"), dict):
        return None
    export = document.get(EXPORT_FIELD) or {}
    uid = export.get("id") or get(document, "wazuh.event.id")
    level = str(get(document, "wazuh.rule.level") or "").lower()
    severity_id, severity = ocsf.SEVERITIES.get(level, ocsf.SEVERITY_UNKNOWN)
    case_status = get(document, "wazuh.case.status")
    if case_status is None:
        status_id, status = ocsf.STATUS_NEW
    else:
        status_id, status = ocsf.STATUSES.get(str(case_status).lower(), (ocsf.STATUS_OTHER, str(case_status)))
    time = to_epoch_ms(get(document, "@timestamp"))
    title = get(document, "wazuh.rule.title") or get(document, "wazuh.rule.name")
    category = get(document, "wazuh.rule.category")
    agent_id, agent_name = get(document, "wazuh.agent.id"), get(document, "wazuh.agent.name")
    cloud_info = cloud(document)

    return {
        "activity_id": ocsf.ACTIVITY_ID,
        "activity_name": ocsf.ACTIVITY_NAME,
        "category_uid": ocsf.CATEGORY_UID,
        "category_name": ocsf.CATEGORY_NAME,
        "class_uid": ocsf.CLASS_UID,
        "class_name": ocsf.CLASS_NAME,
        "type_uid": ocsf.TYPE_UID,
        "type_name": ocsf.TYPE_NAME,
        "severity_id": severity_id,
        "severity": severity,
        "status_id": status_id,
        "status": status,
        "time": time,
        "message": title,
        "raw_data": get(document, "event.original"),
        "metadata": {
            "version": ocsf.VERSION,
            "uid": uid,
            "log_name": export.get("data_stream"),
            "log_provider": "Wazuh",
            "original_time": get(document, "event.start"),
            "profiles": ["cloud"] if cloud_info else [],
            "product": {"name": "Wazuh", "vendor_name": "Wazuh", "lang": "en"},
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": get(document, "wazuh.rule.description"),
            "types": [category] if category else [],
            "created_time": time,
            "analytic": {
                "uid": get(document, "wazuh.rule.id"),
                "name": get(document, "wazuh.rule.name") or title,
                "desc": get(document, "wazuh.rule.description"),
                "category": category,
                "type": "Rule",
                "type_id": 1,
                "version": get(document, "wazuh.rule.version"),
            },
            "attacks": attacks(document),
        },
        "resources": [{"type": "Host", "uid": agent_id, "name": agent_name}] if agent_id or agent_name else [],
        "evidences": evidences(document),
        "observables": observables(document),
        "cloud": cloud_info,
        "unmapped": unmapped(document),
    }


def transform_events(lines: list) -> tuple:
    """
    OCSF Detection Findings of the JSON lines of a file written by Logstash.
    Returns (findings, skipped): lines that are not JSON or not findings are skipped and logged.
    """
    findings, skipped = [], 0
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            finding = to_detection_finding(json.loads(line))
        except (ValueError, TypeError) as e:
            logger.error("line %d is not a valid finding: %s", number, e)
            skipped += 1
            continue
        if finding is None:
            logger.warning("line %d is not a finding (no wazuh.rule): skipped", number)
            skipped += 1
            continue
        findings.append(finding)
    return findings, skipped
