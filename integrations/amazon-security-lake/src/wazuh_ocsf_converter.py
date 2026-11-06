"""
Conversion of Wazuh findings, documents of the Wazuh Common Schema (WCS) read from the
wazuh-findings-v5-* data streams, into OCSF 1.1.0 Detection Findings (see ocsf.py).

The WCS fields that have an OCSF attribute are mapped to it. Every other field of the
finding is kept in `unmapped`, under its WCS name, so that no data is lost: lists and
objects as JSON, other values as text. So is a mapped field whose value does not reach its
attribute, such as a list where OCSF takes a single IP address, or the region of a cloud
without a provider.

Logstash adds the `_export` object to every document: the id and the data stream of the
source document. It is not part of the finding.
"""
import json
import logging
import re
from datetime import datetime

import ocsf

logger = logging.getLogger(__name__)

EXPORT_FIELD = "_export"
INTEGER = re.compile(r"\s*-?\d+\s*")

# WCS fields mapped to OCSF attributes. They are not repeated in `unmapped` when their value
# reaches the attribute.
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


def as_text(value) -> str:
    """A value as text: strings as they are, anything else as JSON."""
    return value if isinstance(value, str) else json.dumps(value)


class Fields:
    """
    Reads the fields of a finding into OCSF attributes, and records the ones whose value
    reached its attribute whole: every other field is kept in `unmapped`.
    """

    INT32 = range(-2 ** 31, 2 ** 31)

    def __init__(self, document: dict):
        self.document = document
        self.used = set()

    def use(self, field: str):
        self.used.add(field)

    def text(self, field: str):
        """A single value as text, or None for lists and objects."""
        value = get(self.document, field)
        if value is None or isinstance(value, (list, dict)):
            return None
        self.use(field)
        return as_text(value)

    def integer(self, field: str):
        """A single value as a 32-bit integer, or None if it is not one."""
        value = get(self.document, field)
        if isinstance(value, str) and INTEGER.fullmatch(value):
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool) or value not in self.INT32:
            return None
        self.use(field)
        return value

    def texts(self, field: str) -> list:
        """The values of an array as text, or [] if one of them is a list or an object."""
        values = [v for v in as_list(get(self.document, field)) if v is not None]
        if not values or any(isinstance(v, (list, dict)) for v in values):
            return []
        self.use(field)
        return [as_text(v) for v in values]

    def unmapped(self) -> dict:
        """Every leaf field of the finding whose value is in no OCSF attribute, as text."""
        fields = {}
        for field, value in flatten(self.document).items():
            if field in self.used or field == EXPORT_FIELD or field.startswith(f"{EXPORT_FIELD}.") or value is None:
                continue
            fields[field] = as_text(value)
        return dict(sorted(fields.items()))


def named(fields: Fields, category: str) -> list:
    """
    (id, name) of the tactics, techniques or sub-techniques of the rule. The names are optional:
    a rule lists either none or one per id.
    """
    ids = fields.texts(f"wazuh.rule.mitre.{category}.id")
    name_field = f"wazuh.rule.mitre.{category}.name"
    # Names without an id to go with, no ids or more names than ids, stay in `unmapped`.
    names = fields.texts(name_field) if ids and len(as_list(get(fields.document, name_field))) <= len(ids) else []
    return [(uid, names[i] if i < len(names) else None) for i, uid in enumerate(ids)]


def attacks(fields: Fields) -> list:
    """
    MITRE ATT&CK of the rule. A rule lists its tactics, techniques and sub-techniques apart, and
    does not say which technique belongs to which tactic, so no pairing is made up: with a single
    tactic, every technique takes it; with several, the tactics are attacks of their own and the
    techniques have no tactic. A sub-technique goes with its technique, the part of its id before
    the dot, whether the rule lists that technique or not.
    """
    tactics = named(fields, "tactic")
    techniques = dict(named(fields, "technique"))
    subtechniques = named(fields, "subtechnique")
    for uid, _ in subtechniques:
        if "." in uid:
            techniques.setdefault(uid.split(".")[0], None)

    def obj(pair):
        return {"uid": pair[0], "name": pair[1]} if pair else None

    tactic = tactics[0] if len(tactics) == 1 else None
    result = []
    if tactic is None or not techniques:
        result += [{"tactic": obj(t), "technique": None, "sub_technique": None, "version": None} for t in tactics]
    for uid, name in techniques.items():
        subs = [s for s in subtechniques if s[0].startswith(f"{uid}.")] or [None]
        for sub in subs:
            result.append({"tactic": obj(tactic),
                           "technique": {"uid": uid, "name": name}, "sub_technique": obj(sub), "version": None})
    # Sub-techniques with no technique in their id stand alone.
    result += [{"tactic": None, "technique": None, "sub_technique": obj(s), "version": None}
               for s in subtechniques if "." not in s[0]]
    return result


def endpoint(fields: Fields, prefix: str):
    ip, port = fields.text(f"{prefix}.ip"), fields.integer(f"{prefix}.port")
    if ip is None and port is None:
        return None
    return {"ip": ip, "port": port}


def evidences(fields: Fields) -> list:
    """The entities of the event that matched the rule."""
    evidence = {
        "src_endpoint": endpoint(fields, "source"),
        "dst_endpoint": endpoint(fields, "destination"),
    }
    process = {"name": fields.text("process.name"), "pid": fields.integer("process.pid"),
               "cmd_line": fields.text("process.command_line")}
    if any(v is not None for v in process.values()):
        evidence["process"] = process
    file = {"name": fields.text("file.name"), "path": fields.text("file.path")}
    if any(v is not None for v in file.values()):
        evidence["file"] = {**file, "type_id": 0}
    user = {"name": fields.text("user.name"), "uid": fields.text("user.id")}
    if any(v is not None for v in user.values()):
        evidence["actor"] = {"user": user}
    return [evidence] if any(evidence.values()) else []


def observables(document: dict) -> list:
    result = []

    def add(name, kind, value):
        for item in as_list(value):
            if item is not None and not isinstance(item, (list, dict)):
                result.append({"name": name, "type_id": kind[0], "type": kind[1], "value": str(item)})

    add("resources.name", ocsf.OBSERVABLE_HOSTNAME, get(document, "wazuh.agent.name"))
    add("evidences.src_endpoint.ip", ocsf.OBSERVABLE_IP, get(document, "source.ip"))
    add("evidences.dst_endpoint.ip", ocsf.OBSERVABLE_IP, get(document, "destination.ip"))
    add("evidences.actor.user.name", ocsf.OBSERVABLE_USER, get(document, "user.name"))
    return result


def cloud(fields: Fields):
    """The cloud of the finding. OCSF requires its provider: without one, the cloud fields stay in `unmapped`."""
    provider = fields.text("cloud.provider")
    if provider is None:
        return None
    account = fields.text("cloud.account.id")
    return {"provider": provider, "region": fields.text("cloud.region"),
            "account": {"uid": account} if account is not None else None}


def to_detection_finding(document: dict):
    """
    The OCSF Detection Finding of a Wazuh finding, or None if the document is not a finding
    (it has no `wazuh.rule`).
    """
    if not isinstance(get(document, "wazuh.rule"), dict):
        return None
    fields = Fields(document)
    export = document.get(EXPORT_FIELD) or {}
    event_id = get(document, "wazuh.event.id")
    uid = export.get("id") or (as_text(event_id) if event_id is not None else None)
    level = str(get(document, "wazuh.rule.level")).lower()
    if level in ocsf.SEVERITIES:
        fields.use("wazuh.rule.level")
    severity_id, severity = ocsf.SEVERITIES.get(level, ocsf.SEVERITY_UNKNOWN)
    # The status of the case is kept in `unmapped` too: OCSF merges some of them (active and acknowledged).
    case_status = get(document, "wazuh.case.status")
    if case_status is None or isinstance(case_status, (list, dict)):
        status_id, status = ocsf.STATUS_NEW
    else:
        case_status = as_text(case_status)
        status_id, status = ocsf.STATUSES.get(case_status.lower(), (ocsf.STATUS_OTHER, case_status))
    time = to_epoch_ms(get(document, "@timestamp"))
    fields.use("@timestamp")
    rule_title, rule_name = fields.text("wazuh.rule.title"), fields.text("wazuh.rule.name")
    title = rule_title or rule_name
    description = fields.text("wazuh.rule.description")
    category = fields.text("wazuh.rule.category")
    agent_id, agent_name = fields.text("wazuh.agent.id"), fields.text("wazuh.agent.name")
    cloud_info = cloud(fields)

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
        "raw_data": fields.text("event.original"),
        "metadata": {
            "version": ocsf.VERSION,
            "uid": uid,
            "log_name": export.get("data_stream"),
            "log_provider": "Wazuh",
            "original_time": fields.text("event.start"),
            "profiles": ["cloud"] if cloud_info else [],
            "product": {"name": "Wazuh", "vendor_name": "Wazuh", "lang": "en"},
        },
        "finding_info": {
            "uid": uid,
            "title": title,
            "desc": description,
            "types": [category] if category else [],
            "created_time": time,
            "analytic": {
                "uid": fields.text("wazuh.rule.id"),
                "name": rule_name or title,
                "desc": description,
                "category": category,
                "type": "Rule",
                "type_id": 1,
                "version": fields.text("wazuh.rule.version"),
            },
            "attacks": attacks(fields),
        },
        "resources": [{"type": "Host", "uid": agent_id, "name": agent_name}] if agent_id or agent_name else [],
        "evidences": evidences(fields),
        "observables": observables(document),
        "cloud": cloud_info,
        # Last: every other reader has recorded the fields it used.
        "unmapped": fields.unmapped(),
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
