"""
OCSF 1.1.0 Detection Finding (class 2004): the class of the Wazuh custom source in Amazon
Security Lake, and the fixed Parquet schema every file the integration writes follows.

Every file has the same columns and types, whatever attributes its findings carry, so that
the AWS Glue tables of Security Lake read all of them alike. Attributes a finding does not
have are null.
"""
import pyarrow as pa

VERSION = "1.1.0"

CATEGORY_UID, CATEGORY_NAME = 2, "Findings"
CLASS_UID, CLASS_NAME = 2004, "Detection Finding"
ACTIVITY_ID, ACTIVITY_NAME = 1, "Create"
TYPE_UID, TYPE_NAME = CLASS_UID * 100 + ACTIVITY_ID, "Detection Finding: Create"

# severity_id of the levels of the Wazuh rules.
SEVERITIES = {
    "informational": (1, "Informational"),
    "low": (2, "Low"),
    "medium": (3, "Medium"),
    "high": (4, "High"),
    "critical": (5, "Critical"),
}
SEVERITY_UNKNOWN = (0, "Unknown")

# status_id of the statuses of the Wazuh cases. A finding without a case is new.
STATUS_NEW = (1, "New")
STATUSES = {
    "active": (2, "In Progress"),
    "acknowledged": (2, "In Progress"),
    "completed": (4, "Resolved"),
}
STATUS_OTHER = 99

# type_id of the observables.
OBSERVABLE_HOSTNAME = (1, "Hostname")
OBSERVABLE_IP = (2, "IP Address")
OBSERVABLE_USER = (4, "User Name")

_named = pa.struct([("uid", pa.string()), ("name", pa.string())])
_endpoint = pa.struct([("ip", pa.string()), ("port", pa.int32()), ("hostname", pa.string())])

SCHEMA = pa.schema([
    ("activity_id", pa.int32()),
    ("activity_name", pa.string()),
    ("category_uid", pa.int32()),
    ("category_name", pa.string()),
    ("class_uid", pa.int32()),
    ("class_name", pa.string()),
    ("type_uid", pa.int64()),
    ("type_name", pa.string()),
    ("severity_id", pa.int32()),
    ("severity", pa.string()),
    ("status_id", pa.int32()),
    ("status", pa.string()),
    ("time", pa.int64()),
    ("message", pa.string()),
    ("raw_data", pa.string()),
    ("metadata", pa.struct([
        ("version", pa.string()),
        ("uid", pa.string()),
        ("log_name", pa.string()),
        ("log_provider", pa.string()),
        ("original_time", pa.string()),
        ("profiles", pa.list_(pa.string())),
        ("product", pa.struct([("name", pa.string()), ("vendor_name", pa.string()), ("lang", pa.string())])),
    ])),
    ("finding_info", pa.struct([
        ("uid", pa.string()),
        ("title", pa.string()),
        ("desc", pa.string()),
        ("types", pa.list_(pa.string())),
        ("created_time", pa.int64()),
        ("analytic", pa.struct([
            ("uid", pa.string()),
            ("name", pa.string()),
            ("desc", pa.string()),
            ("category", pa.string()),
            ("type", pa.string()),
            ("type_id", pa.int32()),
            ("version", pa.string()),
        ])),
        ("attacks", pa.list_(pa.struct([
            ("tactic", _named),
            ("technique", _named),
            ("sub_technique", _named),
            ("version", pa.string()),
        ]))),
    ])),
    ("resources", pa.list_(pa.struct([("type", pa.string()), ("uid", pa.string()), ("name", pa.string())]))),
    ("evidences", pa.list_(pa.struct([
        ("src_endpoint", _endpoint),
        ("dst_endpoint", _endpoint),
        ("process", pa.struct([("name", pa.string()), ("pid", pa.int32()), ("cmd_line", pa.string())])),
        ("file", pa.struct([("name", pa.string()), ("path", pa.string()), ("type_id", pa.int32())])),
        ("actor", pa.struct([("user", pa.struct([("name", pa.string()), ("uid", pa.string())]))])),
    ]))),
    ("observables", pa.list_(pa.struct([
        ("name", pa.string()),
        ("type", pa.string()),
        ("type_id", pa.int32()),
        ("value", pa.string()),
    ]))),
    ("cloud", pa.struct([
        ("provider", pa.string()),
        ("region", pa.string()),
        ("account", pa.struct([("uid", pa.string())])),
    ])),
    ("unmapped", pa.map_(pa.string(), pa.string())),
])
