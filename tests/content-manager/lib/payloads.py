"""Request-body builders for the Content Manager API.

Seeded from the ``examples:`` in ``plugins/content-manager/openapi.yml`` but
corrected against the live API (validated on a real cluster):

* integration / kvdb / rule fields are nested under ``resource.metadata``;
* decoder ``metadata.author`` is a **string** (the index maps it as keyword;
  an object yields a 500), and decoders use a ``parse|<field>`` block;
* rule ``logsource.product`` MUST equal the parent integration title;
* the integration ``rules``/``decoders``/``kvdbs`` arrays are reorder-only.

Builders return the request body dict. For create endpoints the ``integration``
field is added by ``CMClient.create``.
"""

# ── Integrations ──────────────────────────────────────────────────────────


def make_integration(
    title="component-test-integration",
    author="Wazuh Inc.",
    category="other",
    description="Integration created by the component test suite.",
    references=None,
    documentation="docs",
    enabled=True,
):
    """Body for ``POST /integrations``."""
    return {
        "resource": {
            "metadata": {
                "title": title,
                "author": author,
                "description": description,
                "references": references or ["https://wazuh.com"],
                "documentation": documentation,
            },
            "category": category,
            "enabled": enabled,
        }
    }


def integration_update(stored_document, **overrides):
    """Body for ``PUT /integrations/{id}`` from the stored ``document`` source.

    The ``rules``/``decoders``/``kvdbs`` arrays are reorder-only, so they must
    echo the integration's current contents — we read them back from the index.
    """
    meta = stored_document.get("metadata", {})
    body = {
        "metadata": {
            "title": meta.get("title"),
            "author": meta.get("author"),
            "description": meta.get("description", ""),
            "references": meta.get("references", []),
            "documentation": meta.get("documentation", ""),
        },
        "category": stored_document.get("category", "other"),
        "enabled": stored_document.get("enabled", True),
        "rules": stored_document.get("rules", []),
        "decoders": stored_document.get("decoders", []),
        "kvdbs": stored_document.get("kvdbs", []),
    }
    body.update(overrides)
    return {"resource": body}


# ── Decoders ──────────────────────────────────────────────────────────────


def make_decoder(
    name="decoder/component-test/0",
    title="Component test decoder",
    author="Wazuh, Inc.",
    parse_field="event.original",
    parse=None,
    normalize=None,
):
    """Body (sans ``integration``) for ``POST /decoders``.

    ``author`` is a string; the ``parse|<field>`` key carries the engine parse
    expression. Defaults to a simple "<key>=<value>" parser plus a normalize map.
    """
    if parse is None:
        parse = ["<event.action>=<message>"]
    if normalize is None:
        normalize = [{"map": [{"event.kind": "event"}]}]
    return {
        "resource": {
            "enabled": True,
            "name": name,
            "metadata": {
                "title": title,
                "author": author,
                "description": "Decoder created by the component test suite.",
                "module": "component-test",
                "references": ["https://wazuh.com"],
            },
            f"parse|{parse_field}": parse,
            "normalize": normalize,
        }
    }


# ── KVDBs ─────────────────────────────────────────────────────────────────


def make_kvdb(
    title="component-test-kvdb",
    author="Wazuh Inc.",
    content=None,
    enabled=True,
):
    """Body (sans ``integration``) for ``POST /kvdbs``. ``content`` needs >=1 key."""
    return {
        "resource": {
            "metadata": {"title": title, "author": author},
            "documentation": "docs",
            "references": ["https://wazuh.com"],
            "enabled": enabled,
            "content": content or {"key1": "value1"},
        }
    }


# ── Rules ─────────────────────────────────────────────────────────────────


def make_rule(
    product,
    title="Component test rule",
    detection=None,
    level="low",
    status="experimental",
    author="Wazuh",
    mitre=None,
):
    """Body (sans ``integration``) for ``POST /rules``.

    ``product`` MUST equal the parent integration's ``metadata.title``.
    """
    if detection is None:
        detection = {"condition": "selection", "selection": {"event.action": ["test_event"]}}
    return {
        "resource": {
            "metadata": {
                "title": title,
                "description": "Rule created by the component test suite.",
                "author": author,
                "references": ["https://wazuh.com"],
            },
            "enabled": True,
            "status": status,
            "level": level,
            "logsource": {"product": product, "category": "system"},
            "detection": detection,
            "mitre": mitre or {"tactic": ["TA0001"], "technique": ["T1190"], "subtechnique": []},
        }
    }


# ── Filters ───────────────────────────────────────────────────────────────


def make_filter(
    space="draft",
    name="filter/component-test/0",
    title="component-test-filter",
    check="$host.os.platform == 'ubuntu'",
):
    """Body for ``POST /filters``. ``metadata.title`` is required by the server."""
    return {
        "space": space,
        "resource": {
            "name": name,
            "enabled": True,
            "check": check,
            "type": "pre-filter",
            "metadata": {
                "title": title,
                "description": "Filter created by the component test suite.",
                "author": "Wazuh, Inc.",
            },
        },
    }


# ── Policy ────────────────────────────────────────────────────────────────


def policy_body(
    root_decoder,
    integrations,
    filters=None,
    enrichments=None,
    enabled=True,
    author="Wazuh Inc.",
    description="Policy updated by the component test suite.",
    documentation="docs",
    references=None,
    index_unclassified_events=False,
    index_discarded_events=False,
):
    """Body for ``PUT /policy/draft`` (reorder-safe: pass current integrations/filters)."""
    return {
        "resource": {
            "metadata": {
                "author": author,
                "description": description,
                "documentation": documentation,
                "references": references or ["https://wazuh.com"],
            },
            "root_decoder": root_decoder,
            "integrations": integrations,
            "filters": filters or [],
            "enrichments": enrichments or [],
            "enabled": enabled,
            "index_unclassified_events": index_unclassified_events,
            "index_discarded_events": index_discarded_events,
        }
    }


# ── Logtest: rich decoder + per-modifier rule matrix ───────────────────────

# Event layout (all fields parseable so PASS/FAIL events can toggle any field):
#   <level>  [<thread>] <date> <time> <file>.<ext>:<line> <ip> - <message> - <duration> - <severity>
LOGTEST_PARSE = (
    "<log.level>  [<process.thread.name>] <_tmp.date> <_tmp.time> "
    "<_tmp.f1>.<_tmp.f2>:<log.origin.file.line> <source.ip> - "
    "<message> - <_tmp.duration> - <_tmp.severity>"
)

LOGTEST_NORMALIZE = [
    {
        "map": [
            {"event.kind": "event"},
            {"event.category": 'array_append_unique("database")'},
            {"event.type": 'array_append_unique("info")'},
            {"log.origin.file.name": 'concat($_tmp.f1, ".", $_tmp.f2)'},
            {"event.duration": "parse_long($_tmp.duration)"},
            {"event.severity": "parse_long($_tmp.severity)"},
        ]
    }
]


def make_logtest_decoder(name="decoder/logtest-validation/0"):
    """A richer decoder used by the Sigma-modifier logtest matrix."""
    return make_decoder(
        name=name,
        title="Logtest validation decoder",
        parse_field="event.original",
        parse=[LOGTEST_PARSE],
        normalize=LOGTEST_NORMALIZE,
    )


def logtest_event(
    level="INFO",
    thread="TestThread-1",
    file="TestClass",
    ext="java",
    line=10,
    ip="10.42.3.15",
    message="normal msg",
    duration=100,
    severity=1,
):
    """Build an event string matching ``LOGTEST_PARSE``."""
    return (
        f"{level}  [{thread}] 2025-11-30 14:23:45 {file}.{ext}:{line} {ip} - "
        f"{message} - {duration} - {severity}"
    )


# Each entry: name, detection, and the PASS / FAIL events (kwargs for logtest_event).
MODIFIER_RULES = [
    {
        "name": "exact",
        "title": "LT exact log.level=ERROR",
        "detection": {"condition": "selection", "selection": {"log.level": "ERROR"}},
        "pass": {"level": "ERROR"},
        "fail": {"level": "INFO"},
    },
    {
        "name": "contains",
        "title": "LT contains message timeout",
        "detection": {"condition": "selection", "selection": {"message|contains": "timeout"}},
        "pass": {"message": "Connection timeout occurred"},
        "fail": {"message": "Connection established"},
    },
    {
        "name": "startswith",
        "title": "LT startswith thread Gossip",
        "detection": {"condition": "selection", "selection": {"process.thread.name|startswith": "Gossip"}},
        "pass": {"thread": "GossipStage-1"},
        "fail": {"thread": "TestThread-1"},
    },
    {
        "name": "endswith",
        "title": "LT endswith thread -5",
        "detection": {"condition": "selection", "selection": {"process.thread.name|endswith": "-5"}},
        "pass": {"thread": "Worker-5"},
        "fail": {"thread": "Worker-9"},
    },
    {
        "name": "wildcard",
        "title": "LT wildcard file Storage*.java",
        "detection": {"condition": "selection", "selection": {"log.origin.file.name": "Storage*.java"}},
        "pass": {"file": "StorageService", "ext": "java"},
        "fail": {"file": "TestClass", "ext": "java"},
    },
    {
        "name": "regex",
        "title": "LT regex thread ^Repair",
        "detection": {"condition": "selection", "selection": {"process.thread.name|re": "^Repair"}},
        "pass": {"thread": "RepairRunner-2"},
        "fail": {"thread": "TestThread-1"},
    },
    {
        "name": "cidr",
        "title": "LT cidr source.ip 10.42.0.0/16",
        "detection": {"condition": "selection", "selection": {"source.ip|cidr": "10.42.0.0/16"}},
        "pass": {"ip": "10.42.3.15"},
        "fail": {"ip": "192.168.1.1"},
    },
    {
        "name": "numeric",
        "title": "LT numeric duration>=5000 AND severity<10",
        "detection": {
            "condition": "selection",
            "selection": {"event.duration|gte": 5000, "event.severity|lt": 10},
        },
        "pass": {"duration": 7500, "severity": 4},
        "fail": {"duration": 3000, "severity": 15},
    },
    {
        "name": "or",
        "title": "LT or log.level ERROR or WARN",
        "detection": {
            "condition": "sel_error or sel_warn",
            "sel_error": {"log.level": "ERROR"},
            "sel_warn": {"log.level": "WARN"},
        },
        "pass": {"level": "WARN"},
        "fail": {"level": "INFO"},
    },
    {
        "name": "not",
        "title": "LT not thread startswith Test",
        "detection": {
            "condition": "selection and not filter",
            "selection": {"event.kind": "event"},
            "filter": {"process.thread.name|startswith": "Test"},
        },
        "pass": {"thread": "ScheduledTask-1"},
        "fail": {"thread": "TestThread-1"},
    },
    {
        "name": "and",
        "title": "LT and severity>=8 + message contains fatal",
        "detection": {
            "condition": "sel_sev and sel_msg",
            "sel_sev": {"event.severity|gte": 8},
            "sel_msg": {"message|contains": "fatal"},
        },
        "pass": {"message": "A fatal crash", "severity": 9},
        "fail": {"message": "A fatal crash", "severity": 2},
    },
]
