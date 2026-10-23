"""OpenSearch Dashboards saved objects (index patterns, visualizations and dashboards) of the Wazuh dashboards.

The visualizations are the aggregation-based ones, written in the 7.10 saved object format,
which OpenSearch Dashboards migrates on import.
"""
import json
import uuid

NS = uuid.UUID("0b8e5f2a-6c4d-4a1e-9f3b-7d2c5e8a1f60")
PANEL_VERSION = "3.9.0"


def uid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


INDEX_PATTERNS = {
    "findings": {"id": "wazuh-findings", "title": "logs-wazuh.findings.*-*"},
    "events": {"id": "wazuh-events", "title": "logs-wazuh.events.*-*"},
}

# ---- Aggregations ----


def count(label="Count"):
    return {"type": "count", "params": {"customLabel": label}, "schema": "metric"}


def unique(field, label):
    return {"type": "cardinality", "params": {"field": field, "customLabel": label}, "schema": "metric"}


def histogram(schema="segment"):
    return {"type": "date_histogram", "schema": schema,
            "params": {"field": "@timestamp", "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
                       "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}


def terms(field, label, size, schema):
    return {"type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size, "otherBucket": False,
                       "otherBucketLabel": "Other", "missingBucket": False, "missingBucketLabel": "Missing", "customLabel": label}}


def filters(series, schema="group"):
    return {"type": "filters", "schema": schema,
            "params": {"filters": [{"input": {"query": kql, "language": "kuery"}, "label": label} for label, kql in series]}}


# ---- Visualization params ----

def axes_params(vis_type, legend):
    horizontal = vis_type == "horizontal_bar"
    return {
        "type": "histogram",
        "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left" if horizontal else "bottom", "show": True,
                          "style": {}, "scale": {"type": "linear"},
                          "labels": {"show": True, "rotate": 0, "filter": not horizontal, "truncate": 200 if horizontal else 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "bottom" if horizontal else "left", "show": True,
                       "style": {}, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": horizontal, "truncate": 100}, "title": {"text": "Count"}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked" if not horizontal else "normal",
                          "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                          "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
        "addTooltip": True, "addLegend": legend, "legendPosition": "right", "times": [], "addTimeMarker": False,
        "labels": {"show": horizontal},
        "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
    }


METRIC_PARAMS = {
    "addTooltip": True, "addLegend": False, "type": "metric",
    "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red", "metricColorMode": "None",
               "colorsRange": [{"from": 0, "to": 10000}], "labels": {"show": True}, "invertColors": False,
               "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 40}},
}
PIE_PARAMS = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True,
              "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}
TABLE_PARAMS = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
                "totalFunc": "sum", "percentageCol": ""}


def visualization(key, title, vis_type, params, aggs, source, kql=None, name=None):
    """name: what the id derives from, the title unless another panel of the dashboard has it."""
    for i, agg in enumerate(aggs, start=1):
        agg.setdefault("enabled", True)
        agg["id"] = str(i)
    return {
        "id": uid("visualization", key, name or title),
        "type": "visualization",
        "migrationVersion": {"visualization": "7.10.0"},
        "references": [{"id": INDEX_PATTERNS[source]["id"], "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}],
        "attributes": {
            "title": title,
            "description": "",
            "version": 1,
            "uiStateJSON": "{}",
            "visState": json.dumps({"title": title, "type": vis_type, "params": params, "aggs": aggs}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                "query": {"query": kql or "", "language": "kuery"}, "filter": [],
                "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
        },
    }


# ---- Panel builders: (title, vis_type, params, aggs, source, kql, width) ----

def metric(title, source, agg, kql=None):
    return (title, "metric", METRIC_PARAMS, [agg], source, kql, None)


def over_time(title, source, field, label, kql=None, w=None):
    return (title, "histogram", axes_params("histogram", True), [count(), histogram(), terms(field, label, 10, "group")], source, kql, w)


def series_over_time(title, source, series):
    return (title, "histogram", axes_params("histogram", True), [count(), histogram(), filters(series)], source, None, None)


def donut(title, source, field, label, kql=None):
    return (title, "pie", PIE_PARAMS, [count(), terms(field, label, 10, "segment")], source, kql, None)


def top_bars(title, source, field, label, size=10, kql=None):
    return (title, "horizontal_bar", axes_params("horizontal_bar", False), [count(), terms(field, label, size, "segment")], source, kql, None)


def table(title, source, rows, metrics, size=20, kql=None):
    aggs = list(metrics) + [terms(field, label, size if i == 0 else 5, "bucket") for i, (field, label) in enumerate(rows)]
    return (title, "table", TABLE_PARAMS, aggs, source, kql, None)


class Dashboard:
    def __init__(self, key, title, description):
        self.key, self.id, self.title, self.description = key, uid("dashboard", key), title, description
        self.panels, self.references, self.visualizations, self.searches, self.y = [], [], [], [], 0
        self.names = set()

    def _name(self, title, kind):
        """What the ids of a panel derive from: its title, or its title and kind if another panel has the title."""
        name = title if title not in self.names else f"{title}/{kind}"
        self.names.add(name)
        return name

    def row(self, h, *panels):
        widths = [p[6] for p in panels]
        free = [w for w in widths if w is None]
        rest = 48 - sum(w for w in widths if w)
        x = 0
        for title, vis_type, params, aggs, source, kql, width in panels:
            w = width or rest // len(free)
            name = self._name(title, vis_type)
            vis = visualization(self.key, title, vis_type, json.loads(json.dumps(params)), json.loads(json.dumps(aggs)), source, kql, name)
            self.visualizations.append(vis)
            ref = f"panel_{len(self.panels)}"
            pid = uid(self.id, name)
            self.panels.append({"version": PANEL_VERSION, "gridData": {"x": x, "y": self.y, "w": w, "h": h, "i": pid},
                                "panelIndex": pid, "embeddableConfig": {}, "panelRefName": ref})
            self.references.append({"id": vis["id"], "name": ref, "type": "visualization"})
            x += w
        self.y += h

    def search(self, h, title, source, columns, kql=None):
        """A full-width saved search: the latest documents, newest first, with the given columns."""
        name = self._name(title, "search")
        sid = uid("search", self.key, name)
        self.searches.append({
            "id": sid, "type": "search", "migrationVersion": {"search": "7.9.3"},
            "references": [{"id": INDEX_PATTERNS[source]["id"], "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}],
            "attributes": {
                "title": title, "description": "", "columns": columns, "sort": [["@timestamp", "desc"]], "hits": 0, "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
                    "query": {"query": kql or "", "language": "kuery"}, "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})},
            },
        })
        ref = f"panel_{len(self.panels)}"
        pid = uid(self.id, name)
        self.panels.append({"version": PANEL_VERSION, "gridData": {"x": 0, "y": self.y, "w": 48, "h": h, "i": pid},
                            "panelIndex": pid, "embeddableConfig": {}, "panelRefName": ref})
        self.references.append({"id": sid, "name": ref, "type": "search"})
        self.y += h

    def saved_objects(self):
        return self.visualizations + self.searches + [{
            "id": self.id,
            "type": "dashboard",
            "migrationVersion": {"dashboard": "7.9.3"},
            "references": self.references,
            "attributes": {
                "title": self.title,
                "description": self.description,
                "panelsJSON": json.dumps(self.panels),
                "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                "version": 1,
                "timeRestore": True,
                "timeFrom": "now-24h",
                "timeTo": "now",
                "refreshInterval": {"pause": True, "value": 0},
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
            },
        }]


F, E = "findings", "events"
HIGH = 'wazuh.rule.level : ("critical" or "high")'

# Findings overview: replaces wazuh-security-events, wazuh-incident-response and wazuh-malware-detection.
findings = Dashboard("findings-overview", "Wazuh - Findings overview", "Detection findings exported from the Wazuh indexer.")
findings.row(7, metric("Findings", F, count("Findings")), metric("Critical and high", F, count("Critical and high"), HIGH),
             metric("Agents with findings", F, unique("wazuh.agent.name", "Agents")), metric("Rules triggered", F, unique("wazuh.rule.id", "Rules")))
findings.row(15, over_time("Findings over time by level", F, "wazuh.rule.level", "Level", w=32), donut("Findings by level", F, "wazuh.rule.level", "Level"))
findings.row(15, top_bars("Findings by category", F, "wazuh.integration.category", "Category"), top_bars("Top agents", F, "wazuh.agent.name", "Agent"))
findings.row(16, table("Top rules", F, [("wazuh.rule.title", "Rule"), ("wazuh.rule.level", "Level")],
                       [count("Findings"), unique("wazuh.agent.name", "Agents")]))
findings.row(16, table("Findings by agent and rule", F, [("wazuh.agent.name", "Agent"), ("wazuh.rule.title", "Rule"), ("wazuh.integration.name", "Integration")],
                       [count("Findings")]))
findings.search(18, "Latest findings", F, ["wazuh.agent.name", "wazuh.rule.level", "wazuh.rule.title", "wazuh.integration.name", "source.ip", "user.name"])

# MITRE ATT&CK: new.
mitre = Dashboard("mitre-attack", "Wazuh - MITRE ATT&CK", "MITRE ATT&CK tactics and techniques of the rules that produced the findings.")
mitre.row(7, metric("Findings with MITRE ATT&CK", F, count("Findings"), "wazuh.rule.mitre.technique.id : *"),
          metric("Tactics", F, unique("wazuh.rule.mitre.tactic.id", "Tactics")), metric("Techniques", F, unique("wazuh.rule.mitre.technique.id", "Techniques")),
          metric("Sub-techniques", F, unique("wazuh.rule.mitre.subtechnique.id", "Sub-techniques")))
mitre.row(15, over_time("Tactics over time", F, "wazuh.rule.mitre.tactic.name", "Tactic", w=32), donut("Findings by tactic", F, "wazuh.rule.mitre.tactic.name", "Tactic"))
mitre.row(15, top_bars("Top techniques", F, "wazuh.rule.mitre.technique.name", "Technique"),
          top_bars("Top sub-techniques", F, "wazuh.rule.mitre.subtechnique.name", "Sub-technique"))
mitre.row(16, table("Techniques", F, [("wazuh.rule.mitre.technique.id", "Technique ID"), ("wazuh.rule.mitre.technique.name", "Technique")],
                    [count("Findings"), unique("wazuh.agent.name", "Agents"), unique("wazuh.rule.id", "Rules")]))

# Compliance: replaces wazuh-pci-dss.
# Every framework of wazuh.rule.compliance in WCS.
FRAMEWORKS = [("pci_dss", "PCI DSS"), ("nist_800_53", "NIST 800-53"), ("nist_800_171", "NIST 800-171"), ("gdpr", "GDPR"), ("hipaa", "HIPAA"),
              ("iso_27001", "ISO 27001"), ("nis2", "NIS2"), ("tsc", "TSC"), ("cmmc", "CMMC"), ("fedramp", "FedRAMP")]
compliance = Dashboard("compliance", "Wazuh - Compliance", "Regulatory requirements of the rules that produced the findings.")
for half in (FRAMEWORKS[:5], FRAMEWORKS[5:]):
    compliance.row(7, *[metric(f"{name} findings", F, count("Findings"), f"wazuh.rule.compliance.{key} : *") for key, name in half])
compliance.row(15, series_over_time("Findings by framework over time", F, [(name, f"wazuh.rule.compliance.{key} : *") for key, name in FRAMEWORKS]))
for pair in zip(FRAMEWORKS[::2], FRAMEWORKS[1::2]):
    compliance.row(15, *[top_bars(f"{name} requirements", F, f"wazuh.rule.compliance.{key}", "Requirement") for key, name in pair])
compliance.row(16, table("PCI DSS requirements by rule", F, [("wazuh.rule.compliance.pci_dss", "PCI DSS"), ("wazuh.rule.title", "Rule")],
                         [count("Findings"), unique("wazuh.agent.name", "Agents")], kql="wazuh.rule.compliance.pci_dss : *"))

# Events overview: replaces wazuh-amazon-aws (cloud panels).
events = Dashboard("events-overview", "Wazuh - Events overview", "Normalized events exported from the Wazuh indexer.")
events.row(7, metric("Events", E, count("Events")), metric("Agents", E, unique("wazuh.agent.name", "Agents")),
           metric("Integrations", E, unique("wazuh.integration.name", "Integrations")), metric("Failed outcomes", E, count("Events"), 'event.outcome : "failure"'))
events.row(15, over_time("Events over time by category", E, "wazuh.integration.category", "Category", w=32), donut("Events by outcome", E, "event.outcome", "Outcome"))
events.row(15, top_bars("Top integrations", E, "wazuh.integration.name", "Integration"), top_bars("Top agents", E, "wazuh.agent.name", "Agent"))
events.row(16, table("Authentication failures by source", E, [("source.ip", "Source IP"), ("user.name", "User")],
                     [count("Events"), unique("wazuh.agent.name", "Agents")], kql='event.category : "authentication" and event.outcome : "failure"'),
           table("Cloud activity", E, [("cloud.provider", "Provider"), ("cloud.account.id", "Account"), ("event.action", "Action")],
                 [count("Events")], kql='wazuh.integration.category : "cloud-services"'))

objects = [{"id": p["id"], "type": "index-pattern", "migrationVersion": {"index-pattern": "7.6.0"}, "references": [],
            "attributes": {"title": p["title"], "timeFieldName": "@timestamp"}} for p in INDEX_PATTERNS.values()]
for d in (findings, mitre, compliance, events):
    objects.extend(d.saved_objects())

DASHBOARD_IDS = {d.title: d.id for d in (findings, mitre, compliance, events)}


def build() -> dict:
    """{file name: content}: one ndjson file with the index patterns, visualizations and dashboards."""
    return {"dashboards.ndjson": "".join(json.dumps(o) + "\n" for o in objects)}
