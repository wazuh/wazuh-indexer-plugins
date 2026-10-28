"""OpenSearch Dashboards saved objects (index patterns, visualizations and dashboards) of the Wazuh dashboards.

The visualizations are the aggregation-based ones, written in the 7.10 saved object format,
which OpenSearch Dashboards migrates on import.
"""
import json
import os
import uuid

import wazuh_dashboard

NS = uuid.UUID("0b8e5f2a-6c4d-4a1e-9f3b-7d2c5e8a1f60")
PANEL_VERSION = "3.9.0"


def uid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


INDEX_PATTERNS = {
    "findings": {"id": "wazuh-findings", "title": "logs-wazuh.findings.*-*"},
    "events": {"id": "wazuh-events", "title": "logs-wazuh.events.*-*"},
}

# ---- Fields of the index patterns ----
#
# OpenSearch Dashboards keeps the fields of an index pattern in the saved object, and only reads
# them from the cluster when asked to refresh them. Imported without fields, before any data
# arrives, every visualization fails ("Could not locate that index-pattern-field"). The index
# patterns carry the fields of the WCS instead: those of the index templates the setup plugin
# installs for the source data streams, which the exported documents follow.

STREAM_TEMPLATES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                                "plugins", "setup", "src", "main", "resources", "templates", "streams")

# OpenSearch Dashboards type of every mapping type of the WCS.
FIELD_TYPES = {
    "keyword": "string", "match_only_text": "string", "flat_object": "string",
    "long": "number", "integer": "number", "short": "number", "byte": "number",
    "double": "number", "float": "number", "scaled_float": "number",
    "date": "date", "ip": "ip", "boolean": "boolean", "geo_point": "geo_point",
}
# Mapping types without doc values: searchable, not aggregatable.
NOT_AGGREGATABLE = {"match_only_text", "flat_object"}
META_FIELDS = [
    {"name": "_id", "type": "string", "esTypes": ["_id"], "searchable": True, "aggregatable": True, "readFromDocValues": False},
    {"name": "_index", "type": "string", "esTypes": ["_index"], "searchable": True, "aggregatable": True, "readFromDocValues": False},
    {"name": "_score", "type": "number", "searchable": False, "aggregatable": False, "readFromDocValues": False},
    {"name": "_source", "type": "_source", "esTypes": ["_source"], "searchable": False, "aggregatable": False, "readFromDocValues": False},
    {"name": "_type", "type": "string", "searchable": False, "aggregatable": False, "readFromDocValues": False},
]


def wcs_mappings(kind: str) -> dict:
    """{field: mapping type} of the WCS fields of the events or findings data streams."""
    with open(os.path.join(STREAM_TEMPLATES, f"{kind}.json")) as fd:
        mappings = json.load(fd)["template"]["mappings"]
    fields = {}

    def leaves(properties, prefix=""):
        for name, mapping in properties.items():
            if "type" in mapping:
                fields[prefix + name] = mapping["type"]
            leaves(mapping.get("properties", {}), f"{prefix}{name}.")

    leaves(mappings["properties"])
    for rule in mappings["dynamic_templates"]:
        body = next(iter(rule.values()))
        fields[body["path_match"]] = body["mapping"]["type"]
    # The integration names the destination data stream of every document in data_stream.*.
    fields.update({f"data_stream.{name}": "keyword" for name in ("type", "dataset", "namespace")})
    return fields


def index_pattern_fields(kind: str) -> list:
    """The fields of the index pattern of a kind of data, as OpenSearch Dashboards stores them."""
    fields = []
    for name, es_type in sorted(wcs_mappings(kind).items()):
        if es_type not in FIELD_TYPES:
            continue  # objects
        aggregatable = es_type not in NOT_AGGREGATABLE
        fields.append({"name": name, "type": FIELD_TYPES[es_type], "esTypes": [es_type], "searchable": True,
                       "aggregatable": aggregatable, "readFromDocValues": aggregatable})
    return META_FIELDS + fields

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

# The findings: the dashboards of the Wazuh dashboard, converted (see wazuh_dashboard.py).
# The events: the Wazuh dashboard has no dashboard of events, so the integration has its own.

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
            "attributes": {"title": p["title"], "timeFieldName": "@timestamp", "fields": json.dumps(index_pattern_fields(kind))}}
           for kind, p in INDEX_PATTERNS.items()]
objects.extend(wazuh_dashboard.dashboards(INDEX_PATTERNS["findings"]["id"]))
objects.extend(events.saved_objects())


def check_fields(objects: list) -> None:
    """Every field a visualization aggregates on is an aggregatable field of its index pattern."""
    patterns = {o["id"]: {f["name"]: f for f in json.loads(o["attributes"]["fields"])}
                for o in objects if o["type"] == "index-pattern"}
    for o in objects:
        if o["type"] != "visualization":
            continue
        pattern = next(r["id"] for r in o["references"] if r["type"] == "index-pattern")
        fields = patterns[pattern]
        state = json.loads(o["attributes"]["visState"])
        names = [agg.get("params", {}).get("field") for agg in state.get("aggs", [])]
        names += [c["fieldName"] for c in state.get("params", {}).get("controls", [])]
        for name in names:
            if name and not fields.get(name, {}).get("aggregatable"):
                raise SystemExit(f"{o['id']} ({o['attributes']['title']}): {name} is not an aggregatable field of {pattern}")


def build() -> dict:
    """{file name: content}: one ndjson file with the index patterns, visualizations and dashboards."""
    check_fields(objects)
    return {"dashboards.ndjson": "".join(json.dumps(o) + "\n" for o in objects)}
