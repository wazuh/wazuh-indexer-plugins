"""Kibana saved objects (data views and dashboards) of the Wazuh dashboards.

The Lens panels of the events overview are written in the 8.6 saved object format, which Kibana migrates on import.
"""
import json
import uuid

import wazuh_dashboard

NS = uuid.UUID("6f2a4c3e-9b1d-4e57-8c2a-0d5e7f9a1b3c")
VERSION = "8.6.2"


def uid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


DATA_VIEWS = {
    "findings": {"id": "wazuh-findings", "title": "logs-wazuh.findings.*-*", "name": "Wazuh findings"},
    "events": {"id": "wazuh-events", "title": "logs-wazuh.events.*-*", "name": "Wazuh events"},
}


def count(label="Count", kql=None):
    col = {"label": label, "customLabel": True, "dataType": "number", "operationType": "count", "isBucketed": False,
           "scale": "ratio", "sourceField": "___records___", "params": {"emptyAsNull": True}}
    if kql:
        col["filter"] = {"query": kql, "language": "kuery"}
    return col


def unique(field, label):
    return {"label": label, "customLabel": True, "dataType": "number", "operationType": "unique_count", "isBucketed": False,
            "scale": "ratio", "sourceField": field, "params": {"emptyAsNull": True}}


def histogram():
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram", "sourceField": "@timestamp",
            "isBucketed": True, "scale": "interval", "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False}}


def terms(field, label, size, order_by):
    return {"label": label, "customLabel": True, "dataType": "string", "operationType": "terms", "scale": "ordinal",
            "sourceField": field, "isBucketed": True,
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_by}, "orderDirection": "desc",
                       "otherBucket": False, "missingBucket": False, "parentFormat": {"id": "terms"},
                       "include": [], "exclude": [], "includeIsRegex": False, "excludeIsRegex": False}}


class Dashboard:
    def __init__(self, key, title, description):
        self.id, self.title, self.description = uid("dashboard", key), title, description
        self.panels, self.references, self.y = [], [], 0
        self.names = set()

    def _name(self, title, kind):
        """What the ids of a panel derive from: its title, or its title and kind if another panel has the title."""
        name = title if title not in self.names else f"{title}/{kind}"
        self.names.add(name)
        return name

    def _panel(self, title, source, vis_type, visualization, columns, order, kql, x, w, h):
        pid = uid(self.id, self._name(title, vis_type))
        layer = uid(pid, "layer")
        # Column ids are local to the panel: make them unique per panel.
        ids = {c: uid(pid, c) for c in columns}
        cols = {}
        for c, col in columns.items():
            col = json.loads(json.dumps(col))
            if col.get("params", {}).get("orderBy", {}).get("columnId"):
                col["params"]["orderBy"]["columnId"] = ids[col["params"]["orderBy"]["columnId"]]
            cols[ids[c]] = col
        vis = json.loads(json.dumps(visualization).replace("%LAYER%", layer))
        for c, i in ids.items():
            vis = json.loads(json.dumps(vis).replace(f"%{c}%", i))
        view = DATA_VIEWS[source]["id"]
        ref_name = f"indexpattern-datasource-layer-{layer}"
        self.references.append({"id": view, "name": f"{pid}:{ref_name}", "type": "index-pattern"})
        self.panels.append({
            "version": VERSION,
            "type": "lens",
            "gridData": {"x": x, "y": self.y, "w": w, "h": h, "i": pid},
            "panelIndex": pid,
            "title": title,
            "embeddableConfig": {
                "enhancements": {},
                # Metrics show their own label: a panel title would repeat it.
                "hidePanelTitles": vis_type == "lnsMetric",
                "attributes": {
                    "title": title,
                    "visualizationType": vis_type,
                    "type": "lens",
                    "references": [{"id": view, "name": ref_name, "type": "index-pattern"}],
                    "state": {
                        "visualization": vis,
                        "query": {"query": kql or "", "language": "kuery"},
                        "filters": [],
                        "datasourceStates": {"formBased": {"layers": {layer: {
                            "columns": cols, "columnOrder": [ids[c] for c in order], "incompleteColumns": {}, "sampling": 1}}}},
                        "internalReferences": [],
                        "adHocDataViews": {},
                    },
                },
            },
        })

    def row(self, h, *panels):
        widths = [p.get("w") for p in panels]
        free = [w for w in widths if w is None]
        rest = 48 - sum(w for w in widths if w)
        x = 0
        for p in panels:
            w = p.get("w") or rest // len(free)
            self._panel(p["title"], p["source"], p["type"], p["vis"], p["columns"], p["order"], p.get("kql"), x, w, h)
            x += w
        self.y += h

    def saved_object(self):
        return {
            "id": self.id,
            "type": "dashboard",
            "coreMigrationVersion": VERSION,
            "migrationVersion": {"dashboard": "8.6.0"},
            "references": self.references,
            "attributes": {
                "title": self.title,
                "description": self.description,
                "panelsJSON": json.dumps(self.panels),
                "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True, "syncTooltips": False, "hidePanelTitles": False}),
                "version": 1,
                "timeRestore": True,
                "timeFrom": "now-24h",
                "timeTo": "now",
                "refreshInterval": {"pause": True, "value": 60000},
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
            },
        }


# ---- Panel builders ----

def metric(title, source, column, kql=None):
    return {"title": title, "source": source, "type": "lnsMetric", "kql": kql,
            "vis": {"layerId": "%LAYER%", "layerType": "data", "metricAccessor": "%m%"},
            "columns": {"m": column}, "order": ["m"]}


def over_time(title, source, split_field, split_label, kql=None, w=None):
    return {"title": title, "source": source, "type": "lnsXY", "kql": kql, "w": w,
            "vis": {"legend": {"isVisible": True, "position": "right"}, "valueLabels": "hide", "fittingFunction": "None",
                    "preferredSeriesType": "bar_stacked",
                    "layers": [{"layerId": "%LAYER%", "accessors": ["%c%"], "position": "top", "seriesType": "bar_stacked",
                                "showGridlines": False, "layerType": "data", "xAccessor": "%x%", "splitAccessor": "%s%"}]},
            "columns": {"s": terms(split_field, split_label, 10, "c"), "x": histogram(), "c": count()},
            "order": ["s", "x", "c"]}


def donut(title, source, field, label, kql=None):
    return {"title": title, "source": source, "type": "lnsPie", "kql": kql,
            "vis": {"shape": "donut", "layers": [{"layerId": "%LAYER%", "primaryGroups": ["%g%"], "metrics": ["%c%"],
                                                   "numberDisplay": "percent", "categoryDisplay": "default", "legendDisplay": "default",
                                                   "nestedLegend": False, "layerType": "data"}]},
            "columns": {"g": terms(field, label, 10, "c"), "c": count()}, "order": ["g", "c"]}


def top_bars(title, source, field, label, size=10, kql=None):
    return {"title": title, "source": source, "type": "lnsXY", "kql": kql,
            "vis": {"legend": {"isVisible": False, "position": "right"}, "valueLabels": "show", "fittingFunction": "None",
                    "preferredSeriesType": "bar_horizontal",
                    "layers": [{"layerId": "%LAYER%", "accessors": ["%c%"], "position": "top", "seriesType": "bar_horizontal",
                                "showGridlines": False, "layerType": "data", "xAccessor": "%t%"}]},
            "columns": {"t": terms(field, label, size, "c"), "c": count()}, "order": ["t", "c"]}


def table(title, source, rows, metrics, size=20, kql=None):
    """rows: [(field, label)], metrics: [(key, column)]. Rows are ordered by the first metric."""
    columns, order = {}, []
    first = metrics[0][0]
    for i, (field, label) in enumerate(rows):
        columns[f"r{i}"] = terms(field, label, size if i == 0 else 5, first)
        order.append(f"r{i}")
    for key, column in metrics:
        columns[key] = column
        order.append(key)
    return {"title": title, "source": source, "type": "lnsDatatable", "kql": kql,
            "vis": {"layerId": "%LAYER%", "layerType": "data",
                    "columns": [{"columnId": f"%{c}%", "isTransposed": False} for c in order]},
            "columns": columns, "order": order}


F, E = "findings", "events"

# The findings: the dashboards of the Wazuh dashboard, converted (see wazuh_dashboard.py). Kibana
# still renders the aggregation-based visualizations of OpenSearch Dashboards, from which they
# come, and migrates them on import: only the parameters OpenSearch Dashboards renamed differ.
# The events: the Wazuh dashboard has no dashboard of events, so the integration has its own.
RENAMED = {"useNormalizedOpenSearchInterval": "useNormalizedEsInterval"}


def from_opensearch(o: dict) -> dict:
    content = json.dumps(o)
    for old, new in RENAMED.items():
        content = content.replace(old, new)
    return json.loads(content)


events = Dashboard("events-overview", "Wazuh - Events overview", "Normalized events exported from the Wazuh indexer.")
events.row(7, metric("Events", E, count("Events")), metric("Agents", E, unique("wazuh.agent.name", "Agents")),
           metric("Integrations", E, unique("wazuh.integration.name", "Integrations")), metric("Failed outcomes", E, count("Events", 'event.outcome : "failure"')))
events.row(15, over_time("Events over time by category", E, "wazuh.integration.category", "Category", w=32), donut("Events by outcome", E, "event.outcome", "Outcome"))
events.row(15, top_bars("Top integrations", E, "wazuh.integration.name", "Integration"), top_bars("Top agents", E, "wazuh.agent.name", "Agent"))
events.row(16, table("Authentication failures by source", E, [("source.ip", "Source IP"), ("user.name", "User")],
                     [("c", count("Events")), ("a", unique("wazuh.agent.name", "Agents"))], kql='event.category : "authentication" and event.outcome : "failure"'),
           table("Cloud activity", E, [("cloud.provider", "Provider"), ("cloud.account.id", "Account"), ("event.action", "Action")],
                 [("c", count("Events"))], kql='wazuh.integration.category : "cloud-services"'))

objects = []
for view in DATA_VIEWS.values():
    objects.append({
        "id": view["id"], "type": "index-pattern", "coreMigrationVersion": VERSION, "migrationVersion": {"index-pattern": "8.0.0"},
        "references": [],
        "attributes": {"title": view["title"], "name": view["name"], "timeFieldName": "@timestamp", "allowNoIndex": True,
                       "fieldAttrs": "{}", "fieldFormatMap": "{}", "fields": "[]", "runtimeFieldMap": "{}", "sourceFilters": "[]", "typeMeta": "{}"},
    })
objects.extend(from_opensearch(o) for o in wazuh_dashboard.dashboards(DATA_VIEWS["findings"]["id"]))
objects.append(events.saved_object())



def build() -> dict:
    """{file name: content}: one ndjson file with the data views and the dashboards."""
    return {"dashboards.ndjson": "".join(json.dumps(o) + "\n" for o in objects)}
