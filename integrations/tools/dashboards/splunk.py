"""Splunk Dashboard Studio definitions of the Wazuh dashboards, as the views of the Splunk app."""
import csv
import json
import os
import re
from xml.sax.saxutils import escape

import wazuh_dashboard

F = "`wazuh_findings`"
E = "`wazuh_events`"


class Dashboard:
    def __init__(self, title, description):
        self.title, self.description = title, description
        self.viz, self.ds, self.layout, self.inputs = {}, {}, [], {}
        self.y = 0

    def panel(self, kind, title, query, w, h, x, options=None, y=None):
        n = len(self.viz) + 1
        ds_id, viz_id = f"ds_{n:02d}", f"viz_{n:02d}"
        self.ds[ds_id] = {"type": "ds.search", "name": title or viz_id, "options": {"query": query}}
        self.viz[viz_id] = {"type": kind, "title": title, "dataSources": {"primary": ds_id}, "options": options or {}}
        self.layout.append({"item": viz_id, "type": "block", "position": {"x": x, "y": self.y if y is None else y, "w": w, "h": h}})

    def row(self, h, *panels):
        """Panels side by side, splitting the 1200 px width evenly unless a width is given."""
        widths = [p.get("w") for p in panels]
        free = [i for i, w in enumerate(widths) if w is None]
        rest = 1200 - sum(w for w in widths if w)
        x = 0
        for i, p in enumerate(panels):
            w = widths[i] if widths[i] else rest // len(free)
            self.panel(p["kind"], p["title"], p["query"], w, h, x, p.get("options"))
            x += w
        self.y += h

    def dropdown(self, token, title, query):
        """A dropdown of the values of a search (label and value fields), to scope the dashboard."""
        n = len(self.inputs) + 1
        ds_id = f"ds_input_{n:02d}"
        self.ds[ds_id] = {"type": "ds.search", "name": title, "options": {"query": query}}
        self.inputs[f"input_{token}"] = {
            "type": "input.dropdown", "title": title, "dataSources": {"primary": ds_id},
            "options": {"items": ">frame(label, value) | prepend(formattedStatics) | objects()", "token": token, "defaultValue": "*"},
            "context": {"formattedConfig": {"number": {"prefix": ""}}, "formattedStatics": ">statics | formatByType(formattedConfig)",
                        "statics": [["All"], ["*"]],
                        "label": '>primary | seriesByName("label") | renameSeries("label") | formatByType(formattedConfig)',
                        "value": '>primary | seriesByName("value") | renameSeries("value") | formatByType(formattedConfig)'},
        }

    def render(self):
        inputs = {"input_global_trp": {"type": "input.timerange", "title": "Time range",
                                       "options": {"token": "global_time", "defaultValue": "-24h@h,now"}}}
        inputs.update(self.inputs)
        layout = {"type": "grid", "options": {}, "globalInputs": list(inputs), "structure": self.layout}
        if self.absolute:
            height = max((b["position"]["y"] + b["position"]["h"] for b in self.layout), default=0)
            layout.update({"type": "absolute", "options": {"width": 1200, "height": height + 20, "display": "auto-scale"}})
        return {
            "title": self.title,
            "description": self.description,
            "inputs": inputs,
            "defaults": {
                "dataSources": {
                    "ds.search": {
                        "options": {"queryParameters": {"earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}}
                    }
                }
            },
            "dataSources": self.ds,
            "visualizations": self.viz,
            "layout": layout,
        }

    absolute = False


def single(title, query):
    return {"kind": "splunk.singlevalue", "title": title, "query": query}


def chart(kind, title, query, **options):
    return {"kind": kind, "title": title, "query": query, "options": options}


def table(title, query):
    return {"kind": "splunk.table", "title": title, "query": query}


# ---- The dashboards of the Wazuh dashboard ----
#
# The visualizations of the Wazuh dashboard are aggregations of OpenSearch Dashboards: they are
# translated to searches and visualizations of Dashboard Studio, in the same place of the same
# layout. Splunk names the fields of the JSON documents by their path, with {} after every array
# (wazuh.rule.compliance.pci_dss{}, wazuh.threat.enrichments{}.indicator.name): the arrays are
# those of the WCS findings fields.

WCS_FINDINGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                            "wcs", "stateless", "events", "findings", "docs", "fields.csv")


def wcs_arrays() -> set:
    with open(WCS_FINDINGS, newline="") as fd:
        return {row["Field"] for row in csv.DictReader(fd) if "array" in row["Normalization"]}


ARRAYS = wcs_arrays()

# Splunk has no field for an object: the existence of an object is that of one of its fields,
# one every instance of the object has.
OBJECT_FIELDS = {"wazuh.threat.enrichments": "wazuh.threat.enrichments.matched.field"}


def splunk_field(field: str) -> str:
    parts = field.split(".")
    return ".".join(part + ("{}" if ".".join(parts[:i + 1]) in ARRAYS else "") for i, part in enumerate(parts))


def condition(spec) -> str:
    """Search condition of a filter of wazuh_dashboard."""
    if spec["type"] == "exists":
        return f'"{splunk_field(OBJECT_FIELDS.get(spec["field"], spec["field"]))}"=*'
    return f'"{splunk_field(spec["field"])}"="{spec["value"]}"'


def kql(query: str) -> str:
    """Search condition of the KQL queries of the visualizations: field:"value"."""
    match = re.fullmatch(r'\s*([\w.@]+)\s*:\s*"([^"]*)"\s*', query)
    if not match:
        raise SystemExit(f"KQL query not translated to SPL: {query}")
    return f'"{splunk_field(match[1])}"="{match[2]}"'


INTERVALS = {"d": "1d", "h": "1h", "m": "1m", "w": "1w", "M": "1mon", "y": "1y"}


def span(params: dict) -> str:
    interval = params.get("interval") or "auto"
    if interval == "auto":
        return ""
    return f" span={INTERVALS.get(interval, interval)}"


class Search:
    """The SPL of the aggregations of a visualization: the fields it reads are first copied to
    fields of simple names (f1, f2...), which keep their multiple values, so that the stats
    commands split them as the terms aggregations do."""

    def __init__(self, base: str):
        self.base, self.fields = base, {}

    def field(self, name: str) -> str:
        return self.fields.setdefault(name, f"f{len(self.fields) + 1}")

    def metric(self, agg: dict) -> str:
        if agg["type"] == "count":
            return "count"
        field = self.field(agg["params"]["field"])
        if agg["type"] == "cardinality":
            return f"dc({field})"
        if agg["type"] == "top_hits":
            return f"{'max' if agg['params'].get('sortOrder') == 'desc' else 'min'}({field})"
        raise SystemExit(f"metric not translated to SPL: {agg['type']}")

    def query(self, tail: str) -> str:
        evals = ", ".join(f"{alias}='{splunk_field(name)}'" for name, alias in self.fields.items())
        return f"{self.base}{' | eval ' + evals if evals else ''} | {tail}"


def label(agg: dict) -> str:
    custom = agg.get("params", {}).get("customLabel")
    if custom:
        return custom
    if agg["type"] == "count":
        return "Count"
    if agg["type"] == "cardinality":
        return f"Unique count of {agg['params']['field']}"
    if agg["type"] == "date_histogram":
        return "_time"
    return agg["params"].get("field", agg["type"])


def quoted(name: str) -> str:
    return '"' + name.replace('"', "'") + '"'


CHARTS = {"histogram": "splunk.column", "horizontal_bar": "splunk.bar", "line": "splunk.line", "area": "splunk.area"}


def translate(state: dict, base: str) -> list:
    """[(Dashboard Studio visualization type, title, query, options)] of a visualization: one, but
    for the metrics, one per value."""
    aggs = [a for a in state.get("aggs", []) if a.get("enabled", True)]
    metrics = [a for a in aggs if a["schema"] == "metric"]
    buckets = [a for a in aggs if a["schema"] != "metric" and a["schema"] != "radius"]
    s = Search(base)
    kind, title = state["type"], state.get("title", "")
    m = metrics[0]
    mexpr, mlabel = s.metric(m), label(m)

    if kind == "metric":
        if buckets and buckets[0]["type"] == "filters":
            return [("splunk.singlevalue", f["label"] or f["input"]["query"],
                     f"{base} {kql(f['input']['query'])} | stats {mexpr} as value", {"underLabel": f"{f['label']} - {mlabel}"})
                    for f in buckets[0]["params"]["filters"]]
        return [("splunk.singlevalue", label(a), s.query(f"stats {s.metric(a)} as value"), {"underLabel": label(a)}) for a in metrics]

    dates = [b for b in buckets if b["type"] == "date_histogram"]
    terms = [b for b in buckets if b["type"] == "terms"]
    if any(b["type"] not in ("date_histogram", "terms") for b in buckets):
        raise SystemExit(f"bucket not translated to SPL: {[b['type'] for b in buckets]}")

    def by(b):
        return s.field(b["params"]["field"])

    def size(b):
        return int(b["params"].get("size", 10))

    def order(b):
        return "" if b["params"].get("order") == "asc" else "- "

    renames = []

    def rename(alias, name):
        renames.append(f"{alias} as {quoted(name)}")

    if kind == "table":
        fields = []
        tail = ""
        for b in buckets:
            if b["type"] == "date_histogram":
                tail += f"bin _time{span(b['params']) or ' bins=24'} | "
                fields.append("_time")
            else:
                fields.append(by(b))
                rename(by(b), label(b))
        limit = 1
        for b in terms:
            limit *= size(b)
        tail += f"stats {mexpr} as metric by {', '.join(fields)} | sort {order(terms[0]) if terms else '- '}metric | head {min(limit, 500)}"
        rename("metric", mlabel)
        return [("splunk.table", title, s.query(tail + " | rename " + ", ".join(renames)), {})]

    if dates:
        group = terms[0] if terms else None
        tail = f"timechart{span(dates[0]['params'])} {mexpr} as {quoted(mlabel)}"
        if group:
            tail = f"timechart{span(dates[0]['params'])} useother=f usenull=f limit={size(group)} {mexpr} by {by(group)}"
        options = {}
        if kind in ("histogram", "area", "horizontal_bar") and any(p.get("mode") == "stacked" for p in state["params"].get("seriesParams", [])):
            options["stackMode"] = "stacked"
        return [(CHARTS.get(kind, "splunk.column"), title, s.query(tail), options)]

    if kind == "heatmap":
        x, y = terms[0], terms[1]
        tail = f"stats {mexpr} as metric by {by(x)}, {by(y)} | sort - metric | head {size(x) * size(y)}"
        rename(by(x), label(x)), rename(by(y), label(y)), rename("metric", mlabel)
        return [("splunk.punchcard", title, s.query(tail + " | rename " + ", ".join(renames)), {})]

    segments = [b for b in terms if b["schema"] in ("segment", "bucket")]
    groups = [b for b in terms if b["schema"] == "group"]
    if kind in CHARTS and segments and groups and segments[0]["params"]["field"] != groups[0]["params"]["field"]:
        x, g = segments[0], groups[0]
        tail = (f"chart {mexpr} over {by(x)} by {by(g)} useother=f usenull=f limit={size(g)} | addtotals fieldname=total "
                f"| sort - total | head {size(x)} | fields - total | rename {by(x)} as {quoted(label(x))}")
        options = {}
        if any(p.get("mode") == "stacked" for p in state["params"].get("seriesParams", [])):
            options["stackMode"] = "stacked"
        return [(CHARTS[kind], title, s.query(tail), options)]

    # One or more terms: the values of the first ones joined, as the rings of a pie. A field split
    # by itself is one series.
    levels = [b for i, b in enumerate(terms) if b["params"]["field"] not in [t["params"]["field"] for t in terms[:i]]]
    names = [by(b) for b in levels]
    limit = 1
    for b in levels:
        limit *= size(b)
    tail = f"stats {mexpr} as metric by {', '.join(names)} | sort {order(levels[0])}metric | head {min(limit, 50)}"
    if len(names) > 1:
        joined = ' . " / " . '.join(names)
        tail += f" | eval value={joined} | table value metric"
        rename("value", " / ".join(label(b) for b in levels))
    else:
        rename(names[0], label(levels[0]))
    rename("metric", mlabel)
    tail += " | rename " + ", ".join(renames)
    if kind == "pie":
        return [("splunk.pie", title, s.query(tail), {"showDonutHole": bool(state["params"].get("isDonut", True))})]
    return [(CHARTS.get(kind, "splunk.bar"), title, s.query(tail), {})]


# Grid of OpenSearch Dashboards: 48 columns, rows of 20 px. Dashboard Studio: 1200 px wide.
COLUMN, ROW, GAP = 25, 20, 4


def converted(path: str, o: dict, spec, scope, sources: dict) -> Dashboard:
    title = o["attributes"]["title"]
    scope_text = ""
    if scope:
        scope_text = f" Pick the {scope[1].lower()} in the {scope[1]} input, as the Wazuh dashboard does."
    d = Dashboard(f"Wazuh - {title}", f"{title} of the Wazuh dashboard, on the findings exported from the Wazuh indexer.{scope_text}")
    d.absolute = True
    base = F + (f" {condition(spec)}" if spec else "")
    if scope:
        field, name = splunk_field(scope[0]), scope[1]
        d.dropdown("scope", name, f'{base} "{field}"=* | eval value=\'{field}\' | stats count by value '
                                  f"| sort - count | head 500 | eval label=value | fields label, value")
        base += f' "{field}"=$scope|s$'
    refs = {r["name"]: r["id"] for r in o["references"]}
    options = json.loads(o["attributes"].get("optionsJSON") or "{}")
    for panel in sorted(json.loads(o["attributes"]["panelsJSON"]), key=lambda p: (p["gridData"]["y"], p["gridData"]["x"])):
        vis = sources[refs[panel["panelRefName"]]]
        state = json.loads(vis["attributes"]["visState"])
        hidden = (options.get("hidePanelTitles") or panel.get("embeddableConfig", {}).get("hidePanelTitles")
                  or not vis["attributes"].get("title"))
        grid = panel["gridData"]
        parts = translate(state, base)
        width = grid["w"] * COLUMN / len(parts)
        for i, (kind, part_title, query, viz_options) in enumerate(parts):
            # The title of the panel, over its first part; the metrics show their label under the value.
            part_title = "" if hidden or i else vis["attributes"]["title"]
            d.panel(kind, part_title, query, round(width) - GAP, grid["h"] * ROW - GAP, round(grid["x"] * COLUMN + i * width),
                    viz_options, y=grid["y"] * ROW)
    return d


def view_name(dashboard_id: str) -> str:
    return "wazuh_" + re.sub(r"\W", "_", dashboard_id)


def module(path: str) -> str:
    """The module of the Wazuh dashboard of a definition: overview/<module>/..."""
    return path.split("/")[1]


boards, sources = wazuh_dashboard.resolved()
WAZUH = [(view_name(o["id"]), module(path), converted(path, o, spec, scope, sources)) for path, o, spec, scope in boards]

# The events: the Wazuh dashboard has no dashboard of events, so the integration has its own.
d = Dashboard("Wazuh - Events overview", "Normalized events exported from the Wazuh indexer.")
d.row(110,
      single("Events", f"{E} | stats count"),
      single("Agents", f"{E} | stats dc(wazuh.agent.name)"),
      single("Integrations", f"{E} | stats dc(wazuh.integration.name)"),
      single("Failed outcomes", f'{E} event.outcome="failure" | stats count'))
d.row(320,
      chart("splunk.column", "Events over time by category", f"{E} | timechart usenull=f useother=f count by wazuh.integration.category", stackMode="stacked", w=800),
      chart("splunk.pie", "Events by outcome", f'{E} | eval outcome=coalesce(\'event.outcome\', "unknown") | stats count by outcome'))
d.row(320,
      chart("splunk.bar", "Top integrations", f"{E} | stats count by wazuh.integration.name | sort - count | head 10"),
      chart("splunk.bar", "Top agents", f"{E} | stats count by wazuh.agent.name | sort - count | head 10"))
d.row(320,
      table("Authentication failures by source", f'{E} "event.category{{}}"="authentication" event.outcome="failure" | stats count, values(user.name) as users, dc(wazuh.agent.name) as agents by source.ip | sort - count | head 20'),
      table("Cloud activity", f'{E} wazuh.integration.category="cloud-services" | stats count by cloud.provider, cloud.account.id, event.action, event.outcome | sort - count'))
events = d

VIEWS = [(name, dash) for name, _, dash in WAZUH] + [("wazuh_events_overview", events)]


def view(dash: Dashboard) -> str:
    """Simple XML view holding a Dashboard Studio definition."""
    definition = json.dumps(dash.render(), indent=2)
    return (f'<dashboard version="2" theme="dark">\n  <label>{escape(dash.title)}</label>\n'
            f'  <description>{escape(dash.description)}</description>\n'
            f"  <definition><![CDATA[\n{definition}\n]]></definition>\n</dashboard>\n")


def navigation() -> str:
    """Navigation menu of the app: the dashboards of every module of the Wazuh dashboard, the
    events overview, then search."""
    menus = {}
    for name, key, dash in WAZUH:
        menus.setdefault(dash.title.split(" - ")[1], []).append(name)
    items = "\n".join(f'    <collection label="{escape(label)}">\n' + "\n".join(f'      <view name="{n}" />' for n in names)
                      + "\n    </collection>" for label, names in menus.items())
    return (f'<nav search_view="search">\n  <collection label="Dashboards">\n{items}\n    <view name="wazuh_events_overview" />\n'
            f'  </collection>\n  <view name="search" />\n  <view name="dashboards" />\n</nav>\n')


def build() -> dict:
    """{path under the app's default/data/ui: content} of the views and the navigation menu."""
    files = {f"views/{name}.xml": view(dash) for name, dash in VIEWS}
    files["nav/default.xml"] = navigation()
    return files
