"""Splunk Dashboard Studio definitions of the Wazuh dashboards, as the views of the Splunk app."""
import json
from xml.sax.saxutils import escape

F = "`wazuh_findings`"
E = "`wazuh_events`"


class Dashboard:
    def __init__(self, title, description):
        self.title, self.description = title, description
        self.viz, self.ds, self.layout = {}, {}, []
        self.y = 0

    def panel(self, kind, title, query, w, h, x, options=None):
        n = len(self.viz) + 1
        ds_id, viz_id = f"ds_{n:02d}", f"viz_{n:02d}"
        self.ds[ds_id] = {"type": "ds.search", "name": title, "options": {"query": query}}
        self.viz[viz_id] = {"type": kind, "title": title, "dataSources": {"primary": ds_id}, "options": options or {}}
        self.layout.append({"item": viz_id, "type": "block", "position": {"x": x, "y": self.y, "w": w, "h": h}})

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

    def render(self):
        return {
            "title": self.title,
            "description": self.description,
            "inputs": {
                "input_global_trp": {
                    "type": "input.timerange",
                    "title": "Time range",
                    "options": {"token": "global_time", "defaultValue": "-24h@h,now"},
                }
            },
            "defaults": {
                "dataSources": {
                    "ds.search": {
                        "options": {"queryParameters": {"earliest": "$global_time.earliest$", "latest": "$global_time.latest$"}}
                    }
                }
            },
            "dataSources": self.ds,
            "visualizations": self.viz,
            "layout": {"type": "grid", "options": {}, "globalInputs": ["input_global_trp"], "structure": self.layout},
        }


def single(title, query):
    return {"kind": "splunk.singlevalue", "title": title, "query": query}


def chart(kind, title, query, **options):
    return {"kind": kind, "title": title, "query": query, "options": options}


def table(title, query):
    return {"kind": "splunk.table", "title": title, "query": query}


LEVELS = 'eval level_order=case(\'wazuh.rule.level\'="critical",1,\'wazuh.rule.level\'="high",2,\'wazuh.rule.level\'="medium",3,\'wazuh.rule.level\'="low",4,true(),5)'

# Findings overview: replaces wazuh-security-events, wazuh-incident-response and wazuh-malware-detection.
d = Dashboard("Wazuh - Findings overview", "Detection findings exported from the Wazuh indexer.")
d.row(110,
      single("Findings", f"{F} | stats count"),
      single("Critical and high", f'{F} (wazuh.rule.level="critical" OR wazuh.rule.level="high") | stats count'),
      single("Agents with findings", f"{F} | stats dc(wazuh.agent.name)"),
      single("Rules triggered", f"{F} | stats dc(wazuh.rule.id)"))
d.row(320,
      chart("splunk.column", "Findings over time by level", f"{F} | timechart usenull=f useother=f count by wazuh.rule.level", stackMode="stacked", w=800),
      chart("splunk.pie", "Findings by level", f"{F} | stats count by wazuh.rule.level"))
d.row(320,
      chart("splunk.bar", "Findings by category", f"{F} | stats count by wazuh.integration.category | sort - count"),
      chart("splunk.bar", "Top agents", f"{F} | stats count by wazuh.agent.name | sort - count | head 10"))
d.row(320, table("Top rules", f"{F} | stats count, dc(wazuh.agent.name) as agents by wazuh.rule.title, wazuh.rule.level | {LEVELS} | sort level_order, - count | fields - level_order | head 20"))
d.row(360, table("Latest findings", f"{F} | sort - _time | table _time, wazuh.agent.name, wazuh.rule.level, wazuh.rule.title, wazuh.integration.name, source.ip, user.name | head 50"))
findings = d

# MITRE ATT&CK: new.
d = Dashboard("Wazuh - MITRE ATT&CK", "MITRE ATT&CK tactics and techniques of the rules that produced the findings.")
d.row(110,
      single("Findings with MITRE ATT&CK", f'{F} "wazuh.rule.mitre.technique.id{{}}"=* | stats count'),
      single("Tactics", f'{F} | stats dc("wazuh.rule.mitre.tactic.id{{}}")'),
      single("Techniques", f'{F} | stats dc("wazuh.rule.mitre.technique.id{{}}")'),
      single("Sub-techniques", f'{F} | stats dc("wazuh.rule.mitre.subtechnique.id{{}}")'))
d.row(320,
      chart("splunk.column", "Tactics over time", f'{F} | rename "wazuh.rule.mitre.tactic.name{{}}" as tactic | timechart usenull=f useother=f count by tactic', stackMode="stacked", w=800),
      chart("splunk.pie", "Findings by tactic", f'{F} | rename "wazuh.rule.mitre.tactic.name{{}}" as tactic | stats count by tactic'))
d.row(320,
      chart("splunk.bar", "Top techniques", f'{F} | rename "wazuh.rule.mitre.technique.name{{}}" as technique | stats count by technique | sort - count | head 10'),
      chart("splunk.bar", "Top sub-techniques", f'{F} | rename "wazuh.rule.mitre.subtechnique.name{{}}" as subtechnique | where isnotnull(subtechnique) | stats count by subtechnique | sort - count | head 10'))
d.row(360, table("Techniques", f'{F} | rename "wazuh.rule.mitre.technique.id{{}}" as id, "wazuh.rule.mitre.technique.name{{}}" as technique, "wazuh.rule.mitre.tactic.name{{}}" as tactic | where isnotnull(id) | stats count, values(tactic) as tactics, dc(wazuh.agent.name) as agents, values(wazuh.rule.title) as rules by id, technique | sort - count'))
mitre = d

# Compliance: replaces wazuh-pci-dss.
# Every framework of wazuh.rule.compliance in WCS.
FRAMEWORKS = [("pci_dss", "PCI DSS"), ("nist_800_53", "NIST 800-53"), ("nist_800_171", "NIST 800-171"), ("gdpr", "GDPR"), ("hipaa", "HIPAA"),
              ("iso_27001", "ISO 27001"), ("nis2", "NIS2"), ("tsc", "TSC"), ("cmmc", "CMMC"), ("fedramp", "FedRAMP")]
d = Dashboard("Wazuh - Compliance", "Regulatory requirements of the rules that produced the findings.")
for half in (FRAMEWORKS[:5], FRAMEWORKS[5:]):
    d.row(110, *[single(f"{name} findings", f'{F} "wazuh.rule.compliance.{key}{{}}"=* | stats count') for key, name in half])
FRAMEWORK_EVAL = ", ".join(f"if(isnotnull('wazuh.rule.compliance.{key}{{}}'),\"{name}\",null())" for key, name in FRAMEWORKS)
d.row(320,
      chart("splunk.column", "Findings by framework over time",
            f'{F} | eval framework=mvappend({FRAMEWORK_EVAL}) | where isnotnull(framework) | timechart usenull=f useother=f limit=0 count by framework',
            stackMode="stacked"))
for pair in zip(FRAMEWORKS[::2], FRAMEWORKS[1::2]):
    d.row(320, *[chart("splunk.bar", f"{name} requirements", f'{F} | rename "wazuh.rule.compliance.{key}{{}}" as requirement | where isnotnull(requirement) | stats count by requirement | sort - count | head 10') for key, name in pair])
RENAMES = ", ".join(f'"wazuh.rule.compliance.{key}{{}}" as {key}' for key, _ in FRAMEWORKS)
ANY = " OR ".join(f"isnotnull({key})" for key, _ in FRAMEWORKS)
VALUES = ", ".join(f"values({key}) as {key}" for key, _ in FRAMEWORKS)
d.row(360, table("Requirements by rule", f'{F} | rename {RENAMES} | where {ANY} | stats count, dc(wazuh.agent.name) as agents, {VALUES} by wazuh.rule.title | sort - count'))
compliance = d

# Events overview: replaces wazuh-amazon-aws (cloud panels).
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



VIEWS = (("wazuh_findings_overview", findings), ("wazuh_mitre_attack", mitre),
         ("wazuh_compliance", compliance), ("wazuh_events_overview", events))


def view(dash: Dashboard) -> str:
    """Simple XML view holding a Dashboard Studio definition."""
    definition = json.dumps(dash.render(), indent=2)
    return (f'<dashboard version="2" theme="dark">\n  <label>{escape(dash.title)}</label>\n'
            f'  <description>{escape(dash.description)}</description>\n'
            f"  <definition><![CDATA[\n{definition}\n]]></definition>\n</dashboard>\n")


def navigation() -> str:
    """Navigation menu of the app: the dashboards first, then search."""
    items = "\n".join(f'    <view name="{name}" />' for name, _ in VIEWS)
    return (f'<nav search_view="search">\n  <collection label="Dashboards">\n{items}\n  </collection>\n'
            f'  <view name="search" />\n  <view name="dashboards" />\n</nav>\n')


def build() -> dict:
    """{path under the app's default/data/ui: content} of the views and the navigation menu."""
    files = {f"views/{name}.xml": view(dash) for name, dash in VIEWS}
    files["nav/default.xml"] = navigation()
    return files
