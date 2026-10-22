"""Splunk Dashboard Studio definitions of the Wazuh dashboards."""
import json

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
FRAMEWORKS = [("pci_dss", "PCI DSS"), ("nist_800_53", "NIST 800-53"), ("gdpr", "GDPR"), ("hipaa", "HIPAA")]
d = Dashboard("Wazuh - Compliance", "Regulatory requirements of the rules that produced the findings.")
d.row(110, *[single(f"{name} findings", f'{F} "wazuh.rule.compliance.{key}{{}}"=* | stats count') for key, name in FRAMEWORKS])
d.row(320,
      chart("splunk.column", "Findings by framework over time",
            f'{F} | eval framework=mvappend(if(isnotnull(\'wazuh.rule.compliance.pci_dss{{}}\'),"PCI DSS",null()), if(isnotnull(\'wazuh.rule.compliance.nist_800_53{{}}\'),"NIST 800-53",null()), if(isnotnull(\'wazuh.rule.compliance.gdpr{{}}\'),"GDPR",null()), if(isnotnull(\'wazuh.rule.compliance.hipaa{{}}\'),"HIPAA",null())) | where isnotnull(framework) | timechart usenull=f useother=f count by framework',
            stackMode="stacked"))
d.row(320, *[chart("splunk.bar", f"{name} requirements", f'{F} | rename "wazuh.rule.compliance.{key}{{}}" as requirement | where isnotnull(requirement) | stats count by requirement | sort - count | head 10') for key, name in FRAMEWORKS[:2]])
d.row(320, *[chart("splunk.bar", f"{name} requirements", f'{F} | rename "wazuh.rule.compliance.{key}{{}}" as requirement | where isnotnull(requirement) | stats count by requirement | sort - count | head 10') for key, name in FRAMEWORKS[2:]])
d.row(360, table("Requirements by rule", f'{F} | rename "wazuh.rule.compliance.pci_dss{{}}" as pci_dss, "wazuh.rule.compliance.nist_800_53{{}}" as nist_800_53, "wazuh.rule.compliance.gdpr{{}}" as gdpr, "wazuh.rule.compliance.hipaa{{}}" as hipaa | where isnotnull(pci_dss) OR isnotnull(nist_800_53) OR isnotnull(gdpr) OR isnotnull(hipaa) | stats count, dc(wazuh.agent.name) as agents, values(pci_dss) as pci_dss, values(nist_800_53) as nist_800_53, values(gdpr) as gdpr, values(hipaa) as hipaa by wazuh.rule.title | sort - count'))
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



def build() -> dict:
    """{file name: content} of the dashboards, one Dashboard Studio definition per file."""
    files = {}
    for name, dash in (("wazuh-findings-overview", findings), ("wazuh-mitre-attack", mitre),
                       ("wazuh-compliance", compliance), ("wazuh-events-overview", events)):
        files[f"{name}.json"] = json.dumps(dash.render(), indent=2) + "\n"
    return files
