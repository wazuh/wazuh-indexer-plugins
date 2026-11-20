#!/usr/bin/env python3

# Dashboards of the Wazuh dashboard, converted for the integrations.
#
# The Wazuh dashboard shows the findings in modules (threat hunting, MITRE ATT&CK, compliance,
# cloud services...), each one a dashboard of OpenSearch Dashboards on the findings data
# streams. The integrations export the same findings, with the same fields of the Wazuh Common
# Schema, so they reuse those dashboards instead of redrawing them: the definitions of every
# dashboard built on the findings are copied from wazuh-dashboard-plugins, at the version below,
# under wazuh-dashboard/<version>/, and converted for the index pattern of the exported findings.
#
# The Wazuh dashboard renders the saved dashboards as they are, so the conversion keeps their
# panels, layout and options. It changes only what the Wazuh dashboard does outside of them:
# - it filters the data of every module itself (for example, only the findings of the AWS
#   integration), so the conversion adds that filter to the dashboard;
# - it loads all the definitions in the same OpenSearch Dashboards, where a visualization shared
#   by several of them is one object, and the last definition loaded wins. The conversion
#   resolves them in the same order.
#
# Usage:
#   wazuh_dashboard.py   download the definitions of VERSION (to update them)

import json
import os
import sys
import urllib.request

VERSION = "5.0.0"
SOURCE = "https://raw.githubusercontent.com/wazuh/wazuh-dashboard-plugins/{version}/plugins/main/common/dashboards/dashboard-definitions/{path}"
DEFINITIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wazuh-dashboard", VERSION)


def exists(field):
    return {"type": "exists", "field": field}


def phrase(field, value):
    return {"type": "phrase", "field": field, "value": value}


def wildcard(field, value):
    return {"type": "wildcard", "field": field, "value": value}


# The filter the Wazuh dashboard applies to every module.
MITRE = exists("wazuh.rule.mitre.technique.id")
MALWARE = exists("wazuh.threat.enrichments")
CASES = exists("wazuh.case.status")
DOCKER = phrase("wazuh.integration.name", "docker")
AWS = wildcard("wazuh.integration.name", "aws*")
AZURE = phrase("wazuh.integration.name", "azure")
GCP = phrase("wazuh.integration.name", "gcp")
GITHUB = phrase("wazuh.integration.name", "github")
O365 = phrase("wazuh.integration.name", "o365")


def compliance(framework):
    return exists(f"wazuh.rule.compliance.{framework}")


# The dashboards the Wazuh dashboard scopes to one value, which the conversion adds a panel on top
# of them to pick: (field, label, panel).
# - The agent dashboards, shown when an agent is pinned, out of all the agents: an options list.
# - The drilldowns, shown when a value of a table of the module is clicked: a table of the values
#   of the module, to filter for one. An options list would offer the values of every module.
AGENT = ("wazuh.agent.name", "Agent", "control")


def drilldown(field, label):
    return (field, label, "table")


# Dashboards of the Wazuh dashboard built on the findings: definition in wazuh-dashboard-plugins,
# filter of its module, and the value it is scoped to. Left out, the dashboards that the Wazuh
# dashboard embeds in other pages, with one or a few panels: the findings count evolution of the
# agent summary, the cases panels of the cases list, and the histogram of the events.
DASHBOARDS = [
    ("overview/aws/overview/aws-overview-dashboard-tab.ndjson", AWS, None),
    ("overview/aws/pinned-agent/aws-pinned-agent-dashboard-tab.ndjson", AWS, AGENT),
    ("overview/azure/overview/azure-overview-dashboard-tab.ndjson", AZURE, None),
    ("overview/azure/pinned-agent/azure-pinned-agent-dashboard-tab.ndjson", AZURE, AGENT),
    ("overview/case-management/case-management-dashboard-tab.ndjson", CASES, None),
    ("overview/cmmc/overview/cmmc-overview-dashboard-tab.ndjson", compliance("cmmc"), None),
    ("overview/cmmc/pinned-agent/cmmc-pinned-agent-dashboard-tab.ndjson", compliance("cmmc"), AGENT),
    ("overview/docker/overview/docker-overview-dashboard-tab.ndjson", DOCKER, None),
    ("overview/docker/pinned-agent/docker-pinned-agent-dashboard-tab.ndjson", DOCKER, AGENT),
    ("overview/fedramp/overview/fedramp-overview-dashboard-tab.ndjson", compliance("fedramp"), None),
    ("overview/fedramp/pinned-agent/fedramp-pinned-agent-dashboard-tab.ndjson", compliance("fedramp"), AGENT),
    ("overview/gdpr/overview/gdpr-overview-dashboard.ndjson", compliance("gdpr"), None),
    ("overview/gdpr/pinned-agent/gdpr-pinned-agent-dashboard.ndjson", compliance("gdpr"), AGENT),
    ("overview/github/drilldowns/action/github-drilldown-action-dashboard-tab.ndjson", GITHUB, drilldown("event.action", "Action")),
    ("overview/github/drilldowns/actor/github-drilldown-actor-dashboard-tab.ndjson", GITHUB, drilldown("user.name", "Actor")),
    ("overview/github/drilldowns/organization/github-drilldown-organization-dashboard-tab.ndjson", GITHUB,
     drilldown("organization.name", "Organization")),
    ("overview/github/drilldowns/repository/github-drilldown-repository-dashboard.ndjson", GITHUB, drilldown("url.original", "Repository")),
    ("overview/github/overview/github-overview-dashboard-tab.ndjson", GITHUB, None),
    ("overview/github/pinned-agent/github-pinned-agent-dashboard-tab.ndjson", GITHUB, AGENT),
    ("overview/google-cloud/overview/google-cloud-detector-dashboard-tab.ndjson", GCP, None),
    ("overview/google-cloud/pinned-agent/google-cloud-pinned-agent-dashboard.ndjson", GCP, AGENT),
    ("overview/hipaa/overview/hipaa-overview-dashboard-tab.ndjson", compliance("hipaa"), None),
    ("overview/hipaa/pinned-agent/hipaa-pinned-agent-dashboard-tab.ndjson", compliance("hipaa"), AGENT),
    ("overview/iso27001/overview/iso27001-overview-dashboard-tab.ndjson", compliance("iso_27001"), None),
    ("overview/iso27001/pinned-agent/iso27001-pinned-agent-dashboard-tab.ndjson", compliance("iso_27001"), AGENT),
    ("overview/malware-detection/overview/malware-detection-overview-dashboard-tab.ndjson", MALWARE, None),
    ("overview/malware-detection/pinned-agent/malware-detection-pinned-agent-dashboard-tab.ndjson", MALWARE, AGENT),
    ("overview/mitre/overview/mitre-overview-dashboard-tab.ndjson", MITRE, None),
    ("overview/mitre/pinned-agent/mitre-pinned-agent-dashboard-tab.ndjson", MITRE, AGENT),
    ("overview/nis2/overview/nis2-overview-dashboard-tab.ndjson", compliance("nis2"), None),
    ("overview/nis2/pinned-agent/nis2-pinned-agent-dashboard-tab.ndjson", compliance("nis2"), AGENT),
    ("overview/nist-800-171/overview/nist-800-171-overview-dashboard-tab.ndjson", compliance("nist_800_171"), None),
    ("overview/nist-800-171/pinned-agent/nist-800-171-pinned-agent-dashboard-tab.ndjson", compliance("nist_800_171"), AGENT),
    ("overview/nist/overview/nist-overview-dashboard-tab.ndjson", compliance("nist_800_53"), None),
    ("overview/nist/pinned-agent/nist-pinned-agent-dashboard-tab.ndjson", compliance("nist_800_53"), AGENT),
    ("overview/office/drilldowns/ip-config/office-drilldown-ip-config-panel-tab.ndjson", O365, drilldown("client.ip", "Client IP address")),
    ("overview/office/drilldowns/operations-config/office-drilldown-operations-config-panel-tab.ndjson", O365,
     drilldown("event.action", "Operation")),
    ("overview/office/drilldowns/rules-config/office-drilldown-rules-config-panel-tab.ndjson", O365, drilldown("event.type", "Event type")),
    ("overview/office/drilldowns/user-config/office-drilldown-user-config-panel-tab.ndjson", O365, drilldown("user.name", "User")),
    ("overview/office/overview/office-overview-dashboard-tab.ndjson", O365, None),
    ("overview/pci/overview/pci-overview-dashboard-tab.ndjson", compliance("pci_dss"), None),
    ("overview/pci/pinned-agent/pci-pinned-agent-dashboard-tab.ndjson", compliance("pci_dss"), AGENT),
    ("overview/threat-hunting/overview/threat-hunting-overview-dashboard.ndjson", None, None),
    ("overview/threat-hunting/pinned-agent/threat-hunting-pinned-agent-dashboard.ndjson", None, AGENT),
    ("overview/tsc/overview/tsc-overview-dashboard-tab.ndjson", compliance("tsc"), None),
    ("overview/tsc/pinned-agent/tsc-pinned-agent-dashboard-tab.ndjson", compliance("tsc"), AGENT),
]

# Titles and labels of the visualizations that the integrations change:
# - the documents are findings: the titles and labels that call them events or alerts say
#   findings. "Event" stays where it names a field of the event a finding carries (event type,
#   event category);
# - a visualization that shows only the N most frequent values of a field says "Top N" in its
#   title, for the values the title names first. Fields with fewer values than N (outcome,
#   status, severity, TLP) and tables of hundreds of rows show them all, and keep their titles.
# Every change names the text it replaces: the conversion fails when the Wazuh dashboard changes
# that text, so that its new version is reviewed. Untitled visualizations (shown without a title)
# change the name of their saved object.
TITLES = {
    "agents-docker-top-5-actions": ("Top 5 events", "Top 5 actions"),
    "agents-general-alerts-evolution-by-action": ("Findings evolution by action", "Top 5 actions over time"),
    "aws_agent_events_by_bucket": ("Top actions over time (agent)", "Top 5 actions over time (agent)"),
    "aws_agent_events_by_source": ("Events by source over time (agent)", "Top 5 sources over time (agent)"),
    "aws_agent_geolocation_map": ("Top Source IPs and Actions (agent)", "Top 15 source IPs and their actions (agent)"),
    "aws_overview_events_by_resource": ("Top actions over time", "Top 5 actions over time"),
    "aws_overview_events_by_source": ("Events by source over time", "Top 5 sources over time"),
    "aws_overview_top_accounts": ("Top AWS accounts (overview)", "Top 5 AWS accounts (overview)"),
    "azure_agent_events_by_category": ("Events by category over time (agent)", "Top 10 event categories over time (agent)"),
    "azure_agent_source_ip_by_activity": ("Top Source IPs by Activity (agent)", "Top 15 source IPs by activity (agent)"),
    "azure_overview_events_by_category": ("Events by category over time (overview)", "Top 5 event categories over time (overview)"),
    "azure_overview_source_ip_by_activity": ("Top Source IPs by Activity (overview)", "Top 15 source IPs by activity (overview)"),
    "fedramp-agent-dashboard-requirements-by-agent": ("Requirements by agent", "Top 5 requirements by agent"),
    "fedramp-agent-dashboard-requirements-evolution-time": ("Requirements evolution over time", "Top 10 requirements over time"),
    "fedramp-overview-dashboard-common-requirements": ("Most common requirements", "Top 5 requirements"),
    "fedramp-overview-dashboard-fedramp-requirements": ("Fedramp Requirements", "Top 10 FedRAMP requirements"),
    "fedramp-pinned-agent-dashboard-fedramp-requirements": ("Fedramp Requirements", "Top 10 FedRAMP requirements"),
    "fedramp-pinned-agent-dashboard-integration-distribution": ("Integration distribution", "Top 5 requirements by integration"),
    "fedramp-pinned-agent-dashboard-requirements-evolution-time": ("Requirements evolution over time", "Top 10 requirements over time"),
    "malware-detection-overview-enrichment-type": ("Enrichment types", "Top 8 enrichment types"),
    "malware-detection-overview-last-seen-software-type": ("Last seen software types", "Top 5 software types by last seen date"),
    "nis2-overview-dashboard-nis2-requirements": ("NIS2 requirements", "Top 10 NIS2 requirements"),
    "nis2-overview-dashboard-requirements-by-agent": ("Requirements by agent", "Top 5 requirements by agent"),
    "nis2-overview-dashboard-requirements-evolution-over-time": ("Requirements evolution over time", "Top 10 requirements over time"),
    "nis2-overview-dashboard-top-10-agents-by-events-count": ("Top 10 agents by events count", "Top 10 agents by findings"),
    "nis2-pinned-agent-dashboard-nis2-requirements": ("NIS2 requirements", "Top 10 NIS2 requirements"),
    "nis2-pinned-agent-dashboard-nis2-requirements-over-time": ("NIS2 requirements over time", "Top 5 NIS2 requirements over time"),
    "overview-cmmc-top-10-agents": ("Most active agents", "Top 10 agents"),
    "overview-cmmc-top-10-requirements-over-time-by-agent": ("Requirements distribution by agent", "Requirements distribution of the top 5 agents"),
    "overview-docker-top-5-events": ("Top 5 events", "Top 5 actions"),
    "overview-hipaa-top-10-agents": ("Most active agents", "Top 10 agents"),
    "overview-hipaa-top-10-requirements-over-time-by-agent": ("Requirements distribution by agent", "Requirements distribution of the top 5 agents"),
    "wz-case-management-top-5-users": ("Top case creator by status", "Top 5 case creators by status"),
    "wz-vis-agents-cmmc-bubbles": ("CMMC requirements", "Top 5 CMMC requirements"),
    "wz-vis-agents-cmmc-distributed-by-level": ("Rule distribution", "Top 5 rules"),
    "wz-vis-agents-cmmc-most-common": ("Most common requirements", "Top 5 requirements"),
    "wz-vis-agents-cmmc-requirements-stacked-overtime": ("Requirements over time", "Top 5 requirements over time"),
    "wz-vis-agents-docker-actions-over-time": ("Events occurred evolution", "Top 10 actions over time"),
    "wz-vis-agents-docker-types-over-time": ("Resources usage over time", "Top 5 event categories over time"),
    "wz-vis-agents-gcp-event-query-name": ("Top query events", "Top 5 DNS queries"),
    "wz-vis-agents-gcp-events-over-time": ("GCP alerts evolution", "GCP findings over time"),
    "wz-vis-agents-gcp-outcome": ("Event outcome count", "Findings by outcome"),
    "wz-vis-agents-gdpr-requirements": ("GDPR requirements", "Top 10 GDPR requirements"),
    "wz-vis-agents-gdpr-rule-level-distribution": ("Top categories", "Top 15 categories"),
    "wz-vis-agents-github-alert-action-type-by-organization": ("Top audits by action type and organization",
                                                               "Top 5 organizations and their top 3 actions"),
    "wz-vis-agents-github-alerts-evolution-by-organization": ("Audits evolution by organization", "Top 5 organizations over time"),
    "wz-vis-agents-github-users-with-more-alerts": ("Users with more audits", "Top 5 users by organization"),
    "wz-vis-agents-hipaa-bubbles": ("HIPAA requirements", "Top 5 HIPAA requirements"),
    "wz-vis-agents-hipaa-distributed-by-level": ("Integration distribution", "Top 5 requirements by integration"),
    "wz-vis-agents-hipaa-most-common": ("Most common requirements", "Top 5 requirements"),
    "wz-vis-agents-hipaa-requirements-stacked-overtime": ("Requirements over time", "Top 5 requirements over time"),
    "wz-vis-agents-iso27001-requirements": ("ISO 27001 requirements", "Top 10 ISO 27001 requirements"),
    "wz-vis-agents-iso27001-requirements-over-time": ("ISO 27001 requirements over time", "Top 5 ISO 27001 requirements over time"),
    "wz-vis-agents-mitre-level-by-attack": ("Rule level by technique", "Rule level of the top 5 techniques"),
    "wz-vis-agents-mitre-level-by-tactic": ("Rule level by tactic", "Rule level of the top 5 tactics"),
    "wz-vis-agents-nist-171-requirement-by-level": ("Integration distribution", "Top 5 requirements by integration"),
    "wz-vis-agents-nist-171-requirements-stacked-overtime": ("Requirements over time", "Top 5 requirements over time"),
    "wz-vis-agents-nist-800-53-requirement-by-level": ("Integration distribution", "Top 5 requirements by integration"),
    "wz-vis-agents-nist-800-53-requirements-stacked-overtime": ("Requirements over time", "Top 5 requirements over time"),
    "wz-vis-agents-pci-requirements": ("PCI DSS requirements", "Top 10 PCI DSS requirements"),
    "wz-vis-agents-pci-requirements-over-time": ("PCI requirements over time", "Top 5 PCI DSS requirements over time"),
    "wz-vis-agents-tsc-requirements": ("TSC requirements", "Top 10 TSC requirements"),
    "wz-vis-agents-tsc-rule-level-distribution": ("Top integrations", "Top 15 integrations"),
    "wz-vis-gcp-events-over-time": ("GCP alerts evolution", "GCP findings over time"),
    "wz-vis-gtsc-requirements": ("TSC requirements", "Top 10 TSC requirements"),
    "wz-vis-iso27001-requirements": ("ISO 27001 requirements", "Top 10 ISO 27001 requirements"),
    "wz-vis-overview-cmmc-heatmap": ("Findings volume by agent", "Findings volume of the top 5 agents"),
    "wz-vis-overview-cmmc-tag-cloud": ("Most common requirements", "Top 5 requirements"),
    "wz-vis-overview-cmmc-top-requirements-over-time": ("Requirements evolution over time", "Top 10 requirements over time"),
    "wz-vis-overview-docker-events": ("Events", "Findings"),
    "wz-vis-overview-docker-events-by-source-over-time": ("Events by source over time", "Top 5 event categories over time"),
    "wz-vis-overview-gcp-alerts-evolution-by-authanswer": ("Events over time by outcome", "Findings over time by outcome"),
    "wz-vis-overview-gcp-top-eventcategory-by-project-id": ("Event category by project ID", "Top 5 projects by event category"),
    "wz-vis-overview-gcp-top-instances-by-responsecode": ("Top instances by response code", "Top 5 instances by response code"),
    "wz-vis-overview-gcp-top-projectid-by-sourcetype": ("Top project ID by action", "Top 5 project IDs by action"),
    "wz-vis-overview-gcp-top-resourcetype-by-project-id": ("Top projects by category", "Top 5 projects by event category"),
    "wz-vis-overview-gdpr-agents": ("Top 10 agents by events number", "Top 10 agents by findings"),
    "wz-vis-overview-gdpr-requirements": ("GDPR requirements", "Top 10 GDPR requirements"),
    "wz-vis-overview-gdpr-requirements-agents": ("Last events", "Findings volume of the top 5 requirements"),
    "wz-vis-overview-gdpr-requirements-by-agent": ("Requirements by agent", "Top 5 requirements by agent"),
    "wz-vis-overview-gdpr-requirements-heatmap": ("Top requirements over time", "Top 5 requirements over time"),
    "wz-vis-overview-github-alert-action-type-by-organization": ("Top audits by action type and organization",
                                                                 "Top 5 organizations and their top 3 actions"),
    "wz-vis-overview-github-alert-level-evolution": ("Audit level evolution", "Top 10 rule levels over time"),
    "wz-vis-overview-github-alerts-evolution-by-organization": ("Audits evolution by organization", "Top 5 organizations over time"),
    "wz-vis-overview-github-users-with-more-alerts": ("Users with more audits", "Top 5 users by organization"),
    "wz-vis-overview-hipaa-heatmap": ("Requirements volume by agent", "Findings volume of the top 5 agents"),
    "wz-vis-overview-hipaa-tag-cloud": ("Most common requirements", "Top 5 requirements"),
    "wz-vis-overview-hipaa-top-requirements-over-time": ("Requirements evolution over time", "Top 10 requirements over time"),
    "wz-vis-overview-iso27001-agents": ("Top 10 agents by events number", "Top 10 agents by findings"),
    "wz-vis-overview-iso27001-requirements-agents-heatmap": ("Last events", "Findings volume of the top 5 requirements"),
    "wz-vis-overview-iso27001-requirements-by-agent": ("Requirements by agent", "Top 5 requirements by agent"),
    "wz-vis-overview-iso27001-requirements-over-time": ("Top requirements over time", "Top 5 requirements over time"),
    "wz-vis-overview-mitre-alerts-evolution": ("Findings evolution over time", "Top 5 techniques over time"),
    "wz-vis-overview-mitre-attacks-by-agent": ("Top techniques by agent", "Top 5 techniques by agent"),
    "wz-vis-overview-mitre-attacks-by-technique": ("Top techniques", "Top 10 techniques"),
    "wz-vis-overview-mitre-top-tactics": ("Top tactics", "Top 10 tactics"),
    "wz-vis-overview-mitre-top-tactics-by-agent": ("Top tactics by agent", "Top 5 tactics by agent"),
    "wz-vis-overview-nist-171-agents": ("Most active agents", "Top 10 agents"),
    "wz-vis-overview-nist-171-requirements-agents-heatmap": ("Events volume by agent", "Findings volume of the top 5 agents"),
    "wz-vis-overview-nist-171-requirements-by-agents": ("Requirements distribution by agent", "Requirements distribution of the top 5 agents"),
    "wz-vis-overview-nist-800-53-agents": ("Most active agents", "Top 10 agents"),
    "wz-vis-overview-nist-800-53-requirements-agents-heatmap": ("Events volume by agent", "Findings volume of the top 5 agents"),
    "wz-vis-overview-nist-800-53-requirements-by-agents": ("Requirements distribution by agent", "Requirements distribution of the top 5 agents"),
    "wz-vis-overview-office-alerts-evolution-by-user": ("Office 365 events over time", "Top 5 event types over time"),
    "wz-vis-overview-office-alerts-evolution-by-userid": ("Alerts by user", "Top 5 users over time"),
    "wz-vis-overview-office-ips-by-user": ("IP address by users", "Top 12 IP addresses by user"),
    "wz-vis-overview-office-rule-level": ("Events by event type", "Top 12 event types over time"),
    "wz-vis-overview-office-severity-by-user": ("Actions by user", "Top 12 actions by user"),
    "wz-vis-overview-office-top-events": ("Top Event Actions", "Top 10 actions"),
    "wz-vis-overview-office-top-operations": ("Top operations", "Top 5 operations"),
    "wz-vis-overview-office-top-users": ("Top Office users", "Top 5 Office users"),
    "wz-vis-overview-office-top-users-by-subscription": ("Top users by provider", "Top 5 users by provider"),
    "wz-vis-overview-pci-dss-agents": ("Top 10 agents by events count", "Top 10 agents by findings"),
    "wz-vis-overview-pci-dss-requirements-agents-heatmap": ("Last events", "Findings volume of the top 5 requirements"),
    "wz-vis-overview-pci-dss-requirements-by-agent": ("Requirements by agent", "Top 5 requirements by agent"),
    "wz-vis-overview-tsc-agents": ("Top 10 agents by events number", "Top 10 agents by findings"),
    "wz-vis-overview-tsc-requirements-agents-heatmap": ("Last events", "Findings volume of the top 5 requirements"),
    "wz-vis-overview-tsc-requirements-by-agent": ("Requirements by agent", "Top 5 requirements by agent"),
    "wz-vis-overview-tsc-requirements-over-time": ("Top requirements over time", "Top 5 requirements over time"),
}
# Labels of the metrics, buckets and axes: {visualization: {label: new label}}.
FINDINGS_TOTAL = {"Total events": "Total findings"}
LABELS = {
    "aws_agent_geolocation_map": {"Event Count": "Findings", "Top Actions": "Top 5 actions"},
    "azure_agent_source_ip_by_activity": {"Event Count": "Findings", "Top Actions": "Top 5 actions"},
    "azure_overview_source_ip_by_activity": {"Event Count": "Findings", "Top Actions": "Top 5 actions"},
    "wz-vis-agents-docker-actions-over-time": {"Events": "Findings"},
    "wz-vis-agents-nist-171-stats": FINDINGS_TOTAL,
    "wz-vis-agents-nist-800-53-stats": FINDINGS_TOTAL,
    "wz-vis-overview-hipaa-metrics": FINDINGS_TOTAL,
    "wz-vis-overview-nist-171-metrics": FINDINGS_TOTAL,
    "wz-vis-overview-nist-800-53-metrics": FINDINGS_TOTAL,
    "wz-vis-overview-office-alerts-evolution-by-userid": {"Alerts": "Findings"},
    "wz-vis-overview-office-metric-stats": {"Total Events": "Total findings"},
}
SOURCE_IPS_DESCRIPTION = ("Provided by Wazuh. Shows most active source IPs and their top event actions",
                          "Provided by Wazuh. Shows most active source IPs and their top actions")
DESCRIPTIONS = {
    "azure_agent_source_ip_by_activity": SOURCE_IPS_DESCRIPTION,
    "azure_overview_source_ip_by_activity": SOURCE_IPS_DESCRIPTION,
}
# Terms aggregations whose size the title states: {visualization: (field, size, title's size)}.
SIZES = {
    "wz-vis-overview-nist-171-requirements-over-time": ("wazuh.rule.compliance.nist_800_171", 8, 10),
    "wz-vis-overview-nist-800-53-requirements-over-time": ("wazuh.rule.compliance.nist_800_53", 8, 10),
}


def changed(vid: str, what: str, current, expected, new):
    if current != expected:
        raise SystemExit(f"{vid}: the Wazuh dashboard changed its {what} to {current!r}, the integrations expect {expected!r}: "
                         f"review the change to {new!r} in wazuh_dashboard.py")
    return new


def adapted(o: dict) -> dict:
    """A visualization of the Wazuh dashboard, with the titles and labels of the integrations."""
    vid = o["id"]
    if not any(vid in table for table in (TITLES, LABELS, DESCRIPTIONS, SIZES)):
        return o
    o = json.loads(json.dumps(o))
    attributes = o["attributes"]
    state = json.loads(attributes["visState"])
    if vid in TITLES:
        old, new = TITLES[vid]
        # An untitled visualization keeps no title: its saved object is named by its state.
        state["title"] = changed(vid, "title", attributes["title"] or state.get("title"), old, new)
        if attributes["title"]:
            attributes["title"] = new
    if vid in LABELS:
        found = set()
        params = state.get("params", {})
        texts = ([agg.get("params", {}) for agg in state.get("aggs", [])] + [axis.get("title", {}) for axis in params.get("valueAxes", [])]
                 + [series.get("data", {}) for series in params.get("seriesParams", [])])
        for holder in texts:
            for key in ("customLabel", "text", "label"):
                if holder.get(key) in LABELS[vid]:
                    found.add(holder[key])
                    holder[key] = LABELS[vid][holder[key]]
        for label in set(LABELS[vid]) - found:
            changed(vid, "labels", None, label, LABELS[vid][label])
    if vid in DESCRIPTIONS:
        attributes["description"] = changed(vid, "description", attributes.get("description"), *DESCRIPTIONS[vid])
    if vid in SIZES:
        field, old, new = SIZES[vid]
        terms = [agg for agg in state.get("aggs", []) if agg["type"] == "terms" and agg["params"].get("field") == field]
        for agg in terms:
            agg["params"]["size"] = changed(vid, f"size of {field}", agg["params"].get("size"), old, new)
        if not terms:
            changed(vid, f"terms of {field}", None, field, new)
    attributes["visState"] = json.dumps(state)
    return o


# Index patterns of the Wazuh dashboard that the dashboards use: all of them hold findings.
SOURCE_PATTERNS = ("wazuh-findings-v5*", "wazuh-findings-v5-cloud-services*")
FILTER_INDEX_REF = "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index"


def load(path: str) -> list:
    with open(os.path.join(DEFINITIONS, path)) as fd:
        return [json.loads(line) for line in fd if line.strip()]


def saved_filter(spec: dict) -> dict:
    """A filter of a saved search source, referring to its index pattern by FILTER_INDEX_REF."""
    field, value = spec["field"], spec.get("value")
    meta = {"alias": None, "negate": False, "disabled": False, "key": field, "indexRefName": FILTER_INDEX_REF}
    if spec["type"] == "exists":
        return {"meta": {**meta, "type": "exists", "value": "exists"}, "exists": {"field": field}, "$state": {"store": "appState"}}
    if spec["type"] == "phrase":
        return {"meta": {**meta, "type": "phrase", "params": {"query": value}}, "query": {"match_phrase": {field: value}},
                "$state": {"store": "appState"}}
    query = {"wildcard": {field: {"value": value}}}
    return {"meta": {**meta, "type": "custom", "alias": f"{field}: {value}", "value": json.dumps(query)}, "query": query,
            "$state": {"store": "appState"}}


def object_id(source_id: str) -> str:
    return f"wazuh-{source_id}"


def references(o: dict, pattern_id: str) -> list:
    result = []
    for reference in o.get("references", []):
        if reference["type"] == "index-pattern":
            if reference["id"] not in SOURCE_PATTERNS:
                raise SystemExit(f"{o['id']}: index pattern {reference['id']} does not hold findings")
            result.append({**reference, "id": pattern_id})
        else:
            result.append({**reference, "id": object_id(reference["id"])})
    return result


def visualization(o: dict, pattern_id: str) -> dict:
    attributes = json.loads(json.dumps(o["attributes"]))
    if not attributes.get("title"):
        # The Wazuh dashboard shows some panels without a title, in its own layout. They keep no
        # title in the dashboards (see dashboard()), but the saved object needs a name.
        state = json.loads(attributes["visState"])
        labels = [agg["params"]["customLabel"] for agg in state.get("aggs", []) if agg.get("params", {}).get("customLabel")]
        attributes["title"] = state.get("title") or (labels[-1] if labels else o["id"])
    return {"id": object_id(o["id"]), "type": o["type"], "migrationVersion": o.get("migrationVersion", {}),
            "attributes": attributes, "references": references(o, pattern_id)}


def picker(dashboard_id: str, field: str, label: str, panel: str, pattern_id: str) -> dict:
    """The visualization to pick the value a dashboard is scoped to."""
    search = {"query": {"query": "", "language": "kuery"}, "filter": []}
    if panel == "control":
        state = {"title": f"{label} control", "type": "input_control_vis", "aggs": [],
                 "params": {"controls": [{"id": "1", "fieldName": field, "label": label, "type": "list", "parent": "",
                                          "indexPatternRefName": "control_0_index_pattern",
                                          "options": {"type": "terms", "multiselect": False, "dynamicOptions": True,
                                                      "size": 50, "order": "desc"}}],
                            "updateFiltersOnChange": True, "useTimeFilter": True, "pinFilters": False}}
        reference = {"id": pattern_id, "name": "control_0_index_pattern", "type": "index-pattern"}
    else:
        state = {"title": f"{label}: filter for one value", "type": "table",
                 "params": {"perPage": 5, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
                            "totalFunc": "sum", "percentageCol": ""},
                 "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Findings"}},
                          {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
                           "params": {"field": field, "orderBy": "1", "order": "desc", "size": 100, "otherBucket": False,
                                      "missingBucket": False, "customLabel": label}}]}
        search["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
        reference = {"id": pattern_id, "name": search["indexRefName"], "type": "index-pattern"}
    return {"id": object_id(f"{dashboard_id}-{panel}"), "type": "visualization", "migrationVersion": {"visualization": "7.10.0"},
            "attributes": {"title": state["title"], "visState": json.dumps(state), "uiStateJSON": "{}", "description": "", "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search)}},
            "references": [reference]}


PICKER_HEIGHT = {"control": 4, "table": 10}
PICKER_HINT = {"control": "Pick the {} in the control on top, as pinning it does in the Wazuh dashboard.",
               "table": "Filter for one {} in the table on top, as clicking it does in the Wazuh dashboard."}


def dashboard(o: dict, spec, scope, untitled: set, pattern_id: str) -> list:
    """The dashboard, and the visualization to pick the value it is scoped to, if any."""
    attributes = json.loads(json.dumps(o["attributes"]))
    title = attributes["title"]
    attributes["title"] = f"Wazuh - {title}"
    attributes["description"] = f"{title} of the Wazuh dashboard, on the findings exported from the Wazuh indexer."
    if scope:
        attributes["description"] += " " + PICKER_HINT[scope[2]].format(scope[1].lower())
    attributes["timeRestore"], attributes["timeFrom"], attributes["timeTo"] = True, "now-24h", "now"
    attributes["refreshInterval"] = {"pause": True, "value": 0}
    refs = references(o, pattern_id)
    names = {r["name"]: r["id"] for r in refs}
    panels = json.loads(attributes["panelsJSON"])
    for panel in panels:
        if names.get(panel.get("panelRefName")) in untitled:
            panel.setdefault("embeddableConfig", {})["hidePanelTitles"] = True
    extra = []
    if scope:
        extra.append(picker(o["id"], *scope, pattern_id))
        height = PICKER_HEIGHT[scope[2]]
        for panel in panels:
            panel["gridData"]["y"] += height
        name = f"panel_{len(panels)}"
        while name in names:
            name += "_"
        panels.insert(0, {"version": panels[0].get("version", "7.10.0") if panels else "7.10.0", "panelIndex": "picker",
                          "gridData": {"x": 0, "y": 0, "w": 48, "h": height, "i": "picker"},
                          "embeddableConfig": {"hidePanelTitles": scope[2] == "control"}, "panelRefName": name})
        refs.append({"id": extra[0]["id"], "name": name, "type": "visualization"})
    attributes["panelsJSON"] = json.dumps(panels)
    search = {"query": {"query": "", "language": "kuery"}, "filter": []}
    if spec:
        search["filter"] = [saved_filter(spec)]
        refs.append({"id": pattern_id, "name": FILTER_INDEX_REF, "type": "index-pattern"})
    attributes["kibanaSavedObjectMeta"] = {"searchSourceJSON": json.dumps(search)}
    return extra + [{"id": object_id(o["id"]), "type": o["type"], "migrationVersion": o.get("migrationVersion", {}),
                     "attributes": attributes, "references": refs}]


def resolved() -> tuple:
    """([(path, dashboard, filter, scope)], {id: visualization}): the definitions as the Wazuh
    dashboard loads them, in this order, the last definition of a visualization winning."""
    sources, boards = {}, []
    for path, spec, scope in sorted(DASHBOARDS):
        for o in load(path):
            if o["type"] == "dashboard":
                boards.append((path, o, spec, scope))
            elif o["type"] in ("visualization", "search"):
                sources[o["id"]] = o
    stale = sorted(set().union(TITLES, LABELS, DESCRIPTIONS, SIZES) - set(sources))
    if stale:
        raise SystemExit(f"visualizations no longer in the Wazuh dashboard, remove them from wazuh_dashboard.py: {stale}")
    return boards, {i: adapted(o) for i, o in sources.items()}


def dashboards(pattern_id: str) -> list:
    """The saved objects of the dashboards, for the index pattern pattern_id of the exported findings."""
    boards, sources = resolved()
    boards = [(o, spec, scope) for _, o, spec, scope in boards]
    untitled = {object_id(i) for i, o in sources.items() if not o["attributes"].get("title")}
    # Visualizations first, then the dashboards that refer to them.
    converted = [dashboard(o, spec, scope, untitled, pattern_id) for o, spec, scope in boards]
    return ([visualization(o, pattern_id) for o in sources.values()] +
            sorted((obj for objs in converted for obj in objs), key=lambda obj: obj["type"] == "dashboard"))


def download(version: str = VERSION) -> None:
    """Copies the definitions of the dashboards of a version of wazuh-dashboard-plugins."""
    for path, _, _ in DASHBOARDS:
        with urllib.request.urlopen(SOURCE.format(version=version, path=path), timeout=60) as response:
            content = response.read()
        os.makedirs(os.path.dirname(os.path.join(DEFINITIONS, path)), exist_ok=True)
        with open(os.path.join(DEFINITIONS, path), "wb") as fd:
            fd.write(content)
        print(f"downloaded {path}")


if __name__ == "__main__":
    download(sys.argv[1] if len(sys.argv) > 1 else VERSION)
