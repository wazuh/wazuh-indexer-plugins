"""Single source of truth for endpoint paths and index names.

Keeping these in one place avoids the drift that broke the old ad-hoc scripts
(stale ``.cti-*`` index names, ``PUT /policy`` without a space, etc.).
"""

# REST base URI (see PluginSettings.PLUGINS_BASE_URI). Note: openapi.yml's
# servers.url wrongly uses "/_plugins/content-manager"; the real base has the
# underscore prefix.
BASE = "/_plugins/_content_manager"

# Resource endpoints
INTEGRATIONS = f"{BASE}/integrations"
DECODERS = f"{BASE}/decoders"
KVDBS = f"{BASE}/kvdbs"
RULES = f"{BASE}/rules"
FILTERS = f"{BASE}/filters"
POLICY = f"{BASE}/policy"
PROMOTE = f"{BASE}/promote"
LOGTEST = f"{BASE}/logtest"
LOGTEST_NORMALIZATION = f"{BASE}/logtest/normalization"
LOGTEST_DETECTION = f"{BASE}/logtest/detection"
SUBSCRIPTION = f"{BASE}/subscription"
UPDATE = f"{BASE}/update"
VERSION_CHECK = f"{BASE}/version/check"
SPACE = f"{BASE}/space"

# Index aliases (physical backing indices carry an "-a"/"-b" suffix; the alias
# is what queries target). The obsolete ".cti-*" names are gone.
INDEX_POLICIES = "wazuh-threatintel-policies"
INDEX_INTEGRATIONS = "wazuh-threatintel-integrations"
INDEX_RULES = "wazuh-threatintel-rules"
INDEX_KVDBS = "wazuh-threatintel-kvdbs"
INDEX_DECODERS = "wazuh-threatintel-decoders"
INDEX_FILTERS = "wazuh-threatintel-filters"
INDEX_ENRICHMENTS = "wazuh-threatintel-enrichments"

# Convenience map: resource type -> its index alias.
RESOURCE_INDEX = {
    "integration": INDEX_INTEGRATIONS,
    "decoder": INDEX_DECODERS,
    "kvdb": INDEX_KVDBS,
    "rule": INDEX_RULES,
    "filter": INDEX_FILTERS,
    "policy": INDEX_POLICIES,
}

# Spaces
SPACE_DRAFT = "draft"
SPACE_TEST = "test"
SPACE_CUSTOM = "custom"
SPACE_STANDARD = "standard"

# Security Analytics (SAP) + Alerting — used by the findings-generation scenario.
SA_BASE = "/_plugins/_security_analytics"
SA_DETECTORS = f"{SA_BASE}/detectors"
SA_FINDINGS = f"{SA_BASE}/findings/_search"
SA_RULES_SEARCH = f"{SA_BASE}/rules/_search"
ALERTING = "/_plugins/_alerting"
DETECTORS_CONFIG_INDEX = ".opensearch-sap-detectors-config"

# Events data streams the detectors read (one per integration category).
EVENTS_INDEX_PREFIX = "wazuh-events-v5-"

