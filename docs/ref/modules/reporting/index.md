# Wazuh Indexer Reporting plugin

The `wazuh-indexer-reporting` plugin is a module that provides the possibility to create customizable reports based on any data stored in the Wazuh Indexer. These data originate primarily from the Wazuh Manager, which collects and analyzes security events from agents. The plugin supports scheduled generation (e.g., daily, weekly) and on-demand generation, with delivery options via email or on demand download through the UI or API. The plugin allows users to create, read, update, and delete (CRUD) custom reports from the dashboard, with actions restricted by Wazuh Indexer RBAC (role-based access control) permissions.

The behavior is based on OpenSearch's built-in [Reporting and Notifications plugins](https://docs.opensearch.org/docs/latest/reporting/report-dashboard-index/).
