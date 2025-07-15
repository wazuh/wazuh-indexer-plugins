# Wazuh Indexer Reporting plugin

The `wazuh-indexer-reporting` plugin is a module composing the Wazuh Indexer and Wazuh Manager reporting system. It provides the posibility to create customizable reports based on any data stored in the Wazuh Indexer, supporting scheduled generation (e.g., daily, weekly) and on-demand generaion. Reports can be delivered via email or downloaded on demand through the UI or API. The plugin allows users to create, read, update, and delete (CRUD) custom reports from the dashboard, with actions restricted by Wazuh Indexer RBAC (role-based access control) permissions.

The behaviour is based on OpenSearch's built-in [Reporting and Notifications plugins](https://docs.opensearch.org/docs/latest/reporting/report-dashboard-index/).
