# Reporting

The `wazuh-indexer-reporting` plugin provides functionality for generating customizable reports based on data stored in the Wazuh Indexer. Most of this data originates from the Wazuh Manager, which collects and analyzes security events from registered agents. The plugin supports both scheduled and on-demand report generation. Reports can be delivered via email or downloaded on demand through the Wazuh Dashboard or the API. Users can create, read, update, and delete custom reports. Access to these actions is governed by the Wazuh Indexer's role-based access control (RBAC) permissions. This plugin is built on top of OpenSearch's native [Reporting and Notifications plugins](https://docs.opensearch.org/3.6/reporting/report-dashboard-index/).

## Report types

- **Scheduled reports** — generated automatically on a defined schedule from a saved report definition.
- **On-demand reports** — generated immediately when requested, either from a report definition or directly from a saved search, dashboard, visualization, or notebook.

Generated reports are PDF or PNG for dashboards/visualizations/notebooks, or CSV/XLSX for saved searches.

## Delivery

Reports can be delivered by email through the [Notifications](../notifications/index.md) plugin, or downloaded on demand through the Wazuh Dashboard or the API.

For a walkthrough of configuring an email delivery channel and generating a report, see [How to configure email notifications for reports](how-to-configure-email.md).

## Configuration

The Reporting plugin is configured through cluster settings.

- **`plugins.reports.max_report_definitions`** (Integer, default `50`, minimum `0`, no upper bound, dynamic) — maximum number of report definitions allowed. Creation requests that would exceed this limit are rejected with HTTP 400. Existing report definitions are not affected when the limit is lowered.
- **`opensearch.reports.general.operationTimeoutMs`** (Long, default `60000`, min `100`) — timeout in milliseconds for report generation operations.
- **`opensearch.reports.general.defaultItemsQueryCount`** (Integer, default `100`, min `10`) — default number of items fetched per query when building report data.

To change it at runtime:

```bash
curl -sk -u admin:admin -X PUT "https://127.0.0.1:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "plugins.reports.max_report_definitions": 20
  }
}'
```

## Managing permissions on reporting via RBAC

The Reporting plugin uses the Wazuh Indexer RBAC (role-based access control) system to manage permissions. This means that users must have the appropriate roles assigned to them in order to create, read, update, or delete reports. The roles can be managed through the Wazuh Dashboard Index Management -> Security -> Roles section. The following [permissions](https://docs.opensearch.org/3.6/security/access-control/permissions/#reporting-permissions) are available for the Reporting plugin:

```
1. cluster:admin/opendistro/reports/definition/create
2. cluster:admin/opendistro/reports/definition/update
3. cluster:admin/opendistro/reports/definition/on_demand
4. cluster:admin/opendistro/reports/definition/delete
5. cluster:admin/opendistro/reports/definition/get
6. cluster:admin/opendistro/reports/definition/list
7. cluster:admin/opendistro/reports/instance/list
8. cluster:admin/opendistro/reports/instance/get
9. cluster:admin/opendistro/reports/menu/download
```

There are already some predefined roles that can be used to manage permissions on reporting:
- `reports_read_access`: permissions 5 to 9.
- `reports_instances_read_access`: 7 to 9.
- `reports_full_access`: permissions 1 to 9.

More information on how to modify and map roles on the Wazuh Indexer can be found in the [Wazuh Indexer documentation](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).
