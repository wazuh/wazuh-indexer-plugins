# Usage

## Configuring the email notifications channel

1. In Wazuh Dashboard, go to **Notifications > Channels** and click on **Create channel**.
   1. Fill in a name (e.g `Email notifications`).
   2. Select **Email** as **Channel Type**.
   3. Check **SMTP sender** as **Sender Type**.
   4. Click on **Create SMTP sender**
      1. Fill in a name (e.g `mailpit`).
      2. Fill in an email address.
      3. In **Host**, type `mailpit` (Domain Name)
      4. For port, type **1025**.
      5. Select **None** as **Encryption method**.
      6. Click on **Create**.
   5. Click on **Create recipient group**.
      1. Fill in a name (e.g `email-notifications-recipient-group`).
      2. On **Emails**, type any email.
      3. Click on **Create**.
   6. Click on **Send test message** to validate the configuration.
   7. Finally, click on **Create**.

More information on how to configure the email notifications channel can be found in the [OpenSearch documentation](https://docs.opensearch.org/docs/latest/observing-your-data/notifications/index/#email-as-a-channel-type).

## Creating a new report

For more information on how to create reports, please refer to the [OpenSearch documentation](https://docs.opensearch.org/docs/latest/reporting/report-dashboard-index/).

### Generate and download a report
To create a new report you must have predefined the report settings. Once the report is configured, you can generate it by clicking the "Generate Report" button. This is only available on "On demand" report definitions as scheduled reports will be generated automatically. The report will be processed and made available for download at the Reports section on Explore -> Report.
You can also create a report without a report definition by saving a filtered search on Explore -> Discover. Remember to have an available index pattern.

> This generates CSV/XLSX reports.

### Generate a report definition
Before creating a report definition you must have generated and saved a Dashboard, a Visualization, a filtered search or a Notebook. Then you can do so at the Explore -> Reporting section, choosing the intended configuration.

> This generates PDF/PNG reports.

## Managing permissions on reporting via RBAC
The Reporting plugin uses the Wazuh Indexer RBAC (role-based access control) system to manage permissions. This means that users must have the appropriate roles assigned to them in order to create, read, update, or delete reports. The roles can be managed through the Wazuh Dashboard Index Management -> Security -> Roles section. The following [permissions](https://docs.opensearch.org/docs/latest/security/access-control/permissions/#reporting-permissions) are available for the Reporting plugin:

```
cluster:admin/opendistro/reports/definition/create
cluster:admin/opendistro/reports/definition/update
cluster:admin/opendistro/reports/definition/on_demand
cluster:admin/opendistro/reports/definition/delete
cluster:admin/opendistro/reports/definition/get
cluster:admin/opendistro/reports/definition/list
cluster:admin/opendistro/reports/instance/list
cluster:admin/opendistro/reports/instance/get
cluster:admin/opendistro/reports/menu/download
```

More information on how to modify and map roles on the Wazuh Indexer can be found in the [Wazuh Indexer documentation](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).
