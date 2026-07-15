# How to configure email notifications for reports

This page walks through configuring an email delivery channel in the Wazuh Dashboard so generated reports can be sent by email, and creating a report. See [Reporting](index.md) for the capabilities and permissions reference.

## Configuring the email notifications channel

In Wazuh Dashboard, go to **Notifications > Channels** and click on **Create channel**:

![Create Channel](/img/channelCreation.png)

1. Fill in a name (e.g `Email notifications`).
2. Select **Email** as **Channel Type**.
3. Check **SMTP sender** as **Sender Type**.
4. Click on **Create SMTP sender**.
   1. Fill in a name (e.g `mailpit`).
   2. Fill in an email address.
   3. In **Host**, type `mailpit` (adapt this to your SMTP server Domain Name).
   4. For port, type **1025** (adapt this to your SMTP server settings).
   5. Select **None** as **Encryption method**.
   6. Click on **Create**.
   ![Create SMTP sender](/img/SMTPSender.png)
5. Click on **Create recipient group**.
   1. Fill in a name (e.g `email-notifications-recipient-group`).
   2. On **Emails**, type any email.
   3. Click on **Create**.
   ![Create recipient group](/img/recipientGroup.png)

The fields should now be filled in as follows:
<img src="/img/channelCreation2.png" alt="Create Channel" width="500"/>

6. Click on **Send test message** to validate the configuration, a green message should pop up.
7. Finally, click on **Create**.

More information on how to configure the email notifications channel can be found in the [OpenSearch documentation](https://docs.opensearch.org/3.6/observing-your-data/notifications/index/#email-as-a-channel-type).

## Creating a new report

For more information on how to create reports, please refer to the [OpenSearch documentation](https://docs.opensearch.org/3.6/reporting/report-dashboard-index/). The reporting plugin also allows you to create notifications following the behaviour on [OpenSearch's notifications plugin](https://docs.opensearch.org/3.6/observing-your-data/notifications/index/).

### Generate and download a report

To create a new report you must have predefined the report settings. Once the report is configured, you can generate it by clicking the "Generate Report" button. This is only available on "On demand" report definitions as scheduled reports will be generated automatically. The report will be processed and made available for download at the Reports section on Explore -> Report.

You can also create a csv or xlsx report without a report definition by saving a search on Explore -> Discover. Remember to have an available index pattern.

### Generate a report definition

Before creating a report definition you must have generated and saved a Dashboard, a Visualization, a search or a Notebook. Then you can do so at the Explore -> Reporting section, choosing the intended configuration. This generates PDF/PNG reports or CSV/XLSX reports in case a saved search is selected.
