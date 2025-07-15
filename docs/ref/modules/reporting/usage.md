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

## Creating a new report

### Generate and download a report
To create a new report you must have predefined the report settings. Once the report is configured, you can generate it by clicking the "Generate Report" button. This is only available on "On demand" report definitions as scheduled reports will be generated automatically. The report will be processed and made available for download at the Reports section on Explore -> Report.
You can also create a report without a report definition by saving a filtered search on Explore -> Discover. Remember to have an available index pattern.

### Generate a report definition
Before creating a report definition you must have generated and saved a Dashboard, a Visualization, a filtered search or a Notebook. Then you can do so at the Explore -> Reporting section, choosing the intended configuration.
