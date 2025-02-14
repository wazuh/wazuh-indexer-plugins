## Wazuh indexer integrations

This folder contains integrations with third-party XDR, SIEM and cybersecurity software.
The goal is to transport Wazuh's analysis to the platform that suits your needs.

### Amazon Security Lake

Amazon Security Lake automatically centralizes security data from AWS environments, SaaS providers,
on premises, and cloud sources into a purpose-built data lake stored in your account. With Security Lake,
you can get a more complete understanding of your security data across your entire organization. You can
also improve the protection of your workloads, applications, and data. Security Lake has adopted the
Open Cybersecurity Schema Framework (OCSF), an open standard. With OCSF support, the service normalizes
and combines security data from AWS and a broad range of enterprise security data sources.

Refer to these documents for more information about this integration:

- [User Guide](./amazon-security-lake/README.md).
- [Developer Guide](./amazon-security-lake/CONTRIBUTING.md).

### Other integrations

We host development environments to support the following integrations:

- [Splunk](./splunk/README.md).
- [Elasticsearch](./elastic/README.md).
- [OpenSearch](./opensearch/README.md).

**Compatibility matrix**

|                | Wazuh  | Logstash | OpenSearch | Elastic | Splunk |
| -------------- | ------ | -------- | ---------- | ------- | ------ |
| v1.0           | 4.8.1  | 8.9.0    | 2.14.0     | 8.14.3  | 9.1.4  |
| Latest version | 4.10.1 | 8.9.0    | 2.18.0     | 8.17.1  | 9.4.0  |
