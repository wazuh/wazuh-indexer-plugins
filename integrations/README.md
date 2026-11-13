## Wazuh indexer integrations

This folder contains the integrations that export the data of the Wazuh indexer to other
platforms. They read the findings and events data streams of the Wazuh Common Schema and deliver
them, through Logstash, to:

- [Elasticsearch](./elastic/README.md)
- [OpenSearch](./opensearch/README.md)
- [Splunk](./splunk/README.md)
- [Amazon Security Lake](./amazon-security-lake/README.md), findings only, as OCSF Detection Findings

Documentation:

- [Reference manual](../docs/ref/integrations/index.md): what is exported, settings, security,
  and how to deploy every integration in production.
- [Development documentation](../docs/dev/integrations/index.md): the development environments,
  the events generator, the generated templates and dashboards, and the tests.

The integrations of Wazuh 4.x, for the `wazuh-alerts-4.x-*` indices, are a separate product that
will be deprecated. They live in the 4.x branches of
[wazuh-indexer](https://github.com/wazuh/wazuh-indexer/tree/4.14.11/integrations).

**Compatibility matrix**

|                | Wazuh indexer | Logstash | OpenSearch | Elastic | Splunk |
| -------------- | ------------- | -------- | ---------- | ------- | ------ |
| Latest version | 5.0.0-rc1     | 8.19.23  | 3.9.0      | 9.5.4   | 10.6.0 |
