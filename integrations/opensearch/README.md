# Wazuh to OpenSearch integration

Exports the Wazuh findings and events from the Wazuh indexer to OpenSearch, through Logstash.

- [Deployment guide](../../docs/ref/integrations/opensearch.md): how to deploy the integration in production.
- [Development environment](../../docs/dev/integrations/opensearch.md): how to start, customize and test
  the Docker Compose environment of the integration.

Start the development environment from `integrations/docker`:

```bash
docker compose -f compose.indexer-opensearch.yml up -d --build
```
