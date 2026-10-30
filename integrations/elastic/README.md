# Wazuh to Elasticsearch integration

Exports the Wazuh findings and events from the Wazuh indexer to Elasticsearch, through Logstash.

- [Deployment guide](../../docs/ref/integrations/elastic.md): how to deploy the integration in production.
- [Development environment](../../docs/dev/integrations/elastic.md): how to start, customize and test
  the Docker Compose environment of the integration.

Start the development environment from `integrations/docker`:

```bash
docker compose -f compose.indexer-elastic.yml up -d --build
```
