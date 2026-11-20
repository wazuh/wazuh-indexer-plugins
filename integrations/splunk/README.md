# Wazuh to Splunk integration

Exports the Wazuh findings and events from the Wazuh indexer to Splunk, through Logstash.

- [Deployment guide](../../docs/ref/integrations/splunk.md): how to deploy the integration in production.
- [Development environment](../../docs/dev/integrations/splunk.md): how to start, customize and test
  the Docker Compose environment of the integration.

Start the development environment from `integrations/docker`:

```bash
docker compose -f compose.indexer-splunk.yml up -d --build
```
