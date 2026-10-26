# Wazuh to Amazon Security Lake integration

Exports the Wazuh findings from the Wazuh indexer to Amazon Security Lake, as OCSF Detection Findings, through Logstash, an S3 bucket and an AWS Lambda function.

- [Deployment guide](../../docs/ref/integrations/amazon-security-lake.md): how to deploy the integration in AWS, and the OCSF mapping.
- [Development environment](../../docs/dev/integrations/amazon-security-lake.md): how to start, customize and test the Docker Compose environment of the integration, with no AWS account.

Start the development environment from `integrations/docker`:

```bash
docker compose -f compose.amazon-security-lake.yml up -d --build
```

Build the package of the Lambda function:

```bash
make
```
