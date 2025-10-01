# WCS Test Tool

A bash script to test Wazuh Common Schema (WCS) index templates by indexing sample events from the intelligence-data repository into a Wazuh Indexer instance.

## Features

- ✅ Finds all `*_expected.json` test files for specified integrations
- ✅ Reads JSON arrays and indexes each document individually
- ✅ Supports authentication with username/password
- ✅ Comprehensive logging with timestamps
- ✅ Progress tracking and error reporting
- ✅ CSV summary report generation
- ✅ Colored console output for better readability

## Prerequisites

- `curl` - for HTTP requests to the indexer
- `jq` - for JSON processing
- `bash` - version 4.0 or higher
- Access to a Wazuh Indexer instance

## Usage

```bash
./wcs-test-tool.sh -p <intelligence-data-path> -i <integrations-map> -u <indexer-url> [options]
```

### Required Parameters

- `-p, --path`: Path to the intelligence-data repository
- `-i, --integrations`: Comma-separated list of integration:index pairs
- `-u, --url`: URL of the Indexer instance

### Optional Parameters

- `-c, --credentials`: Username and password separated by colon (e.g., `admin:admin`)
- `-l, --log-file`: Log file path (default: `wcs-test-tool.log`)
- `-h, --help`: Show help message

## Examples

### Test Amazon Security Lake integration

```bash
./wcs-test-tool.sh \
  -p /path/to/intelligence-data \
  -i 'amazon-security-lake:wazuh-events-amazon-security-lake' \
  -u https://localhost:9200 \
  -c admin:admin
```

### Test multiple integrations

```bash
./wcs-test-tool.sh \
  -p /path/to/intelligence-data \
  -i 'azure:wazuh-events-azure,aws:wazuh-events-aws,nginx:wazuh-events-nginx' \
  -u https://localhost:9200 \
  -c admin:admin \
  -l /tmp/wcs-test.log
```

### Test with local Wazuh Indexer

```bash
./wcs-test-tool.sh \
  -p ./intelligence-data \
  -i 'amazon-security-lake:wazuh-events-amazon-security-lake' \
  -u http://localhost:9200
```

## Output

The script generates:

1. **Console output**: Real-time progress with colored messages
2. **Log file**: Detailed log with timestamps (default: `wcs-test-tool.log`)
3. **CSV summary**: Summary report with statistics (`<log-file>.summary.csv`)

### Sample CSV Summary

```csv
file,total_docs,indexed_docs,failed_docs
/path/to/findings_expected.json,6,6,0
/path/to/discovery_expected.json,8,8,0
/path/to/application-activity_expected.json,10,10,0
```

## Integration:Index Mapping

The script uses the pattern `wazuh-events-<integration_name>` for index names, but you can specify custom mappings:

| Integration | Default Index Name |
|-------------|-------------------|
| amazon-security-lake | wazuh-events-amazon-security-lake |
| azure | wazuh-events-azure |
| aws | wazuh-events-aws |
| nginx | wazuh-events-nginx |

## Error Handling

The script handles various error conditions:

- ❌ Invalid paths or missing directories
- ❌ Connection failures to the indexer
- ❌ Authentication errors
- ❌ Malformed JSON documents
- ❌ Indexing failures

All errors are logged with details for troubleshooting.

## Testing Without an Indexer

To test the file discovery and document counting without actually indexing:

```bash
# Find test files manually
find /path/to/intelligence-data/ruleset/integrations/amazon-security-lake/test -name "*_expected.json"

# Count documents in a file
jq '. | length' /path/to/file_expected.json
```

## Troubleshooting

### Common Issues

1. **Connection refused**: Ensure the indexer is running and accessible
2. **Authentication failed**: Verify username/password credentials
3. **No test files found**: Check the integration name and intelligence-data path
4. **JSON parsing errors**: Validate the structure of test files

### Debug Mode

For detailed debugging, check the log file which contains:
- HTTP response codes
- Full error messages
- Document processing details
- Timing information

## Integration with CI/CD

This tool can be integrated into CI/CD pipelines to automatically test index templates:

```bash
# Example CI step
./wcs-test-tool.sh \
  -p $INTELLIGENCE_DATA_PATH \
  -i $INTEGRATIONS_TO_TEST \
  -u $INDEXER_URL \
  -c $INDEXER_CREDENTIALS \
  -l ci-test-results.log

# Check exit code
if [ $? -eq 0 ]; then
  echo "All tests passed!"
else
  echo "Some tests failed. Check ci-test-results.log"
  exit 1
fi
```