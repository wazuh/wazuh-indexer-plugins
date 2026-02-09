# Engine Filters Event Generator

This generator creates sample filter documents for testing the `.engine-filters` index.

## Usage

### Generate 10 filters (default)
```bash
python event_generator.py
```

### Generate specific number of filters
```bash
python event_generator.py -n 50
```

### Pretty print output
```bash
python event_generator.py --pretty
```

### Save to file
```bash
python event_generator.py -n 100 -o filters.json --pretty
```

### Bulk index to OpenSearch
```bash
python event_generator.py -n 20 | \
  jq -c '.[] | {"index": {"_index": ".engine-filters"}}, .' | \
  curl -X POST "localhost:9200/_bulk" -H "Content-Type: application/x-ndjson" --data-binary @-
```

## Output Format

Each generated document includes:
- **name**: Filter identifier (e.g., "filter/prefilter/0")
- **id**: Unique UUID
- **enabled**: Boolean flag
- **type**: "pre-filter" or "post-filter"
- **check**: Filter expression
- **metadata**: Description and author information

## Example Output

```json
{
  "filter": {
    "name": "filter/prefilter/0",
    "id": "fef71314-00c6-41f5-ab26-15e271e9f913",
    "enabled": true,
    "type": "pre-filter",
    "check": "$host.os.platform == 'ubuntu'",
    "metadata": {
      "description": "Filter for Ubuntu systems only",
      "author": {
        "name": "Wazuh, Inc.",
        "url": "https://wazuh.com",
        "date": "2022/11/08"
      }
    }
  }
}
```
