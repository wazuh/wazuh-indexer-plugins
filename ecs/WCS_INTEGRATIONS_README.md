# WCS Integrations Generator

This directory contains the script and generated files for Wazuh Common Schema (WCS) integrations.

## Overview

The `generate_wcs_integrations.py` script automates the creation of WCS integration folders and files based on data from a CSV spreadsheet containing integration field definitions.

## Script Features

- **Automatic Folder Creation**: Creates individual `stateless/{integration}` folders for each integration
- **File Generation**: Generates all required files per integration:
  - `docs/README.md`: Integration documentation
  - `docs/fields.csv`: Empty placeholder for field definitions (auto-populated later)
  - `fields/custom/{integration}.yml`: Custom field definitions in YAML format
  - `fields/subset.yml`: Field subset configuration
  - `fields/template-settings.json`: Index template settings
  - `fields/template-settings-legacy.json`: Legacy index template settings
  - `fields/mapping-settings.json`: Mapping configuration settings
- **CSV Parsing**: Reads integration data from spreadsheet format
- **Type Mapping**: Converts Wazuh field types to Elasticsearch field types
- **Log Category Support**: Organizes integrations by log category (general, microsoft, azure, etc.)

## Usage

### Prerequisites

- Python 3.6+
- Required Python packages: `pyyaml` (install with `pip install pyyaml`)

### Basic Usage

```bash
# Generate all integrations from CSV file
python3 generate_wcs_integrations.py /path/to/csv-file.csv --ecs-path /path/to/ecs

# Dry run to see what would be generated
python3 generate_wcs_integrations.py /path/to/csv-file.csv --ecs-path /path/to/ecs --dry-run
```

### Command Line Arguments

- `csv_file`: **Required** - Path to the CSV file containing integration data
- `--ecs-path`: Path to the ECS directory (default: current directory)
- `--template-path`: Path to the template directory (default: ecs-path/stateless/template)
- `--dry-run`: Show what would be generated without creating files

### CSV File Format

The input CSV file must contain the following columns:

| Column               | Description                                           | Required |
| -------------------- | ----------------------------------------------------- | -------- |
| `Elastic Field Name` | Field name in Elastic Common Schema                   | No       |
| `Elastic type`       | Field type in ECS                                     | No       |
| `Wazuh Field Name`   | Custom field name for WCS                             | **Yes**  |
| `Wazuh Type`         | Field type for WCS                                    | **Yes**  |
| `Is array?`          | Whether field can hold multiple values (Yes/No)       | No       |
| `Description`        | Field description                                     | No       |
| `Integration`        | Integration name                                      | **Yes**  |
| `Notes`              | Additional notes                                      | No       |
| `Log category`       | Log category category (e.g., microsoft, azure, cisco) | No       |

## Generated Structure

For each integration, the script creates:

```
stateless/{integration}/
├── docs/
│   ├── README.md           # Integration documentation
│   └── fields.csv          # Field definitions (placeholder)
└── fields/
    ├── custom/
    │   └── {integration}.yml   # Custom field definitions
    ├── subset.yml              # Field subset configuration
    ├── template-settings.json  # Index template settings
    ├── template-settings-legacy.json  # Legacy template settings
    └── mapping-settings.json   # Mapping configuration settings
```

## Example

### Running the Generator

```bash
cd /path/to/wazuh-indexer-plugins/ecs
python3 generate_wcs_integrations.py "fields.csv" --ecs-path .
```

### Example Output

```
🚀 Starting WCS Integrations Generator
==================================================
Reading CSV data from: fields.csv
Loaded 26 integrations
  - snort (Security): 21 fields
  - azure (Cloud): 292 fields
  - windows (System Activity): 71 fields
  ...

Creating folder structure...
Creating folder: stateless/snort
Creating folder: stateless/azure
...

Generating integration files...
Processing integration: snort (category: Security)
  ✓ Created 21 field definitions
  ✓ Generated all required files in stateless/snort
...

✅ Successfully generated 26 integrations
```

## Log Categories

Integrations are organized by log category:

- **Access Management**: User access, authentication and group management
- **Applications**: Application lifecycle, API and web resources activities
- **Cloud Services**: Services managed by cloud providers
- **Network Activity**: DNS, HTTP, Email, SSH, FTP, DHCP, RDP
- **Security**: Security events, threat detection, vulnerability management
- **System Activity**: System monitoring logs
- **Other**: Logs not covered in other categories

## Generated Files Details

### Custom Fields YAML (`fields/custom/{integration}.yml`)

Contains field definitions with:
- Field name and type
- Description
- Example values
- Array indicators where applicable

### Subset Configuration (`fields/subset.yml`)

Defines which ECS fields to include in the index mapping, with the integration's custom fields added.

### Template Settings (`fields/template-settings.json`)

Index template configuration including:
- Index patterns: `wazuh-events-v5-{integration}-*`
- Rollover alias: `wazuh-events-{integration}`
- Default query fields
- Index settings (shards, replicas, etc.)

### Mapping Settings (`fields/mapping-settings.json`)

Elasticsearch mapping configuration including:
- Dynamic mapping: Set to `"false"` to prevent automatic field creation
- Date detection: Disabled to prevent automatic date field detection
- Consistent mapping behavior across all integrations

## Maintenance

### Adding New Integrations

1. Add integration fields to the CSV file
2. Re-run the generator script
3. New integration folders will be created automatically

### Modifying Existing Integrations

1. Update the CSV file with new/modified fields
2. Re-run the generator script
3. Existing files will be overwritten with updated content

### Customizing Templates

Modify files in `stateless/template/` to change the default structure and content for new integrations.

## Troubleshooting

### Common Issues

1. **"CSV file not found"**: Ensure the CSV file path is correct
2. **"ECS directory not found"**: Verify the `--ecs-path` parameter
3. **Permission errors**: Ensure write permissions in the target directory
4. **Missing fields**: Check CSV format and required columns

### Debugging

Use `--dry-run` to preview what would be generated without creating files:

```bash
python3 generate_wcs_integrations.py fields.csv --dry-run
```

## Script Architecture

The generator uses a class-based architecture:

- `WCSIntegrationsGenerator`: Main class handling the generation process
- `read_csv_data()`: Parses CSV input and groups by integration
- `create_folder_structure()`: Creates directory structure  
- `generate_*()`: Methods for generating specific file types
- `write_files_for_integration()`: Orchestrates file creation per integration

## Future Enhancements

Potential improvements:
- Support for additional output formats (JSON, XML)
- Integration validation and testing
- Automatic field documentation generation
- Integration with CI/CD pipelines
- Field conflict detection and resolution