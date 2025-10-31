#!/usr/bin/env python3
"""
WCS Integrations Generator Script

This script automates the generation of Wazuh Common Schema (WCS) integration
folders and files based on data from a CSV spreadsheet.

It creates the necessary folder structure and files for each integration,
including YAML field definitions, JSON template settings, and documentation.
"""

import csv
import json
import yaml
from collections import defaultdict
from pathlib import Path
import argparse
import sys


class WCSIntegrationsGenerator:
    """Main class for generating WCS integration files and folders."""

    def __init__(self, csv_file_path, ecs_base_path, template_path=None):
        """
        Initialize the generator.

        Args:
            csv_file_path: Path to the CSV file containing integration data
            ecs_base_path: Base path for the ECS directory
            template_path: Path to the template directory (optional)
        """
        self.csv_file_path = Path(csv_file_path)
        self.ecs_base_path = Path(ecs_base_path)
        self.template_path = template_path or self.ecs_base_path / "stateless" / "template"

        # Data structure to hold integration information
        self.integrations_data = {}

    def read_csv_data(self):
        """Read and parse the CSV file containing integration data."""
        print(f"Reading CSV data from: {self.csv_file_path}")

        with open(self.csv_file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)

            for row in reader:
                # Skip rows without integration name or Wazuh field name
                integration = row.get('Integration', '').strip()
                wazuh_field_name = row.get('Wazuh field name', '').strip()

                if not integration or not wazuh_field_name:
                    continue

                # Normalize integration name (replace spaces with hyphens, lowercase)
                integration_name = integration.lower().replace(' ', '-')

                # Determine log category (default to 'other' if empty)
                log_category = row.get('Category', '').strip() or 'other'
                log_subcategory = row.get('Subcategory', '').strip() or ''

                # Store integration data using normalized name
                if integration_name not in self.integrations_data:
                    self.integrations_data[integration_name] = {
                        'log_category': f"{log_category}-{log_subcategory}" if log_subcategory else log_category,
                        'log_subcategory': log_subcategory,
                        'original_name': integration,
                        'fields': []
                    }

                # Parse field information including the new Short column
                field_info = {
                    'name': wazuh_field_name,
                    'type': row.get('Wazuh type', 'keyword').strip(),
                    'description': row.get('Description', '').strip(),
                    'short': row.get('Short', '').strip(),
                    'is_array': row.get('Is array?', '').strip().lower() == 'yes',
                }

                self.integrations_data[integration_name]['fields'].append(field_info)

        print(f"Loaded {len(self.integrations_data)} integrations")
        for integration, data in self.integrations_data.items():
            original_name = data.get('original_name', integration)
            print(f"  - {original_name} -> {integration} ({data['log_category']}): {len(data['fields'])} fields")

    def create_folder_structure(self):
        """Create the folder structure for all categories."""
        print("Creating folder structure...")
        # Create folders under stateless/<category>[/<subcategory>]
        categories = set(data['log_category'] for data in self.integrations_data.values())
        for cat in categories:
            # Normalize special two-part sequences into single hyphenated tokens
            # e.g., 'cloud-services-gcp' -> ['cloud-services', 'gcp']
            parts = cat.split('-') if cat else [cat]
            if len(parts) >= 2:
                # join the first two when they match known patterns
                first_two = f"{parts[0]}-{parts[1]}"
                special = {"cloud/services": "cloud-services", "cloud-services": "cloud-services",
                           "network/activity": "network-activity", "network-activity": "network-activity",
                           "system/activity": "system-activity", "system-activity": "system-activity"}

                # check both original slash form and hyphen form
                key_slash = f"{parts[0]}/{parts[1]}"
                if key_slash in special:
                    parts = [special[key_slash]] + parts[2:]
                elif first_two in special:
                    parts = [special[first_two]] + parts[2:]

            # folder structure: stateless/<category>[/<subcategory>...]
            folder_path = self.ecs_base_path / 'stateless' / Path(*parts)

            print(f"Creating folder: {folder_path}")

            # Create main directories
            (folder_path / "docs").mkdir(parents=True, exist_ok=True)
            (folder_path / "fields" / "custom").mkdir(parents=True, exist_ok=True)

            print(f"  Created structure for {cat} integration")

    def generate_custom_fields_yaml(self, integration, integration_data):
        """Generate the custom YAML fields file for an integration."""
        fields = []

        for field_info in integration_data['fields']:
            field_def = {
                'name': field_info['name'],
                'type': field_info['type'],
                'level': 'custom'
            }

            # Add short description if present
            if field_info['short']:
                field_def['short'] = field_info['short']

            # Add description (required)
            description = field_info['description'] or f"Custom field for {integration}"

            # Assign description directly
            field_def['description'] = description

            # Add example if available (use field name as placeholder)
            if field_info['name']:
                # Generate a simple example based on field type
                if field_info['type'] == 'keyword':
                    field_def['example'] = f"example-{field_info['name'].split('.')[-1]}"
                elif field_info['type'] == 'long':
                    field_def['example'] = 12345
                elif field_info['type'] == 'boolean':
                    field_def['example'] = True
                elif field_info['type'] == 'date':
                    field_def['example'] = "2023-01-01T00:00:00.000Z"
                elif field_info['type'] == 'ip':
                    field_def['example'] = "192.168.1.1"

            # Add array indicator if needed
            if field_info['is_array']:
                field_def['normalize'] = ['array']

            fields.append(field_def)

        # Create the YAML structure
        yaml_content = [{
            'name': integration,
            'title': integration.replace('_', ' ').replace('-', ' ').title(),
            'description': f'{integration} custom fields for WCS integration',
            'root': True,
            'fields': fields
        }]

        return yaml_content

    def generate_subset_yaml(self, subset_path, integration, log_category):
        """Generate the subset.yml file for an integration."""
        # Read the subset content from the template or the final file, 
        # depending on existence.
        # In both cases, append the integration fields block, if not present.
        if not subset_path.exists():
            # Read the template subset.yml
            template_subset_path = self.template_path / "fields" / "subset.yml"

            with open(template_subset_path, 'r') as f:
                subset_content = f.read()

            # Replace placeholders
            subset_content = subset_content.replace('<category-name>', log_category)
        else:
            with open(subset_path, 'r') as f:
                subset_content = f.read()

        if f"  {integration}:" in subset_content:
            # Integration already present
            return subset_content
        
        # Append integration fields to the subset
        integration_block = f"""  {integration}:
    fields: "*"
"""
        subset_content += integration_block

        return subset_content

    def generate_template_settings(self, log_category, log_subcategory):
        """Generate template-settings.json for an integration."""
        template_settings_path = self.template_path / "fields" / "template-settings.json"

        with open(template_settings_path, 'r') as f:
            settings = json.load(f)
        # Build index pattern name using hyphen-joined category/subcategory (original log_category)
        index_name = log_category
        settings['index_patterns'] = [f"wazuh-events-v5-{index_name}-*"]
        settings['template']['settings']['plugins.index_state_management.rollover_alias'] = f"wazuh-events-v5-{index_name}"
        settings['priority'] = 10 if log_subcategory else 1

        return settings

    def generate_template_settings_legacy(self, log_category, log_subcategory):
        """Generate template-settings-legacy.json for an integration."""
        template_settings_path = self.template_path / "fields" / "template-settings-legacy.json"

        with open(template_settings_path, 'r') as f:
            settings = json.load(f)
    # Build index pattern name using hyphen-joined category/subcategory (original log_category)
        index_name = log_category
        settings['index_patterns'] = [f"wazuh-events-v5-{index_name}-*"]
        settings['settings']['plugins.index_state_management.rollover_alias'] = f"wazuh-events-v5-{index_name}"
        settings['order'] = 10 if log_subcategory else 1

        return settings

    def generate_mapping_settings(self):
        """Generate mapping-settings.json for an integration."""
        template_mapping_path = self.template_path / "fields" / "mapping-settings.json"

        with open(template_mapping_path, 'r') as f:
            settings = json.load(f)

        # The mapping settings are typically the same for all integrations
        # but we return a copy to allow for future customization
        return settings

    def generate_readme(self, integration_data):
        """Generate README.md for an integration."""
        log_category = integration_data['log_category']
        integrations = [data['original_name'] for _, data in self.integrations_data.items() if data['log_category'] == log_category]
        integrations_list = '\n'.join(f"- {name}" for name in sorted(integrations))

        readme_content = f"""## `wazuh-events-v5-{log_category}` time series index

The `wazuh-events-v5-{log_category}` indices store events received from monitored endpoints through the relevant integrations.

This is a time-based (stateless) index. The index includes the WCS fields and the fields of the corresponding {log_category} integrations.

### Fields summary

For this stage, we are using all the fields of the WCS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [WCS main mappings](../../main/docs/fields.csv)

The detail of the fields can be found in csv file [Stateless {log_category.title()} Fields](fields.csv).

### Integrations:

The **{log_category}** log category provides specialized fields for processing events in the Wazuh security platform coming from these integrations:
{integrations_list}
"""
        return readme_content

    def write_files_for_integration(self, integration, integration_data):
        """Write all files for a specific integration."""
        log_category = integration_data['log_category']
        log_subcategory = integration_data['log_subcategory']
        # Build folder path under stateless/<category>[/<subcategory>...]
        parts = log_category.split('-') if log_category else [log_category]
        if len(parts) >= 2:
            key_slash = f"{parts[0]}/{parts[1]}"
            first_two = f"{parts[0]}-{parts[1]}"
            special = {"cloud/services": "cloud-services", "cloud-services": "cloud-services",
                       "network/activity": "network-activity", "network-activity": "network-activity",
                       "system/activity": "system-activity", "system-activity": "system-activity"}

            if key_slash in special:
                parts = [special[key_slash]] + parts[2:]
            elif first_two in special:
                parts = [special[first_two]] + parts[2:]

        base_path = self.ecs_base_path / 'stateless' / Path(*parts)

        print(f"  Generating files for {integration} integration...")

        # 1. Generate custom fields YAML
        custom_fields = self.generate_custom_fields_yaml(integration, integration_data)
        custom_yaml_path = base_path / "fields" / "custom" / f"{integration}.yml"

        # Custom YAML dumper to handle multi-line strings properly
        yaml.add_representer(str, self._str_presenter)

        with open(custom_yaml_path, 'w') as f:
            yaml.dump(custom_fields, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

        # 2. Generate subset.yml
        subset_path = base_path / "fields" / "subset.yml"
        subset_content = self.generate_subset_yaml(subset_path, integration, log_category)

        with open(subset_path, 'w') as f:
            f.write(subset_content)

        # 3. Generate template-settings.json
        template_settings = self.generate_template_settings(log_category, log_subcategory)
        template_settings_path = base_path / "fields" / "template-settings.json"

        with open(template_settings_path, 'w') as f:
            json.dump(template_settings, f, indent=2)

        # 4. Generate template-settings-legacy.json
        template_settings_legacy = self.generate_template_settings_legacy(log_category, log_subcategory)
        template_settings_legacy_path = base_path / "fields" / "template-settings-legacy.json"

        with open(template_settings_legacy_path, 'w') as f:
            json.dump(template_settings_legacy, f, indent=2)

        # 5. Generate mapping-settings.json
        mapping_settings = self.generate_mapping_settings()
        mapping_settings_path = base_path / "fields" / "mapping-settings.json"

        with open(mapping_settings_path, 'w') as f:
            json.dump(mapping_settings, f, indent=2)

        # 6. Generate README.md
        readme_content = self.generate_readme(integration_data)
        readme_path = base_path / "docs" / "README.md"

        with open(readme_path, 'w') as f:
            f.write(readme_content)

        # 7. Create empty fields.csv (to be filled automatically)
        fields_csv_path = base_path / "docs" / "fields.csv"
        with open(fields_csv_path, 'w') as f:
            f.write("# This file will be automatically populated with field definitions\n")

        print(f"    ✓ Created {len(integration_data['fields'])} field definitions")
        print(f"    ✓ Generated all required files in {base_path}")

    def _str_presenter(self, dumper, data):
        """Custom YAML presenter for multi-line strings."""
        if '\n' in data or len(data) > 80:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='>')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    def generate_all_integrations(self):
        """Generate all integration files and folders."""
        print("\nGenerating integration files...")

        # Process each integration individually
        total_integrations = 0
        for integration, integration_data in self.integrations_data.items():
            log_category = integration_data['log_category']
            print(f"\nProcessing integration: {integration} (category: {log_category})")

            self.write_files_for_integration(integration, integration_data)
            total_integrations += 1

        print(f"\n✅ Successfully generated {total_integrations} integrations")
        print(f"📁 Files created in: {self.ecs_base_path}")

    def run(self):
        """Run the complete generation process."""
        print("🚀 Starting WCS Integrations Generator")
        print("=" * 50)

        try:
            # Step 1: Read CSV data
            self.read_csv_data()

            # Step 2: Create folder structure
            self.create_folder_structure()

            # Step 3: Generate all integration files
            self.generate_all_integrations()

            print("\n" + "=" * 50)
            print("✅ WCS Integrations generation completed successfully!")
            print(f"📊 Generated {len(self.integrations_data)} integrations")

            # Summary by log category
            log_categories = defaultdict(int)
            for integration, data in self.integrations_data.items():
                log_categories[data['log_category']] += 1

            print("\n📋 Summary by log category:")
            for category, count in sorted(log_categories.items()):
                print(f"  - {category}: {count} integration(s)")

        except Exception as e:
            print(f"\n❌ Error during generation: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(
        description="Generate WCS integration files and folders from CSV data"
    )
    parser.add_argument(
        "csv_file",
        help="Path to the CSV file containing integration data"
    )
    parser.add_argument(
        "--ecs-path",
        default=".",
        help="Path to the ECS directory (default: current directory)"
    )
    parser.add_argument(
        "--template-path",
        help="Path to the template directory (default: ecs-path/stateless-template)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be generated without creating files"
    )

    args = parser.parse_args()

    # Validate paths
    csv_path = Path(args.csv_file)
    if not csv_path.exists():
        print(f"❌ CSV file not found: {csv_path}")
        sys.exit(1)

    ecs_path = Path(args.ecs_path)
    if not ecs_path.exists():
        print(f"❌ ECS directory not found: {ecs_path}")
        sys.exit(1)

    # Initialize and run generator
    generator = WCSIntegrationsGenerator(
        csv_file_path=csv_path,
        ecs_base_path=ecs_path,
        template_path=args.template_path
    )

    if args.dry_run:
        print("🔍 DRY RUN MODE - No files will be created")
        generator.read_csv_data()
        print("\nIntegrations that would be generated:")
        for integration, data in generator.integrations_data.items():
            print(f"  - {integration} ({data['log_category']}): {len(data['fields'])} fields")
    else:
        generator.run()


if __name__ == "__main__":
    main()
