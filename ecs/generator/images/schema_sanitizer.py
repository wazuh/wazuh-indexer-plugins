import yaml
import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Set
from dataclasses import dataclass
from datetime import datetime

LOG_FILE = f"schema_sanitizer.log"

# Type mappings from ECS types to Wazuh-compatible types
TYPE_MAPPINGS = {
    'constant_keyword': 'keyword',
    'wildcard': 'keyword',
    'match_only_text': 'keyword',
    'flattened': 'flat_object',
}

# Special field handling for gen_ai nested fields
SPECIFIC_OBJECTS_TYPE_MAPPINGS = {
    'gen_ai.request.encoding_formats': 'keyword',
    'gen_ai.request.stop_sequences': 'keyword',
    'gen_ai.response.finish_reasons': 'keyword'
}

# Default search patterns for YAML files
SEARCH_PATTERNS = [
    "schemas/**/*.yml",
    "schemas/**/*.yaml",
    "**/schemas/**/*.yml",
    "**/schemas/**/*.yaml",
    "generated/**/*.yml",
    "generated/**/*.yaml",
    "**/generated/**/*.yml",
    "**/generated/**/*.yaml",
    "rfcs/**/*.yml",
    "rfcs/**/*.yaml",
]

FIELDS_TO_REMOVE = [
    # Multi-fields to be removed - Already covered by remove_multi_fields method
    # "agent.host.os.full.fields",
    # "agent.host.os.name.fields",
    # "host.os.full.fields",
    # "host.os.name.fields",
    # "vulnerability.description.fields",
    # "process.command_line.fields",
    # "process.name.fields",
    # "vulnerability.description.fields",
    # "file.path.fields",
    # "user.name.fields",
    # "user.full_name.fields",
    # "process.user.name.fields",
    # "process.executable.fields",
    # "process.working_directory.fields",
    # Simple fields to be removed
    "synthetic_source_keep",
    "tags",
    "@timestamp",
    ]

@dataclass
class ModificationStats:
    """Statistics for tracking modifications"""
    processed_files: int = 0
    modified_files: int = 0
    total_modifications: int = 0
    field_type_changes: int = 0
    scaling_factor_removals: int = 0
    multi_field_removals: int = 0
    specific_fixes: int = 0
    fields_removed: int = 0


class SchemaSanitizer:
    def __init__(self, source_path: str, logger: logging.Logger, dry_run: bool = False):
        self.source_path = Path(source_path)
        self.dry_run = dry_run
        self.stats = ModificationStats()
        self.modified_files: Set[Path] = set()
        self.logger = logger

    def modify_field_type(self, field_data: Dict[str, Any], field_path: str = "") -> bool:
        """
        Recursively modify field types in a field definition.

        Args:
            field_data (Dict[str, Any]): The field definition data.
            field_path (str): The dot-separated path to the current field.

        Returns:
            bool: True if any modifications were made, False otherwise.
        """
        modified = False

        if not isinstance(field_data, dict):
            return False

        # Check if this is a field definition with a type
        if 'type' in field_data:
            original_type = field_data['type']

            # Apply specific fixes
            if field_path in SPECIFIC_OBJECTS_TYPE_MAPPINGS:
                field_data['type'] = SPECIFIC_OBJECTS_TYPE_MAPPINGS[field_path]
                self.logger.debug(
                    f"Fixed field: {field_path} ({original_type} -> {field_data['type']})")
                self.stats.specific_fixes += 1
                modified = True
            # Apply general type mappings
            elif original_type in TYPE_MAPPINGS:
                field_data['type'] = TYPE_MAPPINGS[original_type]
                self.logger.debug(
                    f"Modified field: {field_path} ({original_type} -> {field_data['type']})")
                self.stats.field_type_changes += 1
                modified = True

        # Process multi_fields (these can have their own types)
        if 'multi_fields' in field_data and isinstance(field_data['multi_fields'], list):
            for multi_field in field_data['multi_fields']:
                if isinstance(multi_field, dict) and 'type' in multi_field:
                    original_type = multi_field['type']
                    if original_type in TYPE_MAPPINGS:
                        multi_field['type'] = TYPE_MAPPINGS[original_type]
                        multi_field_path = f"{field_path}.{multi_field.get('name', 'multi_field')}"
                        self.logger.debug(
                            f"Modified multi-field: {multi_field_path} ({original_type} -> {multi_field['type']})")
                        self.stats.field_type_changes += 1
                        modified = True

        # Recursively process nested fields
        if 'fields' in field_data and isinstance(field_data['fields'], list):
            for field in field_data['fields']:
                if isinstance(field, dict):
                    field_name = field.get('name', '')
                    nested_path = f"{field_path}.{field_name}" if field_path else field_name
                    if self.modify_field_type(field, nested_path):
                        modified = True

        # Process properties in field definitions
        if 'properties' in field_data and isinstance(field_data['properties'], dict):
            for prop_name, prop_data in field_data['properties'].items():
                nested_path = f"{field_path}.{prop_name}" if field_path else prop_name
                if self.modify_field_type(prop_data, nested_path):
                    modified = True

        # Process other nested structures that might contain field definitions
        for key, value in field_data.items():
            if key not in ['fields', 'properties', 'multi_fields', 'type', 'name']:
                if isinstance(value, dict):
                    nested_path = f"{field_path}.{key}" if field_path else key
                    if self.modify_field_type(value, nested_path):
                        modified = True
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            nested_path = f"{field_path}.{key}[{i}]" if field_path else f"{key}[{i}]"
                            if self.modify_field_type(item, nested_path):
                                modified = True

        return modified

    def remove_unwanted_fields(self, data: Dict[str, Any], field_path: str = "") -> bool:
        """
        Remove unwanted fields specified in FIELDS_TO_REMOVE.
        
        Args:
            data (Dict[str, Any]): The YAML data structure.
            field_path (str): The current field path.
            
        Returns:
            bool: True if any modifications were made, False otherwise.
        """
        modified = False
        
        if not isinstance(data, dict):
            return False
        
        # Remove simple properties like 'synthetic_source_keep'
        properties_to_remove = []
        for key in data.keys():
            if key in FIELDS_TO_REMOVE:
                properties_to_remove.append(key)
        
        for prop in properties_to_remove:
            del data[prop]
            self.logger.debug(f"Removed property: {prop} from {field_path}")
            self.stats.fields_removed += 1
            modified = True
        
        # Handle 'fields' arrays - remove field definitions by name
        if 'fields' in data and isinstance(data['fields'], list):
            original_count = len(data['fields'])
            data['fields'] = [
                field for field in data['fields'] 
                if not (isinstance(field, dict) and field.get('name') in FIELDS_TO_REMOVE)
            ]
            removed_count = original_count - len(data['fields'])
            if removed_count > 0:
                self.logger.debug(f"Removed {removed_count} field definitions from {field_path}")
                self.stats.fields_removed += removed_count
                modified = True
        
        # Recursively process nested structures
        for key, value in data.items():
            current_field_path = f"{field_path}.{key}" if field_path else key
            
            if isinstance(value, dict):
                if self.remove_unwanted_fields(value, current_field_path):
                    modified = True
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        if self.remove_unwanted_fields(item, current_field_path):
                            modified = True
                            
        return modified

    def remove_multi_fields(self, field_data: Dict[str, Any]) -> bool:
        """
        Remove multi-fields (.fields) from field definitions.

        Args:
            field_data (Dict[str, Any]): The field definition data.

        Returns:
            bool: True if any modifications were made, False otherwise.
        """
        modified = False

        if not isinstance(field_data, dict):
            return False

        # Remove .fields property if it exists and is a dict
        if 'fields' in field_data and isinstance(field_data['fields'], dict):
            del field_data['fields']
            self.logger.debug("Removed multi-fields from field definition")
            self.stats.multi_field_removals += 1
            modified = True

        # Recursively process nested structures
        for key, value in field_data.items():
            if isinstance(value, dict):
                if self.remove_multi_fields(value):
                    modified = True
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        if self.remove_multi_fields(item):
                            modified = True

        return modified

    def modify_yaml_file(self, yaml_file_path: Path) -> bool:
        """
        Modify a single YAML file.
        Args:
            yaml_file_path (Path): Path to the YAML file.

        Returns:
            bool: True if the file was modified, False otherwise.
        """
        modified = False

        try:
            # Read the file
            with open(yaml_file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                self.logger.debug(f"Skipping empty file: {yaml_file_path}")
                return False

            # Process the YAML structure
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if self.modify_field_type(item):
                            modified = True
                        if self.remove_multi_fields(item):
                            modified = True
                        if self.remove_unwanted_fields(item):
                            modified = True
            elif isinstance(data, dict):
                if self.modify_field_type(data):
                    modified = True
                if self.remove_multi_fields(data):
                    modified = True
                if self.remove_unwanted_fields(data):
                    modified = True

            # Write back the modified data if changes were made
            if modified:
                if self.dry_run:
                    print(f"  [DRY RUN] Would modify: {yaml_file_path.name}")
                    return True

                # Write the modified file
                with open(yaml_file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                              allow_unicode=True, width=1000, indent=2)

                self.stats.modified_files += 1
                self.stats.total_modifications += 1
                self.modified_files.add(yaml_file_path)
                print(f"  Modified: {yaml_file_path.name}")
                return True

        except yaml.YAMLError as e:
            self.logger.error(f"YAML parsing error in {yaml_file_path}: {e}")
            return False
        except PermissionError as e:
            self.logger.error(f"Permission denied accessing {yaml_file_path}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error processing {yaml_file_path}: {e}")
            return False

        return False

    def find_and_modify_yaml_files(self) -> int:
        """
        Find and modify YAML files in the ECS source directory.

        Returns:
            int: Number of modified files.
        """
        self.logger.info(f"Searching for YAML files in: {self.source_path}")
        print(f"Searching for YAML files in: {self.source_path}")

        # Collect all files first to show progress
        all_files = []
        for pattern in SEARCH_PATTERNS:
            for yaml_file in self.source_path.glob(pattern):
                if yaml_file.is_file():
                    all_files.append(yaml_file)

        self.logger.info(f"Found {len(all_files)} YAML files to process")
        print(f"Found {len(all_files)} YAML files to process")

        # Process files with progress indication
        for i, yaml_file in enumerate(all_files, 1):
            self.stats.processed_files += 1

            if len(all_files) > 10:  # Show progress for large operations
                if i % max(1, len(all_files) // 10) == 0:
                    progress_pct = int((i / len(all_files)) * 100)
                    print(f"Progress: {progress_pct}% ({i}/{len(all_files)} files)")

            self.logger.debug(f"Processing: {yaml_file.relative_to(self.source_path)}")

            if self.modify_yaml_file(yaml_file):
                self.logger.debug(f"Modified file: {yaml_file}")
            else:
                self.logger.debug(f"No changes needed on file: {yaml_file}")

        # For large operations show completion
        if len(all_files) > 10:
            print(f"Progress: 100% ({len(all_files)}/{len(all_files)} files)")

        # Print detailed summary
        self.print_summary()
        return self.stats.modified_files

    def print_summary(self) -> int:
        """
        Print summary and detailed logs

        Returns:
            int: Number of modified files.
        """
        print("\n" + "=" * 50)
        print("SUMMARY")
        print("=" * 50)
        print(f"Processed files: {self.stats.processed_files}")
        print(f"Modified files: {self.stats.modified_files}")

        if self.stats.modified_files > 0:
            print(f"Field type changes: {self.stats.field_type_changes}")
            print(f"Specific fixes: {self.stats.specific_fixes}")
            print(f"Multi-field removals: {self.stats.multi_field_removals}")
            print(f"Fields removed: {self.stats.fields_removed}")

        if self.dry_run:
            print("DRY RUN MODE - No files were actually modified")

        print(f"Detailed logs saved to: {LOG_FILE}")
        # Detailed logs to file and logger
        self.logger.info("=" * 60)
        self.logger.info("DETAILED MODIFICATION SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"  Processed files: {self.stats.processed_files}")
        self.logger.info(f"  Modified files: {self.stats.modified_files}")
        self.logger.info(f"  Field type changes: {self.stats.field_type_changes}")
        self.logger.info(f"  Specific fixes: {self.stats.specific_fixes}")
        self.logger.info(f"  Scaling factor removals: {self.stats.scaling_factor_removals}")
        self.logger.info(f"  Multi-field removals: {self.stats.multi_field_removals}")
        self.logger.info(f"  Fields removed: {self.stats.fields_removed}")
        self.logger.info(f"  Total modifications: {self.stats.total_modifications}")

        if self.dry_run:
            self.logger.info("  ** DRY RUN MODE - No files were actually modified **")

        if self.modified_files:
            self.logger.info(f"Modified files: {sorted(self.modified_files)}")

        return self.stats.modified_files


def get_logger(log_dir: str) -> logging.Logger:
    """Configure logging for the application"""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # File handler for logging to a file
    file_handler = logging.FileHandler(os.path.join(log_dir, LOG_FILE), mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    # Console handler for logging to stdout
    console_handler = logging.StreamHandler(sys.stdout)
    # Only show warnings and errors on console
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Sanitize ECS YAML files replacing unsupported field types with Wazuh-compatible alternatives"
    )
    parser.add_argument(
        "--source",
        default=".",
        help="Path to the ECS source directory"
    )
    parser.add_argument(
        "--log-dir",
        default=".",
        help="Directory to save log files"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be modified without making changes"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()
    logger = get_logger(args.log_dir)

    if not os.path.exists(args.source):
        print(f"Error: ECS source path does not exist: {args.source}")
        logger.error(f"ECS source path does not exist: {args.source}")
        sys.exit(1)

    print("ECS YAML Sanitizer")
    print("=" * 50)
    logger.info("ECS YAML Sanitizer Started")
    logger.info("=" * 50)

    if args.dry_run:
        print("DRY RUN MODE - No files will be modified")
        logger.info("DRY RUN MODE - No files will be modified")

    print(f"Source directory: {args.source}")

    modifier = SchemaSanitizer(
        source_path=args.source,
        logger=logger,
        dry_run=args.dry_run
    )

    try:
        modified_count = modifier.find_and_modify_yaml_files()
        if modified_count > 0:
            if args.dry_run:
                print(f"\nWould modify {modified_count} YAML files")
                logger.info(f"Would modify {modified_count} YAML files")
            else:
                print(f"\nSuccessfully modified {modified_count} YAML files")
                logger.info(
                    f"Successfully modified {modified_count} YAML files")
        else:
            print("\nNo modifications were needed")
            logger.info("No modifications were needed")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        logger.warning("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
