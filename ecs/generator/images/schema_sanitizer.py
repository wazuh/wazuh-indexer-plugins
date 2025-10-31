#!/usr/bin/env python3

# WCS Sanitizer tool
# This tool processes ECS YAML files to replace unsupported field types
# with Wazuh-compatible alternatives, removes multi-fields, and eliminates
# unwanted fields. It provides detailed logging and a summary of modifications.

import yaml
import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Set
from dataclasses import dataclass

LOG_FILE = f"schema_sanitizer.log"

# File search patterns for ECS YAML files
SEARCH_PATTERNS = [
    "schemas/**/*.yml",
    "**/schemas/**/*.yml",
    "generated/**/*.yml",
    "**/generated/**/*.yml",
]

# Type mappings from ECS types to WCS-compatible types
TYPES_TO_REMAP = {
    'constant_keyword': 'keyword',
    'wildcard': 'keyword',
    'match_only_text': 'keyword',
    'flattened': 'flat_object',
}

# Specific field type remappings
OBJECT_TYPES_TO_REMAP = {
    'gen_ai.request.encoding_formats': 'keyword',
    'gen_ai.request.stop_sequences': 'keyword',
    'gen_ai.response.finish_reasons': 'keyword'
}

# Fields to be removed from the schema
FIELDS_TO_REMOVE = [
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
        self.log = logger

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
            if field_path in OBJECT_TYPES_TO_REMAP:
                field_data['type'] = OBJECT_TYPES_TO_REMAP[field_path]
                self.log.debug(f"Fixed field: {field_path} ({original_type} -> {field_data['type']})")
                self.stats.specific_fixes += 1
                modified = True
            # Apply general type mappings
            elif original_type in TYPES_TO_REMAP:
                field_data['type'] = TYPES_TO_REMAP[original_type]
                self.log.debug(f"Modified field: {field_path} ({original_type} -> {field_data['type']})")
                self.stats.field_type_changes += 1
                modified = True

        # Process multi_fields (these can have their own types)
        if 'multi_fields' in field_data and isinstance(field_data['multi_fields'], list):
            for multi_field in field_data['multi_fields']:
                if isinstance(multi_field, dict) and 'type' in multi_field:
                    original_type = multi_field['type']
                    if original_type in TYPES_TO_REMAP:
                        multi_field['type'] = TYPES_TO_REMAP[original_type]
                        multi_field_path = f"{field_path}.{multi_field.get('name', 'multi_field')}"
                        self.log.debug(f"Modified multi-field: {multi_field_path} ({original_type} -> {multi_field['type']})")
                        self.stats.field_type_changes += 1
                        modified = True

        # Recursively process nested fields
        if 'fields' in field_data and isinstance(field_data['fields'], list):
            for field in field_data['fields']:
                if isinstance(field, dict):
                    field_name = field.get('name', '')
                    # Handle group-level fields by including the group name in the path
                    if field_path == "" and 'name' in field_data and field_data.get('type') == 'group':
                        # This is a top-level group, so construct the full path
                        group_name = field_data.get('name', '')
                        nested_path = f"{group_name}.{field_name}" if group_name else field_name
                    else:
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

        # Remove simple properties
        properties_to_remove = []
        for key in data.keys():
            if key in FIELDS_TO_REMOVE:
                properties_to_remove.append(key)

        for prop in properties_to_remove:
            del data[prop]
            self.log.debug(f"Removed property: {prop} from {field_path}")
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
                self.log.debug(f"Removed {removed_count} field definitions from {field_path}")
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

        # Remove multi_fields property (array of multi-field definitions)
        if 'multi_fields' in field_data:
            del field_data['multi_fields']
            self.log.debug("Removed multi_fields array from field definition")
            self.stats.multi_field_removals += 1
            modified = True

        # Remove .fields property if it exists (both dict and list formats)
        if 'fields' in field_data:
            if isinstance(field_data['fields'], dict):
                del field_data['fields']
                self.log.debug("Removed multi-fields dict from field definition")
                self.stats.multi_field_removals += 1
                modified = True
            # Note: Don't remove 'fields' when it's a list, as that contains nested field definitions

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
                self.log.debug(f"Skipping empty file: {yaml_file_path}")
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
                # Write the modified file
                with open(yaml_file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                              allow_unicode=True, width=1000, indent=2)

                self.stats.modified_files += 1
                self.stats.total_modifications += 1
                self.modified_files.add(yaml_file_path)
                return True

        except yaml.YAMLError as e:
            self.log.error(f"YAML parsing error in {yaml_file_path}: {e}")
            return False
        except PermissionError as e:
            self.log.error(f"Permission denied accessing {yaml_file_path}: {e}")
            return False
        except Exception as e:
            self.log.error(f"Unexpected error processing {yaml_file_path}: {e}")
            return False

        return False

    def find_and_modify_yaml_files(self) -> int:
        """
        Find and modify YAML files in the ECS source directory.

        Returns:
            int: Number of modified files.
        """
        self.log.info(f"Searching for YAML files in: {self.source_path}")

        # Collect all files first to show progress
        all_files = []
        for pattern in SEARCH_PATTERNS:
            for yaml_file in self.source_path.glob(pattern):
                if yaml_file.is_file():
                    all_files.append(yaml_file)

        self.log.info(f"Found {len(all_files)} YAML files to process")

        # Process files with progress indication
        for i, yaml_file in enumerate(all_files, 1):
            self.stats.processed_files += 1

            self.log.debug(f"Processing: {yaml_file.relative_to(self.source_path)}")

            if self.modify_yaml_file(yaml_file):
                self.log.debug(f"Modified file: {yaml_file}")
            else:
                self.log.debug(f"No changes needed on file: {yaml_file}")

        # Log detailed summary
        self.show_summary()
        return self.stats.modified_files

    def show_summary(self) -> None:
        """
        Logs a detailed summary of the performed modifications.
        """
        # Detailed logs to file and logger
        self.log.info("=" * 60)
        self.log.info("DETAILED MODIFICATION SUMMARY")
        self.log.info("=" * 60)
        self.log.info(f"  Processed files: {self.stats.processed_files}")
        self.log.info(f"  Modified files: {self.stats.modified_files}")
        self.log.info(f"  Field type changes: {self.stats.field_type_changes}")
        self.log.info(f"  Specific fixes: {self.stats.specific_fixes}")
        self.log.info(f"  Scaling factor removals: {self.stats.scaling_factor_removals}")
        self.log.info(f"  Multi-field removals: {self.stats.multi_field_removals}")
        self.log.info(f"  Fields removed: {self.stats.fields_removed}")
        self.log.info(f"  Total modifications: {self.stats.total_modifications}")

        if self.dry_run:
            self.log.info("  ** DRY RUN MODE - No files were actually modified **")

        if self.modified_files:
            self.log.info(f"Modified files: {sorted(self.modified_files)}")


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
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments

    Returns:
        argparse.Namespace: Parsed arguments
    """
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


def main() -> None:
    args = parse_arguments()
    logger = get_logger(args.log_dir)

    if not os.path.exists(args.source):
        logger.error(f"ECS source path does not exist: {args.source}")
        sys.exit(1)

    logger.info("ECS YAML Sanitizer Started")
    logger.info("=" * 50)

    if args.dry_run:
        logger.info("DRY RUN MODE - No files will be modified")

    modifier = SchemaSanitizer(args.source, logger, args.dry_run)

    try:
        modified_count = modifier.find_and_modify_yaml_files()
        if modified_count > 0:
            if args.dry_run:
                logger.info(f"Would modify {modified_count} YAML files")
            else:
                logger.info(f"Successfully modified {modified_count} YAML files")
        else:
            logger.info("No modifications were needed")

    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
