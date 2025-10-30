#!/usr/bin/env python3
"""
ECS YAML Modifier Script

This script modifies ECS YAML field definition files to replace unsupported 
field types with Wazuh-compatible alternatives before the schema generation.
"""

import yaml
import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime

# Type mappings from ECS types to Wazuh-compatible types
TYPE_MAPPINGS = {
    'constant_keyword': 'keyword',
    'wildcard': 'keyword',
    'match_only_text': 'keyword',
    'flattened': 'flat_object',
    # Add more mappings as needed
    # 'scaled_float': 'float',  # Commented as per your current script
}

# Special field handling for gen_ai nested fields
SPECIFIC_OBJECTS_TYPE_MAPPINGS = {
    'gen_ai.request.encoding_formats': 'keyword',
    'gen_ai.request.stop_sequences': 'keyword',
    'gen_ai.response.finish_reasons': 'keyword'
}

# Default search patterns for YAML files
DEFAULT_SEARCH_PATTERNS = [
    "schemas/**/*.yml",
    "schemas/**/*.yaml"
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


class SchemaSanitizer:
    def __init__(self, ecs_source_path: str, dry_run: bool = False, log_file: Optional[str] = None):
        self.ecs_source_path = Path(ecs_source_path)
        self.dry_run = dry_run
        self.log_file = log_file
        self.stats = ModificationStats()
        self.logger = logging.getLogger(__name__)
        self.modified_files: Set[Path] = set()

    def modify_field_type(self, field_data: Dict[str, Any], field_path: str = "") -> bool:
        """
        Recursively modify field types in a field definition.
        Returns True if any modifications were made.
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

        return modified

    def remove_multi_fields(self, field_data: Dict[str, Any]) -> bool:
        """
        Remove multi-fields (.fields) from field definitions.
        Returns True if any modifications were made.
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
        Returns True if the file was modified.
        """
        try:
            # Read the file
            with open(yaml_file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                self.logger.debug(f"Skipping empty file: {yaml_file_path}")
                return False

            # Track modifications
            modified = False

            # Process the YAML structure
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if self.modify_field_type(item):
                            modified = True
                        if self.remove_multi_fields(item):
                            modified = True
            elif isinstance(data, dict):
                if self.modify_field_type(data):
                    modified = True
                if self.remove_multi_fields(data):
                    modified = True

            # Write back the modified data if changes were made
            if modified:
                if self.dry_run:
                    self.logger.info(f"[DRY RUN] Would modify: {yaml_file_path}")
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

    def find_and_modify_yaml_files(self, search_patterns: Optional[List[str]] = None) -> int:
        """
        Find and modify YAML files in the ECS source directory.
        """
        if search_patterns is None:
            search_patterns = DEFAULT_SEARCH_PATTERNS

        self.logger.info(f"Searching for YAML files in: {self.ecs_source_path}")
        print(f"Searching for YAML files in: {self.ecs_source_path}")
        
        # Collect all files first to show progress
        all_files = []
        for pattern in search_patterns:
            for yaml_file in self.ecs_source_path.glob(pattern):
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
            
            self.logger.debug(f"Processing: {yaml_file.relative_to(self.ecs_source_path)}")

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

    def print_summary(self):
        """Print user-friendly summary and detailed logs"""
        # User-friendly console output
        print("\n" + "=" * 50)
        print("SUMMARY")
        print("=" * 50)
        print(f"Processed files: {self.stats.processed_files}")
        print(f"Modified files: {self.stats.modified_files}")
        
        if self.stats.modified_files > 0:
            print(f"Field type changes: {self.stats.field_type_changes}")
            print(f"Specific fixes: {self.stats.specific_fixes}")
            print(f"Multi-field removals: {self.stats.multi_field_removals}")
        
        if self.dry_run:
            print("DRY RUN MODE - No files were actually modified")
        
        if self.log_file:
            print(f"Detailed logs saved to: {self.log_file}")
        
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
        self.logger.info(f"  Total modifications: {self.stats.total_modifications}")
        
        if self.dry_run:
            self.logger.info("  ** DRY RUN MODE - No files were actually modified **")
        
        if self.modified_files:
            self.logger.info(f"Modified files: {sorted(self.modified_files)}")

        return self.stats.modified_files


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Configure logging for the application"""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(numeric_level)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Always add file handler if log_file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Save all details to file
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Add console handler only for WARNING and above (or if no log file)
    if not log_file or log_level.upper() in ['DEBUG', 'INFO']:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.WARNING if log_file else numeric_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Modify ECS YAML files to replace unsupported field types with Wazuh-compatible alternatives"
    )
    parser.add_argument(
        "--source-path",
        default=".",
        help="Path to the ECS source directory"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be modified without making changes"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)"
    )
    parser.add_argument(
        "--log-file",
        help="Save detailed logs to file (default: auto-generated filename)"
    )
    parser.add_argument(
        "--patterns",
        nargs="+",
        help="Custom search patterns for YAML files"
    )
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()
    
    # Generate log file name if not provided
    if args.log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.log_file = f"ecs_sanitizer_{timestamp}.log"
    
    setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger(__name__)

    if not os.path.exists(args.source_path):
        print(f"Error: ECS source path does not exist: {args.source_path}")
        logger.error(f"ECS source path does not exist: {args.source_path}")
        sys.exit(1)

    print("ECS YAML Sanitizer")
    print("=" * 50)
    logger.info("ECS YAML Sanitizer Started")
    logger.info("=" * 50)
    
    if args.dry_run:
        print("DRY RUN MODE - No files will be modified")
        logger.info("DRY RUN MODE - No files will be modified")

    print(f"Source directory: {args.source_path}")
    print(f"Detailed logs: {args.log_file}")

    modifier = SchemaSanitizer(
        ecs_source_path=args.source_path,
        dry_run=args.dry_run,
        log_file=args.log_file
    )
    
    try:
        modified_count = modifier.find_and_modify_yaml_files(args.patterns)

        if modified_count > 0:
            if args.dry_run:
                print(f"\nWould modify {modified_count} YAML files")
                logger.info(f"Would modify {modified_count} YAML files")
            else:
                print(f"\nSuccessfully modified {modified_count} YAML files")
                logger.info(f"Successfully modified {modified_count} YAML files")
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
