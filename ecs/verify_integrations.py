#!/usr/bin/env python3
"""
Verification script for WCS integrations generator output.

This script validates that all expected files and folders were created correctly.
"""

import os
import json
import yaml
from pathlib import Path


def verify_integration_structure(base_path, integration_name):
    """Verify that an integration has the correct file structure."""
    integration_path = base_path / f"stateless/{integration_name}"
    
    # Check main folders exist
    docs_path = integration_path / "docs"
    fields_path = integration_path / "fields"
    custom_path = fields_path / "custom"
    
    missing_folders = []
    if not docs_path.exists():
        missing_folders.append("docs/")
    if not fields_path.exists():
        missing_folders.append("fields/")
    if not custom_path.exists():
        missing_folders.append("fields/custom/")
    
    # Check required files exist
    required_files = [
        docs_path / "README.md",
        docs_path / "fields.csv",
        fields_path / "subset.yml",
        fields_path / "template-settings.json",
        fields_path / "template-settings-legacy.json",
        fields_path / "mapping-settings.json",
        custom_path / f"{integration_name}.yml"
    ]
    
    missing_files = []
    for file_path in required_files:
        if not file_path.exists():
            missing_files.append(str(file_path.relative_to(integration_path)))
    
    # Validate JSON files are valid
    json_errors = []
    for json_file in [fields_path / "template-settings.json", fields_path / "template-settings-legacy.json", fields_path / "mapping-settings.json"]:
        if json_file.exists():
            try:
                with open(json_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                json_errors.append(f"{json_file.name}: {e}")
    
    # Validate YAML files are valid
    yaml_errors = []
    yaml_files = [fields_path / "subset.yml", custom_path / f"{integration_name}.yml"]
    for yaml_file in yaml_files:
        if yaml_file.exists():
            try:
                with open(yaml_file, 'r') as f:
                    yaml.safe_load(f)
            except yaml.YAMLError as e:
                yaml_errors.append(f"{yaml_file.name}: {e}")
    
    return {
        'integration': integration_name,
        'path': integration_path,
        'missing_folders': missing_folders,
        'missing_files': missing_files,
        'json_errors': json_errors,
        'yaml_errors': yaml_errors,
        'valid': not (missing_folders or missing_files or json_errors or yaml_errors)
    }


def main():
    """Main verification function."""
    base_path = Path(".")
    
    print("🔍 Verifying WCS Integration Generator Output")
    print("=" * 50)
    
    # Find all stateless integration folders
    integration_folders = [d for d in base_path.glob("stateless/*") if d.is_dir() and d.name != "stateless/template"]
    
    if not integration_folders:
        print("❌ No integration folders found!")
        return
    
    print(f"Found {len(integration_folders)} integration folders")
    
    # Verify each integration
    results = []
    for folder in sorted(integration_folders):
        integration_name = folder.name.replace("stateless/", "")
        result = verify_integration_structure(base_path, integration_name)
        results.append(result)
        
        if result['valid']:
            print(f"✅ {integration_name}: OK")
        else:
            print(f"❌ {integration_name}: Issues found")
            if result['missing_folders']:
                print(f"   Missing folders: {', '.join(result['missing_folders'])}")
            if result['missing_files']:
                print(f"   Missing files: {', '.join(result['missing_files'])}")
            if result['json_errors']:
                print(f"   JSON errors: {', '.join(result['json_errors'])}")
            if result['yaml_errors']:
                print(f"   YAML errors: {', '.join(result['yaml_errors'])}")
    
    # Summary
    valid_count = sum(1 for r in results if r['valid'])
    invalid_count = len(results) - valid_count
    
    print("\n" + "=" * 50)
    print(f"📊 Verification Summary:")
    print(f"   ✅ Valid integrations: {valid_count}")
    print(f"   ❌ Invalid integrations: {invalid_count}")
    print(f"   📁 Total integrations: {len(results)}")
    
    if invalid_count == 0:
        print("\n🎉 All integrations are properly structured!")
    else:
        print(f"\n⚠️  {invalid_count} integrations need attention")
    
    return invalid_count == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)