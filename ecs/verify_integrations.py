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
    ]

    # For custom files, accept any .yml file inside fields/custom
    custom_yaml_files = []
    if custom_path.exists() and custom_path.is_dir():
        for p in custom_path.iterdir():
            if p.is_file() and p.suffix.lower() == '.yml':
                custom_yaml_files.append(p)
    
    missing_files = []
    for file_path in required_files:
        if not file_path.exists():
            missing_files.append(str(file_path.relative_to(integration_path)))

    # If no custom yml files found, mark the expected custom file as missing
    if not custom_yaml_files:
        missing_files.append(str((custom_path / f"{integration_name}.yml").relative_to(integration_path)))
    
    # Validate JSON files are valid
    json_errors = []
    for json_file in [fields_path / "template-settings.json", fields_path / "template-settings-legacy.json", fields_path / "mapping-settings.json"]:
        if json_file.exists():
            try:
                with open(json_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                json_errors.append(f"{json_file.name}: {e}")
    
    # Validate YAML files are valid (subset + any custom YAML files)
    yaml_errors = []
    yaml_files = [fields_path / "subset.yml"]
    yaml_files.extend(custom_yaml_files)
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
    # Use the directory where this script lives as the base path so
    # module_list.txt (which resides in the ecs/ folder) is found
    base_path = Path(__file__).parent.resolve()
    
    print("🔍 Verifying WCS Integration Generator Output")
    print("=" * 50)
    
    # Read stateless integrations from module_list.txt (keys inside [ ])
    module_list_path = base_path / "module_list.txt"
    integration_names = []
    if module_list_path.exists():
        try:
            with open(module_list_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # match lines like [stateless/foo]=templates/...
                    if line.startswith('[') and ']' in line:
                        key = line.split(']')[0].lstrip('[').strip()
                        if key.startswith('stateless/') and key != 'stateless/template':
                            # store the full key (e.g. stateless/access-management)
                            integration_names.append(key)
        except Exception as e:
            print(f"❌ Error reading module_list.txt: {e}")
    else:
        print("❌ module_list.txt not found, falling back to filesystem glob")
        integration_folders = [d for d in base_path.glob("stateless/*") if d.is_dir() and d.name != "template"]
        integration_names = [f"stateless/{d.name}" for d in sorted(integration_folders)]

    if not integration_names:
        print("❌ No stateless integrations found in module_list.txt or filesystem!")
        return

    print(f"Found {len(integration_names)} stateless integrations")

    # Verify each integration
    results = []
    for key in sorted(integration_names):
        # key is like 'stateless/access-management' -> extract name after slash
        integration_name = key.split('/', 1)[1]
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