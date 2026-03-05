"""
Convert Wazuh Common Schema (WCS) static index templates to dynamic_templates.

Reads an OpenSearch legacy index template with a monolithic static `properties`
block and generates an optimized `dynamic_templates` array. The output template
uses `"dynamic": "false_allow_templates"` so that only fields matching the
WCS schema are accepted, but mappings are created lazily (on first ingest).

Usage:
    python3 convert_to_dynamic_templates.py input_template.json [output_template.json]
"""

import json
import argparse
import copy

def flatten_properties(properties_dict, current_path=None):
    """
    Recursively extracts all leaf fields from the properties mapping.
    Returns a dictionary of {"full.path": { mapping_details }}
    """
    if current_path is None:
        current_path = []
        
    flat_mappings = {}
    for key, value in properties_dict.items():
        if "properties" in value:
            # It's a parent object, recurse deeper
            nested = flatten_properties(value["properties"], current_path + [key])
            flat_mappings.update(nested)
        else:
            # It's a leaf node containing the actual type/mapping data
            full_path = ".".join(current_path + [key])
            flat_mappings[full_path] = value
            
    return flat_mappings

def extract_object_scaffolding(properties_dict):
    """
    Rebuilds the tree containing ONLY 'properties' objects. 
    This allows OpenSearch 'false_allow_templates' to accept nested JSON objects.
    """
    scaffolding = {}
    for key, value in properties_dict.items():
        if "properties" in value:
            scaffolding[key] = {
                "properties": extract_object_scaffolding(value["properties"])
            }
    return scaffolding

def convert_template(input_data):
    """
    Converts the monolithic static properties template into a dynamic_templates list.
    """
    output = copy.deepcopy(input_data)
    
    template_block = output.get("template", {})
    mappings = template_block.get("mappings", {})
    properties = mappings.get("properties", {})

    if not properties:
        return output

    # 1. Get all flat paths and their mappings
    flat_mappings = flatten_properties(properties)
    
    # 2. Build the object scaffolding (empty nested objects)
    static_props = extract_object_scaffolding(properties)

    # 3. Create a dynamic template for EVERY field
    dynamic_templates = []
    
    for path, mapping in flat_mappings.items():
        # Keep @timestamp as a static property (standard practice)
        if path == "@timestamp":
            static_props["@timestamp"] = mapping
            continue
            
        # Create a safe name for the template rule
        rule_name = "wcs_" + path.replace(".", "_").replace("-", "_").replace("@", "")
        
        template_rule = {
            rule_name: {
                "path_match": path,
                "mapping": mapping
            }
        }
        dynamic_templates.append(template_rule)

    # 4. Sort templates alphabetically for consistent output
    dynamic_templates = sorted(dynamic_templates, key=lambda x: list(x.keys())[0])

    # 5. Overwrite the mappings block in the output
    template_block["mappings"] = {
        "date_detection": mappings.get("date_detection", False),
        "dynamic": "false_allow_templates",
        "dynamic_templates": dynamic_templates,
        "properties": static_props
    }

    return output

def main():
    parser = argparse.ArgumentParser(description="Convert ALL static properties to dynamic_templates.")
    parser.add_argument("input", help="Source JSON template file")
    parser.add_argument("output", nargs="?", help="Output JSON template file")
    args = parser.parse_args()

    # Read input file
    with open(args.input, 'r') as f:
        input_data = json.load(f)

    # Convert
    result = convert_template(input_data)

    # Format JSON
    output_json = json.dumps(result, indent=2)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json + "\n")
        print(f"Successfully converted {len(result['template']['mappings']['dynamic_templates'])} fields.")
        print(f"Written to {args.output}")
    else:
        print(output_json)

if __name__ == "__main__":
    main()
