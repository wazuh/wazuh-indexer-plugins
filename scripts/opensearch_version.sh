#!/bin/bash
# -----------------------------------------------------------------------------
# Script Name: opensearch_version.sh
#
# Description:
#   This script extracts the OpenSearch version from the build.gradle file of a
#   specified plugin directory. It searches for the 'opensearch_version' property
#   and parses its value, removing any '-SNAPSHOT' suffix if present.
#
# Usage:
#   ./opensearch_version.sh <directory_name>
#
# Arguments:
#   <directory_name>   Name of the plugin directory inside 'plugins/' whose
#                      build.gradle file contains the OpenSearch version.
#
# Output:
#   Prints the extracted OpenSearch version to stdout.
#
# Exit Codes:
#   0   Success
#   1   Missing argument or error during extraction
#
# Example:
#   ./opensearch_version.sh my_plugin
# -----------------------------------------------------------------------------

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <directory_name>"
    exit 1
fi

file="plugins/$1/build.gradle"

# Extract the OpenSearch version
version=$(grep "opensearch_version =" "${file}" |
    sed -E 's/.*System.getProperty\("opensearch\.version", "//' |
    sed -E 's/".*//' |
    sed -E 's/-SNAPSHOT$//')

echo "${version}"
exit 0