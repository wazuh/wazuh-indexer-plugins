#!/bin/bash

# Check if an argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <directory_name>"
  exit 1
fi

file="plugins/$1/build.gradle"

# Extract the OpenSearch version
opensearch_version=$(grep "opensearch_version =" "$file" | \
sed -E 's/.*System.getProperty\("opensearch\.version", "//' | \
sed -E 's/".*//' | \
sed -E 's/-SNAPSHOT$//')

echo "$opensearch_version"
