FROM python:3.13-slim

# Upgrade pip and setuptools to latest versions for security
RUN pip install --upgrade pip setuptools

# Define the version as a build argument 
ARG ECS_VERSION=v9.1.0

# ECS defaults every keyword field to `ignore_above: 1024` (scripts/schema/cleaner.py).
# A value past that limit is stored in _source but indexed nowhere: it matches no term,
# wildcard, prefix or even `exists` query, so no Sigma `|contains` selection can fire on
# it. 4096 is the mid-ground between the ECS default and the 8192 Lucene-safe ceiling
# whose cost is unmeasured. See wazuh/internal-devel-requests#6123.
ARG KEYWORD_IGNORE_ABOVE=4096

# Update the package list and upgrade all packages
RUN apt-get update && \
    apt-get upgrade -y && \
    # Install dependencies
    apt-get install  -y git jq curl && \
    # Cleanup
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    # Clone elastic ECS repository and install required Python libraries
    git clone https://github.com/elastic/ecs.git -b ${ECS_VERSION} --depth 1 && \
    pip install -r ecs/scripts/requirements.txt && \
    # Create the directory for the ecs definitions (this will be used as a volume)
    mkdir -p /source/ecs

# Raise the ECS default for `ignore_above` on keyword fields. The upstream call is a
# setdefault, so fields declaring their own value (url.query 2083, the ECS origin_url
# family 8192, file.drive_letter 1) are left untouched. The grep guard fails the build
# if a future ECS_VERSION bump moves that line, instead of silently regressing to 1024.
RUN sed -i "s/setdefault('ignore_above', 1024)/setdefault('ignore_above', ${KEYWORD_IGNORE_ABOVE})/" \
        ecs/scripts/schema/cleaner.py && \
    grep -q "setdefault('ignore_above', ${KEYWORD_IGNORE_ABOVE})" ecs/scripts/schema/cleaner.py

# Ensure the scripts are in the correct location
ADD wcs/generator/images/generator.sh /ecs/generator.sh
ADD wcs/generator/images/schema_sanitizer.py /ecs/schema_sanitizer.py

# Define the directory as a volume to allow for external mounting
VOLUME /source/ecs

# Execute the sanitizer script to clean up the ECS definitions
RUN python /ecs/schema_sanitizer.py --source ecs/ --log-dir /source/ecs

# Ensure the generator.sh script is executable
RUN chmod +x /ecs/generator.sh

# Set the working directory to the ECS repository
WORKDIR /ecs

# Define the entry point for the container to execute the generator.sh script
ENTRYPOINT ["/bin/bash", "/ecs/generator.sh"]
