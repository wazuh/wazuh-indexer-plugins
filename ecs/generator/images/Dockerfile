FROM python:3.13-slim

# Upgrade pip and setuptools to latest versions for security
RUN pip install --upgrade pip setuptools

# Define the version as a build argument 
ARG ECS_VERSION=v9.1.0

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

# Ensure the scripts are in the correct location
ADD ecs/generator/images/generator.sh /ecs/generator.sh
ADD ecs/generator/images/schema_sanitizer.py /ecs/schema_sanitizer.py

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
