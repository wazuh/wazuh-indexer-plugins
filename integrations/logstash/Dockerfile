ARG LOGSTASH_OSS_VERSION
FROM docker.elastic.co/logstash/logstash-oss:${LOGSTASH_OSS_VERSION}

USER logstash

# Input to read from the Wazuh indexer and output to write to OpenSearch, at the versions
# the integrations are tested with.
# https://github.com/elastic/logstash/issues/6600
ARG LOGSTASH_INPUT_OPENSEARCH_VERSION=1.0.0
ARG LOGSTASH_OUTPUT_OPENSEARCH_VERSION=2.1.1
RUN LS_JAVA_OPTS="-Xms1024m -Xmx1024m" logstash-plugin install \
      --version ${LOGSTASH_INPUT_OPENSEARCH_VERSION} logstash-input-opensearch && \
    LS_JAVA_OPTS="-Xms1024m -Xmx1024m" logstash-plugin install \
      --version ${LOGSTASH_OUTPUT_OPENSEARCH_VERSION} logstash-output-opensearch

# Every pipeline reads its settings, credentials included, from the environment or from a
# Logstash keystore created by the deployment: the image holds no credentials.

# The pipelines set ECS compatibility where they need it.
RUN echo "pipeline.ecs_compatibility: disabled" >> /usr/share/logstash/config/logstash.yml

WORKDIR /usr/share/logstash
