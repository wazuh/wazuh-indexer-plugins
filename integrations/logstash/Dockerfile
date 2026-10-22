ARG LOGSTASH_OSS_VERSION
FROM docker.elastic.co/logstash/logstash-oss:${LOGSTASH_OSS_VERSION}

USER logstash

# Input to read from the Wazuh indexer and output to write to OpenSearch.
# https://github.com/elastic/logstash/issues/6600
RUN LS_JAVA_OPTS="-Xms1024m -Xmx1024m" logstash-plugin install logstash-input-opensearch logstash-output-opensearch

# Keystore with the credentials of the Amazon Security Lake pipeline, until that
# integration is adapted to the 5.x data schema. The other pipelines read their
# settings from the environment.
ENV LOGSTASH_KEYSTORE_PASS="SecretPassword"
COPY --chown=logstash:logstash ./setup.sh /usr/share/logstash/bin/setup.sh
RUN bash /usr/share/logstash/bin/setup.sh

# The pipelines set ECS compatibility where they need it.
RUN echo "pipeline.ecs_compatibility: disabled" >> /usr/share/logstash/config/logstash.yml

WORKDIR /usr/share/logstash
