package com.wazuh.contentmanager.cti.catalog.synchronizer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensearch.env.Environment;
import org.opensearch.transport.client.Client;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.processor.DetectorProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.IntegrationProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.RuleProcessor;

/**
 * Handles synchronization logic specifically for the Rules consumer.
 * Processes rules and integrations, and creates/updates detectors.
 */
public class RulesConsumerSynchronizer extends ConsumerSynchronizer {

    public static final String RULE = "rule";
    public static final String INTEGRATION = "integration";

    private final String CONTEXT = "rules_development_0.0.1";
    private final String CONSUMER = "rules_development_0.0.1_test";

    private final IntegrationProcessor integrationProcessor;
    private final RuleProcessor ruleProcessor;
    private final DetectorProcessor detectorProcessor;

    /**
     * Constructs a new RulesConsumerSynchronizer.
     *
     * @param client         The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment    The OpenSearch environment settings.
     */
    public RulesConsumerSynchronizer(Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
        this.integrationProcessor = new IntegrationProcessor(client);
        this.ruleProcessor = new RuleProcessor(client);
        this.detectorProcessor = new DetectorProcessor(client);
    }

    @Override
    protected String getContext() {
        return CONTEXT;
    }

    @Override
    protected String getConsumer() {
        return CONSUMER;
    }

    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(RULE, "/mappings/cti-rules-mappings.json");
        mappings.put(INTEGRATION, "/mappings/cti-rules-integrations-mappings.json");
        return mappings;
    }

    @Override
    protected Map<String, String> getAliases() {
        Map<String, String> aliases = new HashMap<>();
        aliases.put(RULE, ".cti-rules");
        aliases.put(INTEGRATION, ".cti-integration-rules");
        return aliases;
    }

    @Override
    protected void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            refreshIndices(RULE, INTEGRATION);
            String integrationIndex = getIndexName(INTEGRATION);
            String ruleIndex = getIndexName(RULE);

            Map<String, List<String>> integrations = integrationProcessor.process(integrationIndex);
            ruleProcessor.process(ruleIndex);
            detectorProcessor.process(integrations, integrationIndex);
        }
    }
}