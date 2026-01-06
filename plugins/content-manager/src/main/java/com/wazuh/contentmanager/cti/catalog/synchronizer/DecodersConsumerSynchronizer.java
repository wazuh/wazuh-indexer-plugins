package com.wazuh.contentmanager.cti.catalog.synchronizer;

import java.util.HashMap;
import java.util.Map;

import org.opensearch.env.Environment;
import org.opensearch.transport.client.Client;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
/**
 * Handles synchronization logic specifically for the Decoders consumer.
 * Manages decoder, kvdb, integration, and policy indices.
 */
public class DecodersConsumerSynchronizer extends ConsumerSynchronizer {

    private final PolicyHashService policyHashService;
    public static final String POLICY = "policy";
    public static final String RULE = "rule";
    public static final String KVDB = "kvdb";
    public static final String DECODER = "decoder";
    public static final String INTEGRATION = "integration";

    public DecodersConsumerSynchronizer(Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
        this.policyHashService = new PolicyHashService(client);
    }

    @Override
    protected String getContext() {
        return "decoders_development_0.0.1";
    }

    @Override
    protected String getConsumer() {
        return "decoders_development_0.0.1";
    }

    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(DECODER, "/mappings/cti-decoders-mappings.json");
        mappings.put(KVDB, "/mappings/cti-kvdbs-mappings.json");
        mappings.put(INTEGRATION, "/mappings/cti-decoders-integrations-mappings.json");
        mappings.put(POLICY, "/mappings/cti-policies-mappings.json");
        return mappings;
    }

    @Override
    protected Map<String, String> getAliases() {
        Map<String, String> aliases = new HashMap<>();
        aliases.put(DECODER, ".cti-decoders");
        aliases.put(KVDB, ".cti-kvdbs");
        aliases.put(INTEGRATION, ".cti-integration-decoders");
        aliases.put(POLICY, ".cti-policies");
        return aliases;
    }

    @Override
    protected void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            refreshIndices(DECODER, KVDB, INTEGRATION, POLICY);
            policyHashService.calculateAndUpdate(getContext(), getConsumer());
        }
    }
}