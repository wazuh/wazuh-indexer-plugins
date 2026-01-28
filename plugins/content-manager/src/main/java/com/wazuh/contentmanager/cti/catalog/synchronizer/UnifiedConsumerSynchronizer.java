/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.cti.catalog.synchronizer;

import org.opensearch.env.Environment;
import org.opensearch.transport.client.Client;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.processor.DetectorProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.IntegrationProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.RuleProcessor;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Handles synchronization logic for the unified content consumer. Processes rules, decoders, kvdbs,
 * integrations, and policies. It also handles post-sync operations like creating detectors and
 * calculating policy hashes.
 */
public class UnifiedConsumerSynchronizer extends AbstractConsumerSynchronizer {

    /** The unified context identifier. */
    private final String CONTEXT = PluginSettings.getInstance().getContentContext();

    /** The unified consumer name identifier. */
    private final String CONSUMER = PluginSettings.getInstance().getContentConsumer();

    private final IntegrationProcessor integrationProcessor;
    private final RuleProcessor ruleProcessor;
    private final DetectorProcessor detectorProcessor;
    private final PolicyHashService policyHashService;

    /**
     * Constructs a new UnifiedConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     */
    public UnifiedConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
        this.integrationProcessor = new IntegrationProcessor(client);
        this.ruleProcessor = new RuleProcessor(client);
        this.detectorProcessor = new DetectorProcessor(client);
        this.policyHashService = new PolicyHashService(client);
    }

    @Override
    protected String getContext() {
        return this.CONTEXT;
    }

    @Override
    protected String getConsumer() {
        return this.CONSUMER;
    }

    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(RULE, "/mappings/cti-rules-mappings.json");
        mappings.put(DECODER, "/mappings/cti-decoders-mappings.json");
        mappings.put(KVDB, "/mappings/cti-kvdbs-mappings.json");
        mappings.put(INTEGRATION, "/mappings/cti-integrations-mappings.json");
        mappings.put(POLICY, "/mappings/cti-policies-mappings.json");
        return mappings;
    }

    @Override
    protected Map<String, String> getAliases() {
        // We use the alias names as the actual index names, so we do not create separate aliases.
        return Collections.emptyMap();
    }

    @Override
    protected void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            this.refreshIndices(RULE, DECODER, KVDB, INTEGRATION, POLICY);

            String integrationIndex = this.getIndexName(INTEGRATION);
            String ruleIndex = this.getIndexName(RULE);
            String policyIndex = this.getIndexName(POLICY);
            String decoderIndex = this.getIndexName(DECODER);
            String kvdbIndex = this.getIndexName(KVDB);

            Map<String, List<String>> integrations = this.integrationProcessor.process(integrationIndex);
            this.ruleProcessor.process(ruleIndex);
            this.detectorProcessor.process(integrations, integrationIndex);

            this.policyHashService.calculateAndUpdate(
                    policyIndex, integrationIndex, decoderIndex, kvdbIndex, ruleIndex);
        }
    }
}
