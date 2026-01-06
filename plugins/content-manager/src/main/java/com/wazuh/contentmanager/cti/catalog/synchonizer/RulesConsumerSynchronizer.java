/*
 * Copyright (C) 2024, Wazuh Inc.
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.processor.DetectorProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.IntegrationProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.RuleProcessor;

/**
 * Handles synchronization logic specifically for the Rules consumer. Processes rules and
 * integrations, and creates/updates detectors.
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
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     */
    public RulesConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
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
