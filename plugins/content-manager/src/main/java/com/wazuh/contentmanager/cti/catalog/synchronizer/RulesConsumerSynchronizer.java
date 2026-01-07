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
 * integrations, and creates/updates threat detectors after synchronization completes.
 */
public class RulesConsumerSynchronizer extends AbstractConsumerSynchronizer {

    /** Content type identifier for rule documents. */
    public static final String RULE = "rule";

    /** Content type identifier for integration documents. */
    public static final String INTEGRATION = "integration";

    /** The context identifier for the rules consumer. */
    private final String CONTEXT = "rules_development_0.0.1";

    /** The consumer name identifier. */
    private final String CONSUMER = "rules_development_0.0.1_test";

    /** Processor for syncing integrations to the security analytics plugin. */
    private final IntegrationProcessor integrationProcessor;

    /** Processor for syncing rules to the security analytics plugin. */
    private final RuleProcessor ruleProcessor;

    /** Processor for creating/updating threat detectors from integrations. */
    private final DetectorProcessor detectorProcessor;

    /**
     * Constructs a new RulesConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper for tracking synchronization state.
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
        mappings.put(INTEGRATION, "/mappings/cti-integrations-mappings.json");
        return mappings;
    }

    @Override
    protected Map<String, String> getAliases() {
        Map<String, String> aliases = new HashMap<>();
        aliases.put(RULE, ".cti-rules");
        aliases.put(INTEGRATION, ".cti-integration-rules");
        return aliases;
    }

    /**
     * Called after synchronization completes. Refreshes indices and processes rules, integrations,
     * and detectors if updates were applied.
     *
     * @param isUpdated True if any updates were applied during synchronization.
     */
    @Override
    protected void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            this.refreshIndices(RULE, INTEGRATION);
            String integrationIndex = this.getIndexName(INTEGRATION);
            String ruleIndex = this.getIndexName(RULE);

            Map<String, List<String>> integrations = this.integrationProcessor.process(integrationIndex);
            this.ruleProcessor.process(ruleIndex);
            this.detectorProcessor.process(integrations, integrationIndex);
        }
    }
}
