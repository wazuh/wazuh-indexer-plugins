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
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.processor.IocProcessor;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Handles synchronization logic for the unified content consumer. Processes rules, decoders, kvdbs,
 * integrations, and policies. It also handles post-sync operations like creating detectors and
 * calculating policy hashes.
 */
public class IocConsumerSynchronizer extends AbstractConsumerSynchronizer {

    /** The unified IOC type identifier. */
    public static final String IOC = "ioc";

    /** The unified context identifier. */
    private final String CONTEXT = PluginSettings.getInstance().getIocContext();

    /** The unified consumer name identifier. */
    private final String CONSUMER = PluginSettings.getInstance().getIocConsumer();

    private final IocProcessor iocProcessor;

    /**
     * Constructs a new UnifiedConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     */
    public IocConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
        this.iocProcessor = new IocProcessor(client);
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
        mappings.put(IOC, "/mappings/cti-ioc-mappings.json");
        return mappings;
    }

    @Override
    protected Map<String, String> getAliases() {
        // We use the alias names as the actual index names, so we do not create separate aliases.
        return Collections.emptyMap();
    }

    /**
     * Overrides index naming to utilize the alias name convention directly.
     *
     * @param type The type identifier for the index.
     * @return The unified index name.
     */
    @Override
    protected String getIndexName(String type) {
        if (type.equals(IOC)) {
            return ".cti-iocs";
        }
        return super.getIndexName(type);
    }

    @Override
    protected void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            this.refreshIndices(IOC);

            String iocIndex = this.getIndexName(IOC);

            this.iocProcessor.process(iocIndex);

            // TODO: Remove the code below. I'm keeping it for reference while implementing the IOC
            // processor.
            // this.refreshIndices(RULE, DECODER, KVDB, INTEGRATION, IOC);

            // String integrationIndex = this.getIndexName(INTEGRATION);
            // String ruleIndex = this.getIndexName(RULE);
            // String policyIndex = this.getIndexName(IOC);
            // String decoderIndex = this.getIndexName(DECODER);
            // String kvdbIndex = this.getIndexName(KVDB);

            // Map<String, List<String>> integrations = this.iocProcessor.process(integrationIndex);
            // this.ruleProcessor.process(ruleIndex);
            // this.detectorProcessor.process(integrations, integrationIndex);

            // this.policyHashService.calculateAndUpdate(
            //     policyIndex, integrationIndex, decoderIndex, kvdbIndex, ruleIndex);
        }
    }
}
