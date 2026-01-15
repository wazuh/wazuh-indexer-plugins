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
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Handles synchronization logic specifically for the Decoders consumer. Manages decoder, kvdb,
 * integration, and policy indices. After synchronization completes, calculates and updates policy
 * hashes.
 */
public class DecodersConsumerSynchronizer extends AbstractConsumerSynchronizer {

    /** Content type identifier for policy documents. */
    public static final String POLICY = "policy";

    /** Content type identifier for kvdb (key-value database) documents. */
    public static final String KVDB = "kvdb";

    /** Content type identifier for decoder documents. */
    public static final String DECODER = "decoder";

    /** Content type identifier for integration documents. */
    public static final String INTEGRATION = "integration";

    /** The context identifier for the decoders consumer. */
    private final String CONTEXT = PluginSettings.getInstance().getDecodersContext();

    /** The consumer name identifier. */
    private final String CONSUMER = PluginSettings.getInstance().getDecodersConsumer();

    /** Service for calculating and updating policy hashes after synchronization. */
    private final PolicyHashService policyHashService;

    /**
     * Constructs a new DecodersConsumerSynchronizer.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper for tracking synchronization state.
     * @param environment The OpenSearch environment settings.
     */
    public DecodersConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
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
        mappings.put(DECODER, "/mappings/cti-decoders-mappings.json");
        mappings.put(KVDB, "/mappings/cti-kvdbs-mappings.json");
        mappings.put(INTEGRATION, "/mappings/cti-integrations-mappings.json");
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

    /**
     * Called after synchronization completes. Refreshes the relevant indices and calculates policy
     * hashes if updates were applied.
     *
     * @param isUpdated True if any updates were applied during synchronization.
     */
    @Override
    protected void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            this.refreshIndices(DECODER, KVDB, INTEGRATION, POLICY);
            this.policyHashService.calculateAndUpdate(this.getContext(), this.getConsumer());
        }
    }
}
