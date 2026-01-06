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

/**
 * Handles synchronization logic specifically for the Decoders consumer. Manages decoder, kvdb,
 * integration, and policy indices.
 */
public class DecodersConsumerSynchronizer extends ConsumerSynchronizer {

    public static final String POLICY = "policy";
    public static final String RULE = "rule";
    public static final String KVDB = "kvdb";
    public static final String DECODER = "decoder";
    public static final String INTEGRATION = "integration";

    private final String CONTEXT = "decoders_development_0.0.1";
    private final String CONSUMER = "decoders_development_0.0.1";

    private final PolicyHashService policyHashService;

    public DecodersConsumerSynchronizer(
            Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
        this.policyHashService = new PolicyHashService(client);
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
