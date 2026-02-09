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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.time.LocalDate;
import java.util.*;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.processor.DetectorProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.IntegrationProcessor;
import com.wazuh.contentmanager.cti.catalog.processor.RuleProcessor;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Handles synchronization logic for the unified content consumer. Processes rules, decoders, kvdbs,
 * integrations, and policies. It also handles post-sync operations like creating detectors and
 * calculating policy hashes.
 */
public class UnifiedConsumerSynchronizer extends AbstractConsumerSynchronizer {

    private static final Logger log = LogManager.getLogger(UnifiedConsumerSynchronizer.class);
    private final ObjectMapper mapper;

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

        this.mapper = new ObjectMapper();
        this.mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS);
        this.mapper
                .configOverride(Policy.class)
                .setInclude(
                        JsonInclude.Value.construct(JsonInclude.Include.ALWAYS, JsonInclude.Include.ALWAYS));
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
        mappings.put(Constants.KEY_RULE, "/mappings/cti-rules-mappings.json");
        mappings.put(Constants.KEY_DECODER, "/mappings/cti-decoders-mappings.json");
        mappings.put(Constants.KEY_KVDB, "/mappings/cti-kvdbs-mappings.json");
        mappings.put(Constants.KEY_INTEGRATION, "/mappings/cti-integrations-mappings.json");
        mappings.put(Constants.KEY_POLICY, "/mappings/cti-policies-mappings.json");
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
            this.refreshIndices(
                    Constants.INDEX_RULES,
                    Constants.INDEX_DECODERS,
                    Constants.INDEX_KVDBS,
                    Constants.INDEX_INTEGRATIONS,
                    Constants.INDEX_POLICIES);

            // Initialize default spaces if they don't exist
            this.initializeSpaces(Constants.INDEX_POLICIES);

            Map<String, List<String>> integrations =
                    this.integrationProcessor.process(Constants.INDEX_INTEGRATIONS);
            this.ruleProcessor.process(Constants.INDEX_RULES);
            this.detectorProcessor.process(integrations, Constants.INDEX_INTEGRATIONS);

            this.policyHashService.calculateAndUpdate();
        }
    }

    /**
     * Creates default policy documents for user spaces (draft, testing, custom) if they don't exist.
     *
     * @param indexName The policy index name.
     */
    private void initializeSpaces(String indexName) {
        // Generate a single ID to be shared across all default policies so they are linked
        String sharedDocumentId = UUID.randomUUID().toString();
        this.initializeSpace(indexName, Space.DRAFT.toString(), sharedDocumentId);
        this.initializeSpace(indexName, Space.TEST.toString(), sharedDocumentId);
        this.initializeSpace(indexName, Space.CUSTOM.toString(), sharedDocumentId);
    }

    /**
     * Creates a single space policy document if it does not already exist.
     *
     * @param indexName The index name.
     * @param spaceName The space name.
     */
    private void initializeSpace(String indexName, String spaceName, String documentId) {
        try {
            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName));
            searchSourceBuilder.size(0);

            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();

            // Proceed only if no document with this space name exists
            if (searchResponse.getHits().getTotalHits().value() == 0) {
                String date = LocalDate.now(TimeZone.getDefault().toZoneId()).toString();
                String title = "Custom policy";

                Policy policy = new Policy();
                policy.setId(documentId);
                policy.setTitle(title);
                policy.setDescription(title);
                policy.setAuthor("Wazuh Inc.");
                policy.setRootDecoder("");
                policy.setDocumentation("");
                policy.setIntegrations(Collections.emptyList());
                policy.setReferences(List.of("https://wazuh.com"));
                policy.setDate(date);
                policy.setModified(date);

                // TODO: Study the model policy and delete the extra fields
                Map<String, Object> docMap = this.mapper.convertValue(policy, Map.class);
                docMap.remove(Constants.KEY_TYPE); // Delete the field type inside the document

                String docJson = this.mapper.writeValueAsString(docMap);
                String docHash = HashCalculator.sha256(docJson);

                Map<String, Object> space = new HashMap<>();
                space.put(Constants.KEY_NAME, spaceName);
                space.put(Constants.KEY_HASH, Map.of(Constants.KEY_SHA256, docHash));

                Map<String, Object> source = new HashMap<>();
                source.put(Constants.KEY_DOCUMENT, docMap);
                source.put(Constants.KEY_SPACE, space);
                // TODO: change to usage of method to calculate space hash
                source.put(Constants.KEY_HASH, Map.of(Constants.KEY_SHA256, docHash));

                IndexRequest request =
                        new IndexRequest(indexName)
                                .source(this.mapper.writeValueAsString(source), XContentType.JSON)
                                .opType(DocWriteRequest.OpType.CREATE)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                this.client.index(request).actionGet();
            }
        } catch (Exception e) {
            log.error("Failed to initialize space [{}]: {}", spaceName, e.getMessage());
        }
    }
}
