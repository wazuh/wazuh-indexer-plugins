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
package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Changes;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Offset;
import com.wazuh.securityanalytics.action.*;
import com.wazuh.securityanalytics.model.Integration;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.transport.client.Client;

import java.util.*;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * Service responsible for keeping the catalog content up-to-date.
 */
public class UpdateServiceImpl extends AbstractService implements UpdateService {
    private static final Logger log = LogManager.getLogger(UpdateServiceImpl.class);

    // Keys to navigate the JSON structure
    private static final String JSON_TYPE_KEY = "type";
    private static final String JSON_DOCUMENT_KEY = "document";
    private static final String JSON_ID_KEY = "id";
    private static final String JSON_CATEGORY_KEY = "category";
    private static final String JSON_PRODUCT_KEY = "product";
    public static final String JSON_RULES_KEY = "rules";
    public static final String JSON_LOGSOURCE_KEY = "logsource";

    private final ConsumersIndex consumersIndex;
    private final Map<String, ContentIndex> indices;
    private final String context;
    private final String consumer;
    private final Gson gson;
    private final Client osClient;

    /**
     * Constructs a new UpdateServiceImpl.
     *
     * @param context        The context string (e.g., catalog ID) for the consumer.
     * @param consumer       The name of the consumer entity.
     * @param client         The API client used to fetch changes.
     * @param consumersIndex The index responsible for storing consumer state (offsets).
     * @param indices        A map of content type to {@link ContentIndex} managers.
     * @param osClient       The OpenSearch client for SAP actions.
     */
    public UpdateServiceImpl(String context, String consumer, ApiClient client, ConsumersIndex consumersIndex, Map<String, ContentIndex> indices, Client osClient) {
        if (this.client != null) {
            this.client.close();
        }

        this.client = client;
        this.consumersIndex = consumersIndex;
        this.indices = indices;
        this.context = context;
        this.consumer = consumer;
        this.gson = new Gson();
        this.osClient = osClient;
    }

    /**
     *
     * Performs a content update within the specified offset range.
     *
     * Implementation details:
     * 1. Fetches the changes JSON from the API for the given range.
     * 2. Parses the response into {@link Changes} and {@link Offset} objects.
     * 3. Iterates through offsets.
     * 4. Delegates specific operations to {@link #applyOffset(Offset)}.
     * 5. Updates the {@link LocalConsumer} record in the index with the last successfully applied offset.
     *
     * If an exception occurs, the consumer state is reset to prevent data corruption or stuck states.
     */
    @Override
    public void update(long fromOffset, long toOffset) {
        log.info("Starting content update for consumer [{}] from [{}] to [{}]", this.consumer, fromOffset, toOffset);
        try {
            SimpleHttpResponse response = this.client.getChanges(this.context, this.consumer, fromOffset, toOffset);
            if (response.getCode() != 200) {
                log.error("Failed to fetch changes: {} {}", response.getCode(), response.getBodyText());
                return;
            }

            // TODO: Study if it can be changed to Jackson Databind and if so apply the necessary changes
            try (XContentParser parser = XContentType.JSON.xContent().createParser(
                NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                response.getBodyBytes())) {
                Changes changes = Changes.parse(parser);
                long lastAppliedOffset = fromOffset;

                for (Offset offset : changes.get()) {
                    this.applyOffset(offset);
                    lastAppliedOffset = offset.getOffset();
                }

                // Update consumer state
                LocalConsumer consumer = new LocalConsumer(this.context, this.consumer);

                // Properly handle the GetResponse to check if the document exists before parsing
                GetResponse getResponse = this.consumersIndex.getConsumer(this.context, this.consumer);
                LocalConsumer current = (getResponse != null && getResponse.isExists()) ?
                    this.mapper.readValue(getResponse.getSourceAsString(), LocalConsumer.class) : consumer;

                LocalConsumer updated = new LocalConsumer(this.context, this.consumer, lastAppliedOffset, current.getRemoteOffset(), current.getSnapshotLink());
                this.consumersIndex.setConsumer(updated);

                log.info("Successfully updated consumer [{}] to offset [{}]", consumer, lastAppliedOffset);
            }
        } catch (Exception e) {
            log.error("Error during content update: {}", e.getMessage(), e);
            this.resetConsumer();
        }
    }

    /**
     * Applies a specific change offset to the appropriate content index.
     *
     * @param offset The {@link Offset} containing the type of change and data.
     * @throws Exception If the indexing operation fails.
     */
    private void applyOffset(Offset offset) throws Exception {
        String id = offset.getResource();
        ContentIndex index;
        String type;

        switch (offset.getType()) {
            case CREATE:
                if (offset.getPayload() != null) {
                    // TODO: Change the Offset logic to use JsonNode and use Jackson Object Mapper to obtain the payload
                    JsonObject payload = this.gson.toJsonTree(offset.getPayload()).getAsJsonObject();
                    if (payload.has(JSON_TYPE_KEY)) {
                        type = payload.get(JSON_TYPE_KEY).getAsString();

                        // TODO: Delete once the consumer is changed
                        if (this.context.equals("rules_development_0.0.1") && this.consumer.equals("rules_development_0.0.1_test") && "policy".equals(type)) {
                            break;
                        }

                        index = this.indices.get(type);
                        if (index != null) {
                            index.create(id, payload);
                            this.syncToSap(type, payload);
                        } else {
                            log.warn("No index mapped for type [{}]", type);
                        }
                    }
                }
                break;
            case UPDATE:
                // TODO: Delete once the consumer is changed
                if (this.context.equals("rules_development_0.0.1") && this.consumer.equals("rules_development_0.0.1_test") && "policy".equals(id)) {
                    break;
                }

                index = this.findIndexForId(id);
                index.update(id, offset.getOperations());

                String indexName = index.getIndexName();
                type = indexName.substring(indexName.lastIndexOf('-') + 1);

                GetResponse response = this.osClient.get(new GetRequest(index.getIndexName(), id)).actionGet();
                if (response.isExists()) {
                    JsonObject updatedDoc = JsonParser.parseString(response.getSourceAsString()).getAsJsonObject();
                    this.syncToSap(type, updatedDoc);
                }
                break;
            case DELETE:
                index = this.findIndexForId(id);
                index.delete(id);

                String idxName = index.getIndexName();
                type = idxName.substring(idxName.lastIndexOf('-') + 1);

                this.deleteSapResource(type, id);
                break;
            default:
                log.warn("Unsupported JSON patch operation [{}]", offset.getType());
                break;
        }
    }

    /**
     * Parses the source JSON and executes a creation/update request to SAP for 'integration' or 'rule' types.
     *
     * @param type The entity type (e.g., "integration", "rule").
     * @param source The raw JSON source containing the document data.
     */
    private void syncToSap(String type, JsonObject source) {
        try {
            if (!source.has(JSON_DOCUMENT_KEY)) {
                return;
            }
            JsonObject doc = source.getAsJsonObject(JSON_DOCUMENT_KEY);
            String id = doc.get(JSON_ID_KEY).getAsString();

            if ("integration".equals(type)) {
                String name = doc.get("title").getAsString();
                String description = doc.get("description").getAsString();
                String category = this.getCategory(doc);
                List<String> rules = new ArrayList<>();

                if (doc.has(JSON_RULES_KEY)) {
                    doc.get(JSON_RULES_KEY).getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
                }
                if (rules.isEmpty()) {
                    return;
                }

                log.info("Creating/Updating Integration [{}] in SAP - ID: {}", name, id);

                WIndexIntegrationRequest request = new WIndexIntegrationRequest(
                    id,
                    WriteRequest.RefreshPolicy.IMMEDIATE,
                    POST,
                    new Integration(
                        id,
                        null,
                        name,
                        description,
                        category,
                        "Sigma",
                        rules,
                        new HashMap<>()
                    )
                );
                this.osClient.execute(WIndexIntegrationAction.INSTANCE, request).actionGet();

                // Detector update
                WIndexDetectorRequest detectorRequest = new WIndexDetectorRequest(
                    id,
                    name,
                    category,
                    rules,
                    WriteRequest.RefreshPolicy.IMMEDIATE
                );
                this.osClient.execute(WIndexDetectorAction.INSTANCE, detectorRequest).actionGet();
                log.info("Updated Detector [{}] for Integration [{}]", id, id);

            } else if ("rule".equals(type)) {
                String product = "linux";
                if (doc.has(JSON_LOGSOURCE_KEY)) {
                    JsonObject logsource = doc.getAsJsonObject(JSON_LOGSOURCE_KEY);
                    if (logsource.has(JSON_PRODUCT_KEY)) {
                        product = logsource.get(JSON_PRODUCT_KEY).getAsString();
                    } else if (logsource.has(JSON_CATEGORY_KEY)) {
                        product = logsource.get(JSON_CATEGORY_KEY).getAsString();
                    }
                }

                log.info("Creating/Updating Rule [{}] in SAP", id);

                WIndexRuleRequest ruleRequest = new WIndexRuleRequest(
                    id,
                    WriteRequest.RefreshPolicy.IMMEDIATE,
                    product,
                    POST,
                    doc.toString(),
                    true
                );
                this.osClient.execute(WIndexRuleAction.INSTANCE, ruleRequest).actionGet();
            }
        } catch (Exception e) {
            log.error("Failed to sync type [{}] to SAP: {}", type, e.getMessage());
        }
    }

    /**
     * Deletes a resource from SAP based on the provided type and identifier.
     *
     * <p>For {@code "integration"} types, this method performs deletes the
     * associated Detector first, followed by the Integration itself.
     * For {@code "rule"} types, it performs a standard single deletion.</p>
     *
     * @param type The resource type (e.g., "integration", "rule").
     * @param id   The unique identifier of the resource to delete.
     */
    private void deleteSapResource(String type, String id) {
        try {
            if ("integration".equals(type)) {
                // Delete detector first
                log.info("Deleting Detector [{}] from SAP", id);
                this.osClient.execute(WDeleteDetectorAction.INSTANCE, new WDeleteDetectorRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE)).actionGet();

                // Then delete integration
                log.info("Deleting Integration [{}] from SAP", id);
                this.osClient.execute(WDeleteIntegrationAction.INSTANCE, new WDeleteIntegrationRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE)).actionGet();
            } else if ("rule".equals(type)) {
                log.info("Deleting Rule [{}] from SAP", id);
                this.osClient.execute(WDeleteRuleAction.INSTANCE, new WDeleteRuleRequest(id, WriteRequest.RefreshPolicy.IMMEDIATE, true)).actionGet();
            }
        } catch (Exception e) {
            log.error("Failed to delete SAP resource [{}] of type [{}]: {}", id, type, e.getMessage());
        }
    }

    /**
     * Retrieves the integration category from the document and returns a cleaned-up string.
     * @param doc Json document
     * @return capitalized space-separated string
     */
    public String getCategory(JsonObject doc) {
        String rawCategory = doc.get(JSON_CATEGORY_KEY).getAsString();

        // TODO remove when CTI applies the changes to the categorization.
        // Remove subcategory. Currently only cloud-services has subcategories (aws, gcp, azure).
        if (rawCategory.contains("cloud-services")) {
            rawCategory = rawCategory.substring(0, 14);
        }
        return Arrays.stream(
            rawCategory
                .split("-"))
                .reduce("", (current, next) -> current + " " + Strings.capitalize(next))
                .trim();
    }

    /**
     * Locates the {@link ContentIndex} that contains the document with the specified ID.
     *
     * @param id The document ID to search for.
     * @return The matching {@link ContentIndex}.
     * @throws ResourceNotFoundException If no {@link ContentIndex} contains the document with the specified ID.
     */
    private ContentIndex findIndexForId(String id) throws ResourceNotFoundException {
        // When it is a policy document, it must be treated special, since the id policy doesn't exist
        if ("policy".equals(id)) {
            ContentIndex policyIndex = this.indices.get("policy");
            if (policyIndex != null) {
                return policyIndex;
            }
            throw new ResourceNotFoundException("Policy index not found.");
        }

        for (ContentIndex index : this.indices.values()) {
            if (index.exists(id)) {
                return index;
            }
        }
        throw new ResourceNotFoundException("Document with ID '" + id + "' could not be found in any ContentIndex.");
    }

    /**
     * Resets the local consumer offset to 0.
     */
    private void resetConsumer() {
        log.info("Resetting consumer [{}] offset to 0 due to update failure.", this.consumer);
        try {
            LocalConsumer reset = new LocalConsumer(this.context, this.consumer, 0, 0, "");
            this.consumersIndex.setConsumer(reset);
        } catch (Exception e) {
            log.error("Failed to reset consumer: {}", e.getMessage());
        }
    }
}
