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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Service for managing integration relationships with resources. Handles linking and unlinking
 * resources (rules, decoders, kvdbs) to/from integrations.
 */
public class IntegrationService {
    private static final Logger log = LogManager.getLogger(IntegrationService.class);

    private final Client client;
    private final ObjectMapper mapper;

    /**
     * Constructs an IntegrationService.
     *
     * @param client The OpenSearch client.
     */
    public IntegrationService(Client client) {
        this.client = client;
        this.mapper = new ObjectMapper();
    }

    /**
     * Links a resource to an integration by adding its ID to the specified list field.
     *
     * @param integrationId The ID of the integration to update.
     * @param resourceId The ID of the resource to link.
     * @param listKey The key of the list field in the integration document (e.g., "rules").
     * @throws IOException If the integration cannot be found or updated.
     */
    @SuppressWarnings("unchecked")
    public void linkResourceToIntegration(String integrationId, String resourceId, String listKey)
            throws IOException {
        GetResponse response =
                this.client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();

        if (!response.isExists()) {
            throw new IOException("Integration [" + integrationId + "] not found.");
        }

        Map<String, Object> source = response.getSourceAsMap();
        Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

        List<String> list = (List<String>) document.getOrDefault(listKey, new ArrayList<>());

        // Ensure list is mutable
        if (!(list instanceof ArrayList)) {
            list = new ArrayList<>(list);
        }

        if (!list.contains(resourceId)) {
            list.add(resourceId);
            document.put(listKey, list);
            this.updateIntegrationSource(response.getId(), document, source);
        }
    }

    /**
     * Asynchronously links a resource to an integration by adding its ID to the specified list field.
     *
     * @param integrationId The ID of the integration to update.
     * @param resourceId The ID of the resource to link.
     * @param listKey The key of the list field in the integration document.
     * @param listener The listener to notify on completion.
     */
    @SuppressWarnings("unchecked")
    public void linkResourceToIntegrationAsync(
            String integrationId, String resourceId, String listKey, ActionListener<Void> listener) {
        this.client.get(
                new GetRequest(Constants.INDEX_INTEGRATIONS, integrationId),
                ActionListener.wrap(
                        response -> {
                            if (!response.isExists()) {
                                listener.onFailure(
                                        new IOException("Integration [" + integrationId + "] not found."));
                                return;
                            }

                            Map<String, Object> source = response.getSourceAsMap();
                            Map<String, Object> document =
                                    (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

                            List<String> list = (List<String>) document.getOrDefault(listKey, new ArrayList<>());

                            if (!(list instanceof ArrayList)) {
                                list = new ArrayList<>(list);
                            }

                            if (!list.contains(resourceId)) {
                                list.add(resourceId);
                                document.put(listKey, list);
                                this.updateIntegrationSourceAsync(response.getId(), document, source, listener);
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        listener::onFailure));
    }

    /**
     * Asynchronously updates the integration document in the index with a recalculated hash.
     *
     * @param id Integration ID.
     * @param document The updated document content.
     * @param source The full source map including metadata.
     * @param listener The listener to notify on completion.
     */
    public void updateIntegrationSourceAsync(
            String id,
            Map<String, Object> document,
            Map<String, Object> source,
            ActionListener<Void> listener) {
        JsonNode documentNode = this.mapper.valueToTree(document);
        String newHash = Resource.computeSha256(documentNode.toString());

        Map<String, Object> hashMap = new HashMap<>();
        hashMap.put(Constants.KEY_SHA256, newHash);
        source.put(Constants.KEY_HASH, hashMap);
        source.put(Constants.KEY_DOCUMENT, document);

        this.client.index(
                new IndexRequest(Constants.INDEX_INTEGRATIONS)
                        .id(id)
                        .source(source)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE),
                ActionListener.wrap(indexResponse -> listener.onResponse(null), listener::onFailure));
    }

    /**
     * Unlinks a resource from all integrations that reference it, using Optimistic Concurrency
     * Control (OCC) to protect against concurrent updates.
     *
     * @param resourceId The ID of the resource to unlink.
     * @param listKey The key of the list field in the integration document (e.g., "rules").
     * @throws IOException If searching or updating the integration fails.
     */
    public void unlinkResourceFromIntegrations(String resourceId, String listKey) throws IOException {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_INTEGRATIONS);
        BoolQueryBuilder query =
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery(Constants.KEY_DOCUMENT + "." + listKey, resourceId))
                        .filter(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
        searchRequest.source().query(query);

        try {
            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                String integrationId = hit.getId();
                boolean success = false;
                for (int attempt = 1;
                        attempt <= PluginSettings.getInstance().getIntegrationMaxUpdateAttempts();
                        attempt++) {
                    try {
                        GetRequest getRequest = new GetRequest(Constants.INDEX_INTEGRATIONS, integrationId);
                        GetResponse getResponse = this.client.get(getRequest).actionGet();

                        if (!getResponse.isExists()) {
                            log.warn(
                                    "Integration [{}] not found during unlink. It may have been concurrently deleted.",
                                    integrationId);
                            break;
                        }

                        long seqNo = getResponse.getSeqNo();
                        long primaryTerm = getResponse.getPrimaryTerm();
                        Map<String, Object> source = getResponse.getSourceAsMap();

                        @SuppressWarnings("unchecked")
                        Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

                        if (document == null) {
                            break;
                        }

                        @SuppressWarnings("unchecked")
                        List<String> list = (List<String>) document.get(listKey);

                        if (list == null || !list.contains(resourceId)) {
                            success = true;
                            break;
                        }

                        List<String> updatedList = new ArrayList<>(list);
                        updatedList.remove(resourceId);
                        document.put(listKey, updatedList);

                        JsonNode documentNode = this.mapper.valueToTree(document);
                        String newHash = Resource.computeSha256(documentNode.toString());

                        @SuppressWarnings("unchecked")
                        Map<String, Object> hashMap =
                                (Map<String, Object>) source.getOrDefault(Constants.KEY_HASH, new HashMap<>());
                        hashMap.put(Constants.KEY_SHA256, newHash);
                        source.put(Constants.KEY_HASH, hashMap);
                        source.put(Constants.KEY_DOCUMENT, document);

                        IndexRequest indexRequest =
                                new IndexRequest(Constants.INDEX_INTEGRATIONS)
                                        .id(integrationId)
                                        .source(source)
                                        .setIfSeqNo(seqNo)
                                        .setIfPrimaryTerm(primaryTerm)
                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

                        this.client.index(indexRequest).actionGet();
                        success = true;
                        break;

                    } catch (VersionConflictEngineException e) {
                        log.debug(
                                "Version conflict updating integration [{}]. Attempt {} of {}",
                                integrationId,
                                attempt,
                                PluginSettings.getInstance().getIntegrationMaxUpdateAttempts());
                        if (attempt == PluginSettings.getInstance().getIntegrationMaxUpdateAttempts()) {
                            // Rethrown as-is (not wrapped) so it keeps resolving to 409 Conflict at the
                            // response layer instead of a generic 500 — this is an expected outcome under
                            // concurrency, not a server fault.
                            log.warn(
                                    "Failed to unlink resource from integration [{}] after {} concurrent modification retries.",
                                    integrationId,
                                    PluginSettings.getInstance().getIntegrationMaxUpdateAttempts());
                            throw e;
                        }
                    }
                }

                if (!success) {
                    throw new IOException(
                            "Failed to successfully unlink resource from integration [" + integrationId + "].");
                }
            }
        } catch (IOException e) {
            throw e;
        } catch (VersionConflictEngineException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error unlinking resource [{}] from integrations: {}", resourceId, e.getMessage());
            throw new IOException("Failed to unlink resource from integrations: " + e.getMessage(), e);
        }
    }

    /**
     * Updates the integration document in the index with a recalculated hash.
     *
     * @param id Integration ID.
     * @param document The updated document content.
     * @param source The full source map including metadata.
     * @throws IOException If indexing fails.
     */
    public void updateIntegrationSource(
            String id, Map<String, Object> document, Map<String, Object> source) throws IOException {
        JsonNode documentNode = this.mapper.valueToTree(document);
        String newHash = Resource.computeSha256(documentNode.toString());

        Map<String, Object> hashMap = new HashMap<>();
        hashMap.put(Constants.KEY_SHA256, newHash);
        source.put(Constants.KEY_HASH, hashMap);
        source.put(Constants.KEY_DOCUMENT, document);

        this.client
                .index(
                        new IndexRequest(Constants.INDEX_INTEGRATIONS)
                                .id(id)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    /**
     * Empties the given list fields of an integration document and reports whether the integration is
     * left with no decoders, rules or kvdbs. Used by the scoped space clears to keep the integration
     * documents consistent after a bulk delete of their resources.
     *
     * @param integrationId The integration document id.
     * @param listKeys The list fields to empty (e.g. {@code decoders}, {@code kvdbs}).
     * @param listener receives the {@link EmptyResult} once the document has been written (or
     *     immediately, when nothing changed).
     */
    @SuppressWarnings("unchecked")
    public void emptyFieldsAsync(
            String integrationId, Set<String> listKeys, ActionListener<EmptyResult> listener) {
        this.client.get(
                new GetRequest(Constants.INDEX_INTEGRATIONS, integrationId),
                ActionListener.wrap(
                        response -> {
                            if (!response.isExists()) {
                                listener.onFailure(
                                        new IOException("Integration [" + integrationId + "] not found."));
                                return;
                            }
                            Map<String, Object> source = response.getSourceAsMap();
                            Map<String, Object> document =
                                    (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
                            if (document == null) {
                                listener.onResponse(new EmptyResult(false, true));
                                return;
                            }
                            boolean isProtected =
                                    Constants.MODE_PROTECTED.equals(document.get(Constants.KEY_MODE));
                            boolean changed = false;
                            for (String key : listKeys) {
                                if (!isEmptyList(document.get(key))) {
                                    document.put(key, new ArrayList<>());
                                    changed = true;
                                }
                            }
                            boolean nowEmpty =
                                    isEmptyList(document.get(Constants.KEY_DECODERS))
                                            && isEmptyList(document.get(Constants.KEY_RULES))
                                            && isEmptyList(document.get(Constants.KEY_KVDBS));
                            if (changed) {
                                this.updateIntegrationSourceAsync(
                                        response.getId(),
                                        document,
                                        source,
                                        ActionListener.wrap(
                                                v -> listener.onResponse(new EmptyResult(isProtected, nowEmpty)),
                                                listener::onFailure));
                            } else {
                                listener.onResponse(new EmptyResult(isProtected, nowEmpty));
                            }
                        },
                        listener::onFailure));
    }

    /**
     * Deletes an integration document by its id.
     *
     * @param integrationId The integration document id.
     * @param listener notified once the document has been deleted.
     */
    public void deleteIntegrationDocAsync(String integrationId, ActionListener<Void> listener) {
        this.client.delete(
                new DeleteRequest(Constants.INDEX_INTEGRATIONS, integrationId)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE),
                ActionListener.wrap(response -> listener.onResponse(null), listener::onFailure));
    }

    /**
     * Lists the OpenSearch document ids of every integration in a space.
     *
     * @param spaceName The space to filter by.
     * @param listener receives the integration ids.
     */
    public void listIntegrationIdsAsync(String spaceName, ActionListener<List<String>> listener) {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_INTEGRATIONS);
        searchRequest.source(
                new SearchSourceBuilder()
                        .query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName))
                        .fetchSource(false)
                        .size(Constants.MAX_RESULT_WINDOW));
        this.client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            List<String> ids = new ArrayList<>();
                            for (SearchHit hit : response.getHits().getHits()) {
                                ids.add(hit.getId());
                            }
                            listener.onResponse(ids);
                        },
                        listener::onFailure));
    }

    private static boolean isEmptyList(Object value) {
        return !(value instanceof List<?> list) || list.isEmpty();
    }

    /**
     * Outcome of {@link #emptyFieldsAsync}: whether the integration is protected, and whether its
     * decoders, rules and kvdbs lists are all empty after the edit.
     */
    public record EmptyResult(boolean isProtected, boolean nowEmpty) {}
}
