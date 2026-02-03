/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.rest.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for deleting CTI KVDBs.
 *
 * <p>Endpoint: DELETE /_plugins/_content_manager/kvdbs/{kvdb_id}
 *
 * <p>This handler processes KVDB deletion requests. When a KVDB is deleted, it is also removed from
 * any integrations that reference it.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: KVDB deleted successfully.
 *   <li>400 Bad Request: KVDB ID is missing or invalid.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestDeleteKvdbAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_kvdb_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/kvdb_delete";
    private static final Logger log = LogManager.getLogger(RestDeleteKvdbAction.class);
    private static final String KVDB_MAPPINGS = "/mappings/cti-kvdbs-mappings.json";
    private static final String KVDB_ALIAS = ".cti-kvdbs";
    private static final String INTEGRATION_INDEX = ".cti-integrations";
    private static final String FIELD_KVDB_ID_PARAM = "kvdb_id";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_KVDBS = "kvdbs";
    private final EngineService engine;

    /**
     * Constructs a new RestDeleteKvdbAction handler.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestDeleteKvdbAction(EngineService engine) {
        this.engine = engine;
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.KVDBS_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the REST request for processing.
     *
     * @param request the incoming REST request containing the KVDB ID
     * @param client the node client for executing operations
     * @return a consumer that executes the delete operation and sends the response
     * @throws IOException if an I/O error occurs during request preparation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        // Consume path params early to avoid unrecognized parameter errors.
        request.param("id");
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /*
     * Handles the KVDB deletion request.
     *
     * <p>This method validates the request, deletes the KVDB from the index, and removes
     * references to the KVDB from any integrations that include it.
     *
     * @param request the incoming REST request containing the KVDB ID to delete
     * @param client the OpenSearch client for index operations
     * @return a BytesRestResponse indicating success or failure of the deletion
     */
    public BytesRestResponse handleRequest(RestRequest request, Client client) {
        try {
            if (this.engine == null) {
                RestResponse error =
                        new RestResponse(
                                "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                return error.toBytesRestResponse();
            }

            String kvdbId = request.param("id");
            if (kvdbId == null || kvdbId.isBlank()) {
                kvdbId = request.param(FIELD_KVDB_ID_PARAM);
            }
            if (kvdbId == null || kvdbId.isBlank()) {
                return new RestResponse("KVDB ID is required.", RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }

            String kvdbIndexName = KVDB_ALIAS;
            ensureIndexExists(client, kvdbIndexName, KVDB_MAPPINGS, KVDB_ALIAS);
            ContentIndex kvdbIndex = new ContentIndex(client, kvdbIndexName, KVDB_MAPPINGS, KVDB_ALIAS);
            updateIntegrationsRemovingKvdb(client, kvdbId);
            kvdbIndex.delete(kvdbId);

            return new RestResponse("KVDB deleted successfully.", RestStatus.CREATED.getStatus())
                    .toBytesRestResponse();
        } catch (Exception e) {
            log.error("Error deleting KVDB: {}", e.getMessage(), e);
            return new RestResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                    .toBytesRestResponse();
        }
    }

    private static void ensureIndexExists(
            Client client, String indexName, String mappingsPath, String alias) throws IOException {
        if (!IndexHelper.indexExists(client, indexName)) {
            ContentIndex index = new ContentIndex(client, indexName, mappingsPath, alias);
            try {
                index.createIndex();
            } catch (Exception e) {
                throw new IOException("Failed to create index " + indexName, e);
            }
        }
    }

    private static void updateIntegrationsRemovingKvdb(Client client, String kvdbIndexId) {
        SearchRequest searchRequest = new SearchRequest(INTEGRATION_INDEX);
        searchRequest
                .source()
                .query(QueryBuilders.termQuery(FIELD_DOCUMENT + "." + FIELD_KVDBS, kvdbIndexId));
        SearchResponse searchResponse = client.search(searchRequest).actionGet();
        for (org.opensearch.search.SearchHit hit : searchResponse.getHits().getHits()) {
            Map<String, Object> source = hit.getSourceAsMap();
            Object documentObj = source.get(FIELD_DOCUMENT);
            if (!(documentObj instanceof Map)) {
                log.warn(
                        "Integration document [{}] is invalid while removing KVDB [{}].",
                        hit.getId(),
                        kvdbIndexId);
                continue;
            }
            Map<String, Object> doc = new java.util.HashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) documentObj).entrySet()) {
                doc.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            Object kvdbsObj = doc.get(FIELD_KVDBS);
            if (kvdbsObj instanceof List) {
                List<?> list = (List<?>) kvdbsObj;
                java.util.List<Object> updated = new java.util.ArrayList<>(list);
                updated.removeIf(item -> kvdbIndexId.equals(String.valueOf(item)));
                doc.put(FIELD_KVDBS, updated);
                source.put(FIELD_DOCUMENT, doc);
                client
                        .index(
                                new IndexRequest(INTEGRATION_INDEX)
                                        .id(hit.getId())
                                        .source(source)
                                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                        .actionGet();
            }
        }
    }
}
