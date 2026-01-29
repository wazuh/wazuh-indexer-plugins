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
 * TODO !CHANGE_ME DELETE /_plugins/content-manager/decoder/{decoder_id}
 *
 * <p>Deletes a decoder
 *
 * <p>Possible HTTP responses: - 200 Accepted: Wazuh Engine replied with a successful response. -
 * 400 Bad Request: Wazuh Engine replied with an error response. - 500 Internal Server Error:
 * Unexpected error during processing. Wazuh Engine did not respond.
 */
public class RestDeleteDecoderAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_decoder_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_delete";
    private static final Logger log = LogManager.getLogger(RestDeleteDecoderAction.class);
    private static final String DECODER_MAPPINGS = "/mappings/cti-decoders-mappings.json";
    private static final String DECODER_ALIAS = ".cti-decoders";
    private static final String INTEGRATION_INDEX = ".cti-integrations";
    private static final String FIELD_DECODER_ID_PARAM = "decoder_id";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_DECODERS = "decoders";
    private final EngineService engine;

    /**
     * Constructs a new TODO !CHANGE_ME.
     *
     * @param engine The service instance to communicate with the local engine service.
     */
    public RestDeleteDecoderAction(EngineService engine) {
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
                        .path(PluginSettings.DECODERS_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a consumer that executes the update operation
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        // Consume path params early to avoid unrecognized parameter errors.
        request.param("id");
        return channel -> channel.sendResponse(this.handleRequest(request, client));
    }

    /**
     * TODO !CHANGE_ME.
     *
     * @param request incoming request
     * @param client the node client
     * @return a BytesRestResponse describing the outcome
     */
    public BytesRestResponse handleRequest(RestRequest request, Client client) {
        try {
            if (this.engine == null) {
                RestResponse error =
                        new RestResponse(
                                "Engine service unavailable.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
                return error.toBytesRestResponse();
            }

            String decoderId = request.param("id");
            if (decoderId == null || decoderId.isBlank()) {
                decoderId = request.param(FIELD_DECODER_ID_PARAM);
            }
            if (decoderId == null || decoderId.isBlank()) {
                return new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }
            final String resolvedDecoderId = decoderId;

            if (client != null) {
                String decoderIndexName = DECODER_ALIAS;
                ensureIndexExists(client, decoderIndexName, DECODER_MAPPINGS, DECODER_ALIAS);
                ContentIndex decoderIndex =
                        new ContentIndex(client, decoderIndexName, DECODER_MAPPINGS, DECODER_ALIAS);
                updateIntegrationsRemovingDecoder(client, resolvedDecoderId);
                decoderIndex.delete(resolvedDecoderId);
            }

            return new RestResponse("Decoder deleted successfully.", RestStatus.OK.getStatus())
                    .toBytesRestResponse();
        } catch (Exception e) {
            log.error("Error deleting decoder: {}", e.getMessage(), e);
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

    private static void updateIntegrationsRemovingDecoder(Client client, String decoderIndexId) {
        SearchRequest searchRequest = new SearchRequest(INTEGRATION_INDEX);
        searchRequest
                .source()
                .query(QueryBuilders.termQuery(FIELD_DOCUMENT + "." + FIELD_DECODERS, decoderIndexId));
        SearchResponse searchResponse = client.search(searchRequest).actionGet();
        for (org.opensearch.search.SearchHit hit : searchResponse.getHits().getHits()) {
            Map<String, Object> source = hit.getSourceAsMap();
            Object documentObj = source.get(FIELD_DOCUMENT);
            if (!(documentObj instanceof Map)) {
                log.warn(
                        "Integration document [{}] is invalid while removing decoder [{}].",
                        hit.getId(),
                        decoderIndexId);
                continue;
            }
            Map<String, Object> doc = new java.util.HashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) documentObj).entrySet()) {
                doc.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            Object decodersObj = doc.get(FIELD_DECODERS);
            if (decodersObj instanceof List) {
                List<?> list = (List<?>) decodersObj;
                java.util.List<Object> updated = new java.util.ArrayList<>(list);
                updated.removeIf(item -> decoderIndexId.equals(String.valueOf(item)));
                doc.put(FIELD_DECODERS, updated);
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
