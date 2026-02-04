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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for deleting CTI decoders.
 *
 * <p>Endpoint: DELETE /_plugins/content-manager/decoder/{decoder_id}
 *
 * <p>This handler processes decoder deletion requests. When a decoder is deleted, it is also
 * removed from any integrations that reference it.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Decoder deleted successfully.
 *   <li>400 Bad Request: Decoder ID is missing or invalid.
 *   <li>500 Internal Server Error: Unexpected error during processing or engine unavailable.
 * </ul>
 */
public class RestDeleteDecoderAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestDeleteDecoderAction.class);
    // TODO: Move to a common constants class
    private static final String ENDPOINT_NAME = "content_manager_decoder_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/decoder_delete";
    private static final String DECODER_INDEX = ".cti-decoders";
    private static final String INTEGRATION_INDEX = ".cti-integrations";
    private static final String INDEX_ID_PREFIX = "d_";
    private static final String FIELD_DECODER_ID_PARAM = "decoder_id";
    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_DECODERS = "decoders";
    private final EngineService engine;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Constructs a new RestDeleteDecoderAction handler.
     *
     * @param engine the engine service instance for communication with the Wazuh engine
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
     * Prepares the REST request for processing.
     *
     * @param request the incoming REST request containing the decoder ID
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

    /**
     * Handles the decoder deletion request.
     *
     * <p>This method validates the request, deletes the decoder from the index, and removes
     * references to the decoder from any integrations that include it.
     *
     * @param request the incoming REST request containing the decoder ID to delete
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

            String decoderId = request.param("id");
            if (decoderId == null || decoderId.isBlank()) {
                decoderId = request.param(FIELD_DECODER_ID_PARAM);
            }
            if (decoderId == null || decoderId.isBlank()) {
                return new RestResponse("Decoder ID is required.", RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }
            final String resolvedDecoderId = decoderId;

            String decoderIndexName = DECODER_INDEX;
            ensureIndexExists(client, decoderIndexName);
            // Validate decoder is in draft space
            String validationError =
                    DocumentValidations.validateDocumentInSpace(
                            client, DECODER_INDEX, resolvedDecoderId, "Decoder");
            if (validationError != null) {
                return new RestResponse(validationError, RestStatus.BAD_REQUEST.getStatus())
                        .toBytesRestResponse();
            }

            ContentIndex decoderIndex = new ContentIndex(client, decoderIndexName, null);

            // Check if decoder exists before deleting
            if (!decoderIndex.exists(resolvedDecoderId)) {
                return new RestResponse(
                                "Decoder [" + resolvedDecoderId + "] not found.", RestStatus.NOT_FOUND.getStatus())
                        .toBytesRestResponse();
            }

            String nonPrefixedId = removeDraftPrefix(resolvedDecoderId);
            updateIntegrationsRemovingDecoder(client, nonPrefixedId);
            decoderIndex.delete(resolvedDecoderId);

            // Regenerate space hash because decoder was removed from space
            regenerateSpaceHash(client, Space.DRAFT.toString());

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

    private static void ensureIndexExists(Client client, String indexName) throws IOException {
        if (!IndexHelper.indexExists(client, indexName)) {
            ContentIndex index = new ContentIndex(client, indexName, null);
            try {
                index.createIndex();
            } catch (Exception e) {
                throw new IOException("Failed to create index " + indexName, e);
            }
        }
    }

    private static String removeDraftPrefix(String decoderId) {
        return decoderId.startsWith(INDEX_ID_PREFIX) ? decoderId.substring(2) : decoderId;
    }

    /**
     * Regenerates the space hash by using PolicyHashService.
     *
     * @param client the OpenSearch client
     * @param spaceName the name of the space to regenerate hash for
     */
    private static void regenerateSpaceHash(Client client, String spaceName) {
        PolicyHashService policyHashService = new PolicyHashService(client);

        // Use PolicyHashService to recalculate space hash for the given space
        policyHashService.calculateAndUpdate(
                Constants.INDEX_POLICIES,
                Constants.INDEX_INTEGRATIONS,
                Constants.INDEX_DECODERS,
                Constants.INDEX_KVDBS,
                Constants.INDEX_RULES,
                List.of(spaceName));

        log.debug("Regenerated space hash for space={}", spaceName);
    }

    private void updateIntegrationsRemovingDecoder(Client client, String decoderIndexId) {
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
            if (decodersObj instanceof List<?> list) {
                java.util.List<Object> updated = new java.util.ArrayList<>(list);
                updated.removeIf(item -> decoderIndexId.equals(String.valueOf(item)));
                doc.put(FIELD_DECODERS, updated);
                source.put(FIELD_DOCUMENT, doc);

                // Regenerate integration hash and persist
                try {
                    RestPostDecoderAction.regenerateIntegrationHash(client, hit.getId(), doc, source);
                } catch (IOException e) {
                    log.error(
                            "Failed to regenerate hash for integration [{}]: {}",
                            hit.getId(),
                            e.getMessage());
                }
            }
        }
    }
}
