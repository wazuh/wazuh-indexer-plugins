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
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.JsonNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/decoders
 *
 * <p>Creates a new Decoder in the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The payload contains all mandatory fields.
 *   <li>The parent integration exists and is in the draft space.
 *   <li>A new UUID and creation timestamps (in the correct author structure) are generated.
 *   <li>The decoder content is validated by the Engine.
 *   <li>The decoder is indexed in the draft space.
 *   <li>The new decoder is linked to the parent Integration.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: Decoder created successfully.
 *   <li>400 Bad Request: Missing fields, invalid payload, or Engine validation failure.
 *   <li>500 Internal Server Error: Engine unavailable or unexpected error.
 * </ul>
 */
public class RestPostDecoderAction extends AbstractCreateAction {

    private static final Logger log = LogManager.getLogger(RestPostDecoderAction.class);
    private static final String ENDPOINT_NAME = "content_manager_decoder_create";

    public RestPostDecoderAction(EngineService engine) {
        super(engine);
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the delete endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, PluginSettings.DECODERS_URI));
    }

    @Override
    protected boolean supportsYamlField() {
        return true;
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_DECODERS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_DECODER;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        String spaceError =
                this.documentValidations.validateDocumentInSpace(
                        client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
        if (spaceError != null) return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());

        // Enforce max decoders limit
        int maxDecoders = PluginSettings.getInstance().getMaxDecoders();
        SearchRequest countRequest = new SearchRequest(Constants.INDEX_DECODERS);
        SearchSourceBuilder countSource = new SearchSourceBuilder();
        countSource.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
        countSource.size(0);
        countSource.trackTotalHits(true);
        countRequest.source(countSource);
        try {
            SearchResponse countResponse = client.search(countRequest).actionGet();
            long count =
                    countResponse.getHits().getTotalHits() != null
                            ? countResponse.getHits().getTotalHits().value()
                            : 0;
            if (count >= maxDecoders) {
                log.info(Constants.I_LOG_MAX_DECODERS_REACHED, maxDecoders);
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_TOO_MANY_DECODERS, maxDecoders),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        } catch (Exception e) {
            // If counting fails (e.g., index does not exist yet), allow creation to proceed.
            log.warn("Failed to count existing decoders for limit check: {}", e.getMessage());
        }

        return null;
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        RestResponse engineValidation = this.engine.validateResource(Constants.KEY_DECODER, resource);
        if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    Constants.E_400_ENGINE_VALIDATION_FAILED + " " + engineValidation.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    @Override
    protected void linkToParent(Client client, String id, JsonNode root) throws IOException {
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        this.integrationService.linkResourceToIntegration(integrationId, id, Constants.KEY_DECODERS);
    }
}
