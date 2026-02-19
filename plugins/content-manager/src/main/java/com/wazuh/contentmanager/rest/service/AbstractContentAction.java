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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.helpers.MockSecurityAnalyticsService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Base abstract class for Content Manager REST actions.
 *
 * <p>This class provides the foundational structure for handling CTI content requests, including
 * dependency management (Engine, SpaceService, SecurityAnalyticsService) and common request
 * preparation steps like ID extraction.
 */
public abstract class AbstractContentAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(AbstractContentAction.class);
    protected static final ObjectMapper CONTENT_MAPPER = new ObjectMapper();
    protected final EngineService engine;
    protected SpaceService spaceService;
    protected SecurityAnalyticsService securityAnalyticsService;
    protected IntegrationService integrationService;

    /**
     * Constructor for AbstractContentAction.
     *
     * @param engine The engine service used for validation and logic execution.
     */
    public AbstractContentAction(EngineService engine) {
        this.engine = engine;
    }

    /**
     * Generate current date in ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ).
     *
     * @return String representing current date.
     */
    protected String getCurrentDate() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
    }

    /**
     * Prepares the REST request by initializing common services and extracting path parameters.
     *
     * @param request the incoming REST request
     * @param client the node client
     * @return a RestChannelConsumer that executes the specific logic of the implementing class
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        // Consume path ID parameter early to avoid unrecognized parameter errors
        if (request.hasParam(Constants.KEY_ID)) {
            request.param(Constants.KEY_ID);
        }

        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            this.securityAnalyticsService = new MockSecurityAnalyticsService();
        } else {
            this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        }
        this.spaceService = new SpaceService(client);
        this.integrationService = new IntegrationService(client);

        return channel -> {
            RestResponse validationError = this.validateDraftPolicyExists(client);
            if (validationError != null) {
                channel.sendResponse(validationError.toBytesRestResponse());
                return;
            }
            try {
                RestResponse result = executeRequest(request, client);
                channel.sendResponse(result.toBytesRestResponse());
            } catch (Exception e) {
                sendErrorResponse(channel, e);
            }
        };
    }

    /** Sets the policy hash service (for testing). */
    public void setPolicyHashService(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    /** Sets the security analytics service (for testing). */
    public void setSecurityAnalyticsService(SecurityAnalyticsService securityAnalyticsService) {
        this.securityAnalyticsService = securityAnalyticsService;
    }

    /** Sets the integration service (for testing). */
    public void setIntegrationService(IntegrationService integrationService) {
        this.integrationService = integrationService;
    }

    /**
     * Checks synchronously if the policy document for the draft space exists.
     *
     * @param client The OpenSearch client.
     * @return A RestResponse with an error if the draft policy is missing, or {@code null} if valid.
     */
    protected RestResponse validateDraftPolicyExists(Client client) {
        try {
            SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
            sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
            sourceBuilder.size(0);
            searchRequest.source(sourceBuilder);

            SearchResponse response = client.search(searchRequest).actionGet();

            if (Objects.requireNonNull(response.getHits().getTotalHits()).value() == 0) {
                log.error("Failed to find Draft policy document");
                return new RestResponse(
                        "Draft policy not found.", RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }
        } catch (Exception ex) {
            return new RestResponse(
                    "Draft policy check failed: " + ex.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Sends an error response on the channel.
     *
     * @param channel The REST channel.
     * @param e The exception.
     */
    private static void sendErrorResponse(RestChannel channel, Exception e) {
        try {
            log.error("Error processing request", e);
            RestResponse error =
                    new RestResponse(e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            channel.sendResponse(error.toBytesRestResponse());
        } catch (Exception ex) {
            log.error("Failed to send error response", ex);
        }
    }

    /**
     * Executes the specific business logic for the REST action.
     *
     * @param request The incoming REST request.
     * @param client The OpenSearch client.
     * @return A RestResponse indicating the result.
     */
    protected abstract RestResponse executeRequest(RestRequest request, Client client);
}
