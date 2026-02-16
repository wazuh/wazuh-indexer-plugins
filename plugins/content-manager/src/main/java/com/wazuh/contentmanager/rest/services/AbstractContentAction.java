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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.Objects;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;

/**
 * Base abstract class for Content Manager REST actions.
 *
 * <p>This class provides the foundational structure for handling CTI content requests, including
 * dependency management (Engine, PolicyHashService, SecurityAnalyticsService) and common request
 * preparation steps like ID extraction.
 */
public abstract class AbstractContentAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(AbstractContentAction.class);
    protected final EngineService engine;
    protected final ContentUtils contentUtils;
    protected PolicyHashService policyHashService;
    protected SecurityAnalyticsService securityAnalyticsService;

    /**
     * Constructor for AbstractContentAction.
     *
     * @param engine The engine service used for validation and logic execution.
     */
    public AbstractContentAction(EngineService engine) {
        this.engine = engine;
        this.contentUtils = new ContentUtils();
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

        this.policyHashService = new PolicyHashService(client);
        this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);

        return channel -> {
            RestResponse validation = this.validateDraftPolicyExists(client);
            if (validation != null) {
                channel.sendResponse(validation.toBytesRestResponse());
                return;
            }
            RestResponse response = this.executeRequest(request, client);
            channel.sendResponse(response.toBytesRestResponse());
        };
    }

    /** Sets the policy hash service (for testing). */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    /** Sets the security analytics service (for testing). */
    public void setSecurityAnalyticsService(SecurityAnalyticsService securityAnalyticsService) {
        this.securityAnalyticsService = securityAnalyticsService;
    }

    /**
     * Checks if the policy document for the draft space exists.
     *
     * @param client The OpenSearch client.
     * @return RestResponse with error if policy is missing, null otherwise.
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
        } catch (Exception e) {
            return new RestResponse(
                    "Draft policy check failed: " + e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
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
