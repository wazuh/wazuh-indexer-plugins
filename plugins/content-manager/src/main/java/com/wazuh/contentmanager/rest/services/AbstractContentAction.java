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

import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;

import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Base abstract class for Content Manager REST actions.
 *
 * <p>This class provides the foundational structure for handling CTI content requests, including
 * dependency management (Engine, PolicyHashService, SecurityAnalyticsService) and common request
 * preparation steps like ID extraction.
 */
public abstract class AbstractContentAction extends BaseRestHandler {

    protected final EngineService engine;
    protected PolicyHashService policyHashService;
    protected SecurityAnalyticsService securityAnalyticsService;

    /**
     * Constructor for AbstractContentAction.
     *
     * @param engine The engine service used for validation and logic execution.
     */
    public AbstractContentAction(EngineService engine) {
        this.engine = engine;
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
     * Executes the specific business logic for the REST action.
     *
     * @param request The incoming REST request.
     * @param client The OpenSearch client.
     * @return A RestResponse indicating the result.
     */
    protected abstract RestResponse executeRequest(RestRequest request, Client client);
}
