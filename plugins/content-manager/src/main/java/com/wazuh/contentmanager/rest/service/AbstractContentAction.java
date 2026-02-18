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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
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
     * Adds or updates timestamp metadata (date, modified) in the resource node.
     *
     * @param resourceNode The resource object to update.
     * @param isCreate If true, sets creation 'date'. Always sets 'modified'.
     * @param isDecoder If true, uses the decoder specific metadata structure.
     */
    protected void updateTimestampMetadata(
            ObjectNode resourceNode, boolean isCreate, boolean isDecoder) {
        String currentTimestamp = getCurrentDate();

        if (isDecoder) {
            ObjectNode metadataNode;
            if (resourceNode.has(Constants.KEY_METADATA)
                    && resourceNode.get(Constants.KEY_METADATA).isObject()) {
                metadataNode = (ObjectNode) resourceNode.get(Constants.KEY_METADATA);
            } else {
                metadataNode = CONTENT_MAPPER.createObjectNode();
                resourceNode.set(Constants.KEY_METADATA, metadataNode);
            }

            ObjectNode authorNode;
            if (metadataNode.has(Constants.KEY_AUTHOR)
                    && metadataNode.get(Constants.KEY_AUTHOR).isObject()) {
                authorNode = (ObjectNode) metadataNode.get(Constants.KEY_AUTHOR);
            } else {
                authorNode = CONTENT_MAPPER.createObjectNode();
                metadataNode.set(Constants.KEY_AUTHOR, authorNode);
            }

            if (isCreate) {
                authorNode.put(Constants.KEY_DATE, currentTimestamp);
            }
            authorNode.put(Constants.KEY_MODIFIED, currentTimestamp);
        } else {
            if (isCreate) {
                resourceNode.put(Constants.KEY_DATE, currentTimestamp);
            }
            resourceNode.put(Constants.KEY_MODIFIED, currentTimestamp);
        }
    }

    /**
     * Builds the standard CTI wrapper payload containing document, space, and hash.
     *
     * @param resourceNode The content of the resource.
     * @param spaceName The space name (e.g., "draft").
     * @return The constructed JsonNode wrapper.
     */
    protected JsonNode buildCtiWrapper(JsonNode resourceNode, String spaceName) {
        ObjectNode wrapper = CONTENT_MAPPER.createObjectNode();
        wrapper.set(Constants.KEY_DOCUMENT, resourceNode);

        ObjectNode space = CONTENT_MAPPER.createObjectNode();
        space.put(Constants.KEY_NAME, spaceName);
        wrapper.set(Constants.KEY_SPACE, space);

        String hash = computeSha256(resourceNode.toString());
        ObjectNode hashNode = CONTENT_MAPPER.createObjectNode();
        hashNode.put(Constants.KEY_SHA256, hash);
        wrapper.set(Constants.KEY_HASH, hashNode);

        return wrapper;
    }

    /**
     * Computes SHA-256 hash of a string.
     *
     * @param payload The string to hash.
     * @return The hex representation of the hash.
     */
    protected static String computeSha256(String payload) {
        try {
            byte[] hash =
                    MessageDigest.getInstance("SHA-256").digest(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("Error hashing content", e);
            return "";
        }
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

        this.spaceService = new SpaceService(client);
        this.securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        this.integrationService = new IntegrationService(client);

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
