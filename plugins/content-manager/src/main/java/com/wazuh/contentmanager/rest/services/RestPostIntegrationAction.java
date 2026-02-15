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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for creating integration resources.
 *
 * <p>Endpoint: POST /_plugins/_content_manager/integrations
 *
 * <p>Creates an integration in the draft space. This involves:
 *
 * <ul>
 *   <li>Validating mandatory fields (title, author, category).
 *   <li>Generating a UUID and timestamps.
 *   <li>Upserting the integration into the Security Analytics Service (SAP).
 *   <li>Validating the integration payload with the Engine.
 *   <li>Indexing the document in the integrations index.
 *   <li>Linking the new integration to the draft Policy.
 * </ul>
 */
public class RestPostIntegrationAction extends AbstractCreateAction {

    private static final String ENDPOINT_NAME = "content_manager_integration_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_create";

    public RestPostIntegrationAction(EngineService engine) {
        super(engine);
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Defines the routes supported by this REST handler.
     *
     * @return An immutable list containing the POST route for creating integrations.
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.INTEGRATIONS_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_INTEGRATIONS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_INTEGRATION;
    }

    @Override
    protected boolean requiresIntegrationId() {
        return false;
    }

    /**
     * Validates that the integration payload contains all required fields and initializes empty lists
     * for rules, decoders, and kvdbs.
     */
    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        if (!resource.has(Constants.KEY_TITLE)
                || resource.get(Constants.KEY_TITLE).asText().isBlank()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_TITLE),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        if (!resource.has(Constants.KEY_CATEGORY)
                || resource.get(Constants.KEY_CATEGORY).asText().isBlank()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_CATEGORY),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        ((ObjectNode) resource).set(Constants.KEY_RULES, MAPPER.createArrayNode());
        ((ObjectNode) resource).set(Constants.KEY_DECODERS, MAPPER.createArrayNode());
        ((ObjectNode) resource).set(Constants.KEY_KVDBS, MAPPER.createArrayNode());

        return null;
    }

    /**
     * Synchronizes the new integration with external services. 1. Validates with Engine. If
     * validation fails, SAP upsert is rolled back. 2. Upserts to SAP.
     */
    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        // 1. Engine Validate
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set(Constants.KEY_RESOURCE, resource);
        enginePayload.put(Constants.KEY_TYPE, Constants.KEY_INTEGRATION);

        RestResponse engineResponse = this.engine.validate(enginePayload);
        if (engineResponse.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    "Engine Validation Failed: " + engineResponse.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // 2. SAP Upsert
        try {
            this.securityAnalyticsService.upsertIntegration(resource, Space.DRAFT, POST);
        } catch (Exception e) {
            return new RestResponse(
                    "SAP Upsert Error: " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        return null;
    }

    @Override
    protected void rollbackExternalServices(String id) {
        this.securityAnalyticsService.deleteIntegration(id);
    }

    /**
     * Links the new integration to the draft policy by adding its ID to the policy's integrations
     * list.
     */
    @Override
    protected void linkToParent(Client client, String id, JsonNode root) throws IOException {
        ContentIndex policiesIndex = new ContentIndex(client, Constants.INDEX_POLICIES);
        TermQueryBuilder queryBuilder =
                new TermQueryBuilder(Constants.Q_SPACE_NAME, Space.DRAFT.toString());
        ObjectNode searchResult = policiesIndex.searchByQuery(queryBuilder);

        if (searchResult == null
                || !searchResult.has(Constants.Q_HITS)
                || searchResult.get(Constants.Q_HITS).isEmpty()) {
            throw new IllegalStateException("Draft policy not found");
        }

        ArrayNode hitsArray = (ArrayNode) searchResult.get(Constants.Q_HITS);
        JsonNode draftPolicyHit = hitsArray.get(0);
        String draftPolicyId = draftPolicyHit.get(Constants.KEY_ID).asText();
        JsonNode document = draftPolicyHit.get(Constants.KEY_DOCUMENT);

        ArrayNode integrations = (ArrayNode) document.get(Constants.KEY_INTEGRATIONS);
        if (integrations == null) integrations = MAPPER.createArrayNode();

        integrations.add(id);

        String hash = HashCalculator.sha256(document.toString());
        ((ObjectNode) draftPolicyHit.at("/hash")).put(Constants.KEY_SHA256, hash);

        policiesIndex.create(draftPolicyId, draftPolicyHit);
    }
}
