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
package com.wazuh.contentmanager.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/integrations/{id}
 *
 * <p>Deletes an existing integration from the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The integration exists and is in the draft space.
 *   <li>The integration does not have any attached resources (Rules, Decoders, KVDBs).
 *   <li>The integration is removed from the Security Analytics Plugin (SAP).
 *   <li>The integration is removed from the draft policy's integration list.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Integration deleted successfully.
 *   <li>400 Bad Request: Integration is not in draft space or has dependent resources.
 *   <li>404 Not Found: Integration with specified ID was not found.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestDeleteIntegrationAction extends AbstractDeleteAction {

    private static final String ENDPOINT_NAME = "content_manager_integration_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_delete";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Constructs a new RestDeleteIntegrationAction.
     *
     * @param engine The engine service (unused in delete operations but required by parent).
     */
    public RestDeleteIntegrationAction(EngineService engine) {
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
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.INTEGRATIONS_URI + "/{id}")
                        .method(DELETE)
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

    /**
     * Validates that the integration can be deleted.
     *
     * <p>Checks if the integration has any dependent resources (decoders, rules, kvdbs) linked to it.
     * If so, deletion must fail.
     */
    @Override
    protected RestResponse validateDelete(Client client, String id) {
        ContentIndex index = new ContentIndex(client, Constants.INDEX_INTEGRATIONS, null);
        JsonNode doc = index.getDocument(id);

        if (doc != null && doc.has(Constants.KEY_DOCUMENT)) {
            JsonNode document = doc.get(Constants.KEY_DOCUMENT);
            if (this.isListNotEmpty(document.get(Constants.KEY_DECODERS))) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_DECODERS),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            if (this.isListNotEmpty(document.get(Constants.KEY_RULES))) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_RULES),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            if (this.isListNotEmpty(document.get(Constants.KEY_KVDBS))) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_KVDBS),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    /** Deletes the integration from the Security Analytics Plugin. */
    @Override
    protected void deleteExternalServices(String id) {
        this.securityAnalyticsService.deleteIntegration(id, false);
    }

    /**
     * Removes the integration reference from the draft policy.
     *
     * <p>Searches for the policy in the draft space, removes the integration ID from its list of
     * integrations, and updates the policy hash.
     */
    @Override
    protected void unlinkFromParent(Client client, String id) throws Exception {
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
        if (integrations == null) return;

        ArrayNode updatedIntegrations = MAPPER.createArrayNode();
        boolean removed = false;
        for (JsonNode integrationId : integrations) {
            if (!integrationId.asText().equals(id)) {
                updatedIntegrations.add(integrationId);
            } else {
                removed = true;
            }
        }

        if (removed) {
            ((ObjectNode) document).set(Constants.KEY_INTEGRATIONS, updatedIntegrations);
            String hash = Resource.computeSha256(document.toString());
            ((ObjectNode) draftPolicyHit.at("/hash")).put(Constants.KEY_SHA256, hash);
            policiesIndex.create(draftPolicyId, draftPolicyHit, false);
        }
    }

    private boolean isListNotEmpty(JsonNode node) {
        return node != null && node.isArray() && !node.isEmpty();
    }
}
