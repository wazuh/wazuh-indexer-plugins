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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/rules
 *
 * <p>Creates a new Rule in the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The payload contains all mandatory fields (title).
 *   <li>The parent integration exists and is in the draft space.
 *   <li>A new UUID and creation timestamps are generated.
 *   <li>The rule is created in the Security Analytics Plugin (SAP).
 *   <li>The rule is indexed in the draft space.
 *   <li>The new rule is linked to the parent Integration.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: Rule created successfully.
 *   <li>400 Bad Request: Missing fields, invalid payload, or parent integration validation failure.
 *   <li>500 Internal Server Error: SAP error or unexpected error.
 * </ul>
 */
public class RestPostRuleAction extends AbstractCreateAction {

    private static final String ENDPOINT_NAME = "content_manager_rule_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/rule_create";

    public RestPostRuleAction() {
        super(null);
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
                        .path(PluginSettings.RULES_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_RULES;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_RULE;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        if (!resource.has(Constants.KEY_TITLE)
                || resource.get(Constants.KEY_TITLE).asText().isBlank()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_TITLE),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        String spaceError =
                com.wazuh.contentmanager.utils.DocumentValidations.validateDocumentInSpace(
                        client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
        if (spaceError != null) return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());

        return null;
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        try {
            this.securityAnalyticsService.upsertRule(resource, Space.DRAFT);
            return null;
        } catch (Exception e) {
            return new RestResponse(
                    "SAP Error: " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    @Override
    protected void linkToParent(Client client, String id, JsonNode root) throws IOException {
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        ContentUtils.linkResourceToIntegration(client, integrationId, id, Constants.KEY_RULES);
    }
}
