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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * PUT /_plugins/content-manager/rules/{id}
 *
 * <p>Updates an existing Rule in the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The rule exists and is in the draft space.
 *   <li>The request body contains all mandatory fields.
 *   <li>Immutable metadata (creation date) is preserved.
 *   <li>The updated rule is synchronized with the Security Analytics Plugin (SAP).
 *   <li>The rule is re-indexed and the space hash is recalculated.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Rule updated successfully.
 *   <li>400 Bad Request: Missing fields, invalid payload, duplicate name or space validation
 *       failure.
 *   <li>404 Not Found: Rule with specified ID was not found.
 *   <li>500 Internal Server Error: SAP error or unexpected error.
 * </ul>
 */
public class RestPutRuleAction extends AbstractUpdateAction {

    private static final String ENDPOINT_NAME = "content_manager_rule_update";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/rule_update";

    public RestPutRuleAction() {
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
                        .path(PluginSettings.RULES_URI + "/{id}")
                        .method(PUT)
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
        RestResponse requiredFields =
                this.documentValidations.validateRequiredFields(resource, List.of(Constants.KEY_TITLE));
        if (requiredFields != null) return requiredFields;

        String title = resource.get(Constants.KEY_TITLE).asText();
        String id = resource.get(Constants.KEY_ID).asText();

        return this.documentValidations.validateDuplicateTitle(
                client, Constants.INDEX_RULES, Space.DRAFT.toString(), title, id, Constants.KEY_RULE);
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
}
