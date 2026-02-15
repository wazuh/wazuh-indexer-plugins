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

import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.util.List;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * DELETE /_plugins/content-manager/rules/{id}
 *
 * <p>Deletes an existing Rule from the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The rule exists and is in the draft space.
 *   <li>The rule is deleted from the Security Analytics Plugin (SAP).
 *   <li>The rule is unlinked from any integrations that reference it.
 *   <li>The rule is deleted from the index and the space hash is recalculated.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Rule deleted successfully.
 *   <li>400 Bad Request: Rule is not in draft space.
 *   <li>404 Not Found: Rule with specified ID was not found.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestDeleteRuleAction extends AbstractDeleteAction {

    private static final String ENDPOINT_NAME = "content_manager_rule_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/rule_delete";

    public RestDeleteRuleAction() {
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
                        .method(DELETE)
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
    protected void deleteExternalServices(String id) {
        this.securityAnalyticsService.deleteRule(id);
    }

    @Override
    protected void unlinkFromParent(Client client, String id) {
        ContentUtils.unlinkResourceFromIntegrations(client, id, Constants.KEY_RULES);
    }
}
