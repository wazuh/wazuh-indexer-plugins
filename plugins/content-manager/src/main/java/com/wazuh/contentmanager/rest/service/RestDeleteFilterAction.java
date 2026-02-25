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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.NamedRoute;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/**
 * REST handler for deleting Engine Filters.
 *
 * <p>Endpoint: DELETE /_plugins/content-manager/filters/{filter_id}
 *
 * <p>This handler processes filter deletion requests.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Filter deleted successfully.
 *   <li>400 Bad Request: Filter ID is missing or invalid.
 *   <li>404 Not found: Filter index or Filter ID was not found.
 *   <li>500 Internal Server Error: Unexpected error during processing.
 * </ul>
 */
public class RestDeleteFilterAction extends AbstractDeleteActionSpaces {

    private static final String ENDPOINT_NAME = "content_manager_filter_delete";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/filter_delete";

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Constructs a REST handler for deleting Engine Filters.
     *
     * @param engine The {@link EngineService} used to interact with the Engine for filter deletion
     *     operations.
     */
    public RestDeleteFilterAction(EngineService engine) {
        super(engine);
    }

    /**
     * Returns the unique name identifier for this REST handler.
     *
     * @return The handler name "content_manager_filter_delete".
     */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Returns the route configuration for this REST handler.
     *
     * <p>Defines the HTTP method (DELETE) and URI path pattern for filter deletion requests. The
     * endpoint path is: DELETE /_plugins/content-manager/filters/{id}
     *
     * @return A list containing the {@link Route} configuration for the DELETE endpoint.
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.FILTERS_URI + "/{id}")
                        .method(DELETE)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_FILTERS;
    }

    /**
     * Returns the resource type identifier for this handler.
     *
     * @return The resource type "filter".
     */
    @Override
    protected String getResourceType() {
        return Constants.KEY_FILTER;
    }

    /**
     * Returns the set of valid spaces where filters can be deleted.
     *
     * <p>Filters can only be deleted from DRAFT and STANDARD spaces.
     *
     * @return A set containing the allowed deletion spaces: {@link Space#DRAFT} and {@link
     *     Space#STANDARD}.
     */
    @Override
    protected Set<Space> getAllowedSpaces() {
        return validSpaces;
    }

    /**
     * Deletes external service resources associated with the filter.
     *
     * <p>For filter deletion, no external service cleanup is required as filters are managed entirely
     * within the content manager system.
     *
     * @param id The unique identifier of the filter being deleted.
     */
    @Override
    protected void deleteExternalServices(String id) {
        // Not applicable for this implementation.
    }

    /**
     * Unlinks the deleted filter from its parent policy resource.
     *
     * <p>When a filter is deleted, it must be removed from the Draft policy that references it. This
     * method:
     *
     * <ol>
     *   <li>Retrieves the Draft policy document from the policies index
     *   <li>Locates the filter ID in the policy's filters array
     *   <li>Removes the filter ID from the array
     *   <li>Recalculates the policy's SHA256 hash
     *   <li>Updates the policy document with the modified filters array and new hash
     * </ol>
     *
     * <p>If the Draft policy cannot be found, an IllegalStateException is thrown. If the filter is
     * not found in the policy's filters array, the method returns silently without any modifications.
     *
     * @param client The OpenSearch client used for accessing and updating the policies index.
     * @param id The unique identifier of the filter being deleted and removed from the policy.
     * @throws IllegalStateException If the Draft policy document cannot be found in the policies
     *     index.
     * @throws Exception If an error occurs during the index search or update operations.
     */
    @Override
    protected void unlinkFromParent(Client client, String id, String spaceName) throws Exception {
        ContentIndex policiesIndex = new ContentIndex(client, Constants.INDEX_POLICIES);
        TermQueryBuilder queryBuilder = new TermQueryBuilder(Constants.Q_SPACE_NAME, spaceName);
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

        ArrayNode filters = (ArrayNode) document.get(Constants.KEY_FILTERS);
        if (filters == null) return;

        ArrayNode updatedFilters = MAPPER.createArrayNode();
        boolean removed = false;
        for (JsonNode filterId : filters) {
            if (!filterId.asText().equals(id)) {
                updatedFilters.add(filterId);
            } else {
                removed = true;
            }
        }

        if (removed) {
            ((ObjectNode) document).set(Constants.KEY_FILTERS, updatedFilters);
            String hash = Resource.computeSha256(document.toString());
            ((ObjectNode) draftPolicyHit.at("/hash")).put(Constants.KEY_SHA256, hash);
            policiesIndex.create(draftPolicyId, draftPolicyHit, false);
        }
    }
}
