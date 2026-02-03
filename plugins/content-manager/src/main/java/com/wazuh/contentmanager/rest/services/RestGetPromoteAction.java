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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/content-manager/promote
 *
 * <p>Previews the promotion of content from one space to another. Compares resources in the source
 * space against the target space and returns a list of operations (add, remove, update) required to
 * synchronize them.
 *
 * <p>Supported transitions are defined by {@link Space#promote()}.
 */
public class RestGetPromoteAction extends BaseRestHandler {
    private static final String ENDPOINT_NAME = "content_manager_promote_preview";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/promote_preview";
    private static final Logger log = LogManager.getLogger(RestGetPromoteAction.class);

    // Operations
    private static final String OP_ADD = "add";
    private static final String OP_REMOVE_VAL = "remove";
    private static final String OP_UPDATE = "update";

    private final SpaceService spaceService;

    public RestGetPromoteAction(SpaceService spaceService) {
        this.spaceService = spaceService;
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.PROMOTE_URI)
                        .method(GET)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        if (request.hasParam("space")) {
            request.param("space");
        }
        RestResponse response = this.handleRequest(request);
        return channel -> channel.sendResponse(response.toBytesRestResponse());
    }

    public RestResponse handleRequest(RestRequest request) {
        try {
            // 1. Validate Space Parameter
            String spaceParam = request.param("space");
            if (spaceParam == null || spaceParam.isEmpty()) {
                return new RestResponse(
                        "Missing required parameter: space", RestStatus.BAD_REQUEST.getStatus());
            }

            Space sourceSpace;
            try {
                sourceSpace = Space.fromValue(spaceParam);
            } catch (IllegalArgumentException e) {
                return new RestResponse(
                        "Invalid space parameter: " + spaceParam, RestStatus.BAD_REQUEST.getStatus());
            }

            // 2. Determine Target Space
            Space targetSpace = sourceSpace.promote();
            if (targetSpace == sourceSpace) {
                return new RestResponse(
                        "Space [" + sourceSpace + "] cannot be promoted further.",
                        RestStatus.BAD_REQUEST.getStatus());
            }

            // 3. Fetch Resources for both spaces using SpaceService
            // Structure: Map<ResourceType, Map<ID, Hash>>
            Map<String, Map<String, String>> sourceContent =
                    this.spaceService.getSpaceResources(sourceSpace.toString());
            Map<String, Map<String, String>> targetContent =
                    this.spaceService.getSpaceResources(targetSpace.toString());

            // 4. Calculate Differences
            Map<String, List<Map<String, String>>> changes = new HashMap<>();

            // Iterate over the keys returned by the service
            for (String resourceType : sourceContent.keySet()) {
                Map<String, String> sourceItems = sourceContent.getOrDefault(resourceType, new HashMap<>());
                Map<String, String> targetItems = targetContent.getOrDefault(resourceType, new HashMap<>());

                List<Map<String, String>> resourceChanges;
                if (Constants.KEY_POLICIES.equals(resourceType)) {
                    // For policies, we perform a deep comparison ignoring ID
                    resourceChanges =
                            this.calculatePolicyDiff(sourceSpace.toString(), targetSpace.toString());
                } else {
                    resourceChanges = this.calculateDiff(sourceItems, targetItems);
                }
                changes.put(resourceType, resourceChanges);
            }

            // 5. Build Response
            return new PromoteResponse(changes);

        } catch (Exception e) {
            log.error("Error processing promote preview: {}", e.getMessage(), e);
            return new RestResponse(
                    e.getMessage() != null ? e.getMessage() : "Internal Server Error",
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    /**
     * Compares source and target items to determine Add, Update, Remove operations.
     *
     * @param sourceItems Map of ID -> Hash for the source space
     * @param targetItems Map of ID -> Hash for the target space
     * @return List of change operations
     */
    private List<Map<String, String>> calculateDiff(
            Map<String, String> sourceItems, Map<String, String> targetItems) {
        List<Map<String, String>> changes = new ArrayList<>();

        // Check ADD and UPDATE
        for (Map.Entry<String, String> entry : sourceItems.entrySet()) {
            String id = entry.getKey();
            String sourceHash = entry.getValue();

            if (!targetItems.containsKey(id)) {
                // Case 2: Promoted space doesn't have that UUID -> ADD
                changes.add(Map.of("operation", OP_ADD, "id", id));
            } else {
                // Case 1: Promoted space has different hash -> UPDATE
                String targetHash = targetItems.get(id);
                if (!sourceHash.equals(targetHash)) {
                    changes.add(Map.of("operation", OP_UPDATE, "id", id));
                }
            }
        }

        // Check REMOVE
        // Case 3: UUID is in promoted space but not in current one -> DELETE
        for (String targetId : targetItems.keySet()) {
            if (!sourceItems.containsKey(targetId)) {
                changes.add(Map.of("operation", OP_REMOVE_VAL, "id", targetId));
            }
        }

        return changes;
    }

    /**
     * Calculates the difference for the 'policy' resource type. Policies are singletons per space. We
     * fetch the full documents and compare their content ignoring the 'id' field.
     *
     * @param sourceSpace Name of the source space
     * @param targetSpace Name of the target space
     * @return List of change operations
     */
    private List<Map<String, String>> calculatePolicyDiff(String sourceSpace, String targetSpace) {
        List<Map<String, String>> changes = new ArrayList<>();

        try {
            Map<String, Object> sourcePolicy = this.spaceService.getPolicy(sourceSpace);

            Map<String, Object> sourceDoc = (Map<String, Object>) sourcePolicy.get("document");
            String sourceId = (String) sourceDoc.get("id");

            Map<String, Object> targetPolicy = this.spaceService.getPolicy(targetSpace);
            Map<String, Object> targetDoc = (Map<String, Object>) targetPolicy.get("document");

            // Compare content ignoring ID
            if (isPolicyDifferent(sourceDoc, targetDoc)) {
                changes.add(Map.of("operation", OP_UPDATE, "id", sourceId));
            }
        } catch (IOException e) {
            log.error("Failed to fetch policies for diff calculation", e);
        }

        return changes;
    }

    /**
     * Checks if two policy documents are different, ignoring their 'id' field.
     *
     * @param sourceDoc Source policy document map
     * @param targetDoc Target policy document map
     * @return true if content differs, false otherwise
     */
    private boolean isPolicyDifferent(Map<String, Object> sourceDoc, Map<String, Object> targetDoc) {
        if (sourceDoc == null || targetDoc == null) {
            return true;
        }

        // Create shallow copies to remove ID without affecting original maps
        Map<String, Object> s = new HashMap<>(sourceDoc);
        Map<String, Object> t = new HashMap<>(targetDoc);

        s.remove("id");
        t.remove("id");

        return !s.equals(t);
    }

    /** Inner class to extend RestResponse and provide the custom 'changes' payload */
    private static class PromoteResponse extends RestResponse {
        private final Map<String, List<Map<String, String>>> changes;

        public PromoteResponse(Map<String, List<Map<String, String>>> changes) {
            super("Promotion preview calculated", RestStatus.OK.getStatus());
            this.changes = changes;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("changes", this.changes);
            builder.endObject();
            return builder;
        }
    }
}
