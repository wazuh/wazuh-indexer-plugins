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
package com.wazuh.contentmanager.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.action.GetPromoteAction;
import com.wazuh.contentmanager.action.GetPromoteRequest;
import com.wazuh.contentmanager.action.GetPromoteResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action for GET /promote. Previews the promotion of content from one space to another by
 * calculating the diff between source and target spaces.
 */
public class TransportGetPromoteAction
        extends HandledTransportAction<GetPromoteRequest, GetPromoteResponse> {

    private static final Logger log = LogManager.getLogger(TransportGetPromoteAction.class);

    private final SpaceService spaceService;

    @Inject
    public TransportGetPromoteAction(
            TransportService transportService, ActionFilters actionFilters, SpaceService spaceService) {
        super(GetPromoteAction.NAME, transportService, actionFilters, GetPromoteRequest::new);
        this.spaceService = spaceService;
    }

    @Override
    protected void doExecute(
            Task task, GetPromoteRequest request, ActionListener<GetPromoteResponse> listener) {
        try {
            // 1. Validate Space Parameter
            String spaceParam = request.getSpace();
            if (spaceParam == null || spaceParam.isBlank()) {
                listener.onResponse(
                        new GetPromoteResponse(
                                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_SPACE),
                                RestStatus.BAD_REQUEST));
                return;
            }
            Space sourceSpace = Space.fromValue(spaceParam);

            // 2. Determine Target Space
            Space targetSpace = sourceSpace.promote();
            if (targetSpace == sourceSpace) {
                listener.onResponse(
                        new GetPromoteResponse(
                                String.format(Locale.ROOT, Constants.E_400_UNPROMOTABLE_SPACE, sourceSpace),
                                RestStatus.BAD_REQUEST));
                return;
            }

            // 3. Fetch Resources for both spaces
            Map<String, Map<String, String>> sourceContent =
                    this.spaceService.getSpaceResources(sourceSpace.toString());
            Map<String, Map<String, String>> targetContent =
                    this.spaceService.getSpaceResources(targetSpace.toString());

            // 4. Calculate Differences
            Map<String, List<Map<String, String>>> changes = new HashMap<>();

            for (String resourceType : sourceContent.keySet()) {
                if (Constants.KEY_IOCS.equals(resourceType)) {
                    continue;
                }

                Map<String, String> sourceItems = sourceContent.getOrDefault(resourceType, new HashMap<>());
                Map<String, String> targetItems = targetContent.getOrDefault(resourceType, new HashMap<>());

                List<Map<String, String>> resourceChanges;
                if (Constants.KEY_POLICY.equals(resourceType)) {
                    resourceChanges =
                            this.calculatePolicyDiff(sourceSpace.toString(), targetSpace.toString());
                } else {
                    resourceChanges = this.calculateDiff(sourceItems, targetItems);
                }
                changes.put(resourceType, resourceChanges);
            }

            // 5. Build Response
            listener.onResponse(new GetPromoteResponse(changes));
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(new GetPromoteResponse(e.getMessage(), RestStatus.BAD_REQUEST));
        } catch (Exception e) {
            log.error(
                    Constants.E_LOG_OPERATION_FAILED, "processing", "promote preview", e.getMessage(), e);
            listener.onResponse(
                    new GetPromoteResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
        }
    }

    private List<Map<String, String>> calculateDiff(
            Map<String, String> sourceItems, Map<String, String> targetItems) {
        List<Map<String, String>> changes = new ArrayList<>();

        for (Map.Entry<String, String> entry : sourceItems.entrySet()) {
            String id = entry.getKey();
            String sourceHash = entry.getValue();

            if (!targetItems.containsKey(id)) {
                changes.add(Map.of(Constants.KEY_OPERATION, Constants.OP_ADD, Constants.KEY_ID, id));
            } else {
                String targetHash = targetItems.get(id);
                if (!sourceHash.equals(targetHash)) {
                    changes.add(Map.of(Constants.KEY_OPERATION, Constants.OP_UPDATE, Constants.KEY_ID, id));
                }
            }
        }

        for (String targetId : targetItems.keySet()) {
            if (!sourceItems.containsKey(targetId)) {
                changes.add(
                        Map.of(Constants.KEY_OPERATION, Constants.OP_REMOVE, Constants.KEY_ID, targetId));
            }
        }

        return changes;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, String>> calculatePolicyDiff(String sourceSpace, String targetSpace)
            throws Exception {
        List<Map<String, String>> changes = new ArrayList<>();

        Map<String, Object> sourcePolicy = this.spaceService.getPolicy(sourceSpace);
        Map<String, Object> sourceDoc = (Map<String, Object>) sourcePolicy.get(Constants.KEY_DOCUMENT);
        String sourceId = (String) sourceDoc.get(Constants.KEY_ID);

        Map<String, Object> targetPolicy = this.spaceService.getPolicy(targetSpace);
        Map<String, Object> targetDoc = (Map<String, Object>) targetPolicy.get(Constants.KEY_DOCUMENT);

        if (sourceId == null || sourceId.isBlank()) {
            throw new IllegalStateException(Constants.E_500_INTERNAL_SERVER_ERROR);
        }

        if (this.isPolicyDifferent(sourceDoc, targetDoc)) {
            changes.add(Map.of(Constants.KEY_OPERATION, Constants.OP_UPDATE, Constants.KEY_ID, sourceId));
        }

        return changes;
    }

    private boolean isPolicyDifferent(Map<String, Object> sourceDoc, Map<String, Object> targetDoc) {
        if (sourceDoc == null || targetDoc == null) {
            throw new IllegalStateException(Constants.E_500_INTERNAL_SERVER_ERROR);
        }

        Map<String, Object> source = new HashMap<>(sourceDoc);
        Map<String, Object> target = new HashMap<>(targetDoc);

        return !source.equals(target);
    }
}
