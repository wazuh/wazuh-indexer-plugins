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
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.action.GetPolicyResourcesAction;
import com.wazuh.contentmanager.action.GetPolicyResourcesRequest;
import com.wazuh.contentmanager.action.GetPolicyResourcesResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action for {@link GetPolicyResourcesAction}.
 *
 * <p>Validates the space and returns its resources grouped by pipeline phase, reusing {@link
 * SpaceService#getSpaceResourcesAsync}. The {@code standard} space is not supported: it holds the
 * Wazuh base content and cannot be promoted.
 */
public class TransportGetPolicyResourcesAction
        extends HandledTransportAction<GetPolicyResourcesRequest, GetPolicyResourcesResponse> {
    private static final Logger log = LogManager.getLogger(TransportGetPolicyResourcesAction.class);
    private final SpaceService spaceService;

    /**
     * Constructor.
     *
     * @param transportService The transport service.
     * @param actionFilters The action filters.
     * @param spaceService The space service.
     */
    @Inject
    public TransportGetPolicyResourcesAction(
            TransportService transportService, ActionFilters actionFilters, SpaceService spaceService) {
        super(
                GetPolicyResourcesAction.NAME,
                transportService,
                actionFilters,
                GetPolicyResourcesRequest::new);
        this.spaceService = spaceService;
    }

    @Override
    protected void doExecute(
            Task task,
            GetPolicyResourcesRequest request,
            ActionListener<GetPolicyResourcesResponse> listener) {
        try {
            String spaceParam = request.getSpace();
            if (spaceParam == null || spaceParam.isBlank()) {
                listener.onResponse(
                        new GetPolicyResourcesResponse(
                                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_SPACE),
                                RestStatus.BAD_REQUEST));
                return;
            }

            Space space = Space.fromValue(spaceParam);
            if (space == Space.STANDARD) {
                listener.onResponse(
                        new GetPolicyResourcesResponse(
                                String.format(Locale.ROOT, Constants.E_400_UNSUPPORTED_SPACE, space),
                                RestStatus.BAD_REQUEST));
                return;
            }

            this.spaceService.getSpaceResourcesAsync(
                    space.toString(),
                    ActionListener.wrap(
                            resources -> buildResponse(resources, listener), listener::onFailure));
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(new GetPolicyResourcesResponse(e.getMessage(), RestStatus.BAD_REQUEST));
        }
    }

    private void buildResponse(
            Map<String, Map<String, String>> resources,
            ActionListener<GetPolicyResourcesResponse> listener) {
        listener.onResponse(
                new GetPolicyResourcesResponse(
                        ids(resources, Constants.KEY_DECODERS),
                        ids(resources, Constants.KEY_FILTERS),
                        ids(resources, Constants.KEY_KVDBS),
                        ids(resources, Constants.KEY_RULES)));
    }

    /** The sorted ids of a resource type, or an empty list when the type has none. */
    private static List<String> ids(Map<String, Map<String, String>> resources, String resourceType) {
        Map<String, String> items = resources.get(resourceType);
        if (items == null) {
            return List.of();
        }
        List<String> ids = new ArrayList<>(items.keySet());
        ids.sort(String::compareTo);
        return ids;
    }
}
