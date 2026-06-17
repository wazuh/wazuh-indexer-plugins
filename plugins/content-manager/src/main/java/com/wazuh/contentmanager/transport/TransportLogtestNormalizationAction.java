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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.action.LogtestNormalizationAction;
import com.wazuh.contentmanager.action.LogtestNormalizationRequest;
import com.wazuh.contentmanager.action.LogtestResponse;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.LogtestService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.utils.Constants;

public class TransportLogtestNormalizationAction
        extends HandledTransportAction<LogtestNormalizationRequest, LogtestResponse> {

    private final LogtestService logtestService;
    private final PayloadValidations payloadValidations;

    @Inject
    public TransportLogtestNormalizationAction(
            TransportService transportService,
            ActionFilters actionFilters,
            LogtestService logtestService) {
        super(
                LogtestNormalizationAction.NAME,
                transportService,
                actionFilters,
                LogtestNormalizationRequest::new);
        this.logtestService = logtestService;
        this.payloadValidations = new PayloadValidations();
    }

    @Override
    protected void doExecute(
            Task task, LogtestNormalizationRequest request, ActionListener<LogtestResponse> listener) {
        try {
            // 1. Parse JSON
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode;
            try {
                jsonNode = mapper.readTree(request.getBody());
            } catch (Exception ex) {
                listener.onResponse(
                        new LogtestResponse(Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
                return;
            }

            // 2. Validate required field: space
            RestResponse validationError =
                    this.payloadValidations.validateRequiredFields(jsonNode, List.of(Constants.KEY_SPACE));
            if (validationError != null) {
                listener.onResponse(
                        new LogtestResponse(
                                validationError.getMessage(), RestStatus.fromCode(validationError.getStatus())));
                return;
            }

            String space = jsonNode.get(Constants.KEY_SPACE).asText();

            // 3. Validate space is "test" or "standard"
            Space spaceEnum;
            try {
                spaceEnum = Space.fromValue(space);
            } catch (IllegalArgumentException e) {
                listener.onResponse(
                        new LogtestResponse(
                                String.format(Locale.ROOT, Constants.E_400_INVALID_SPACE, space),
                                RestStatus.BAD_REQUEST));
                return;
            }
            if (spaceEnum != Space.TEST && spaceEnum != Space.STANDARD) {
                listener.onResponse(
                        new LogtestResponse(
                                String.format(Locale.ROOT, Constants.E_400_INVALID_SPACE, space),
                                RestStatus.BAD_REQUEST));
                return;
            }

            // 4. Strip integration field if present, build engine payload
            ObjectNode enginePayload = jsonNode.deepCopy();
            enginePayload.remove(Constants.KEY_INTEGRATION);

            // 5. Delegate execution to Service
            RestResponse serviceResponse = this.logtestService.executeNormalization(enginePayload);
            listener.onResponse(
                    new LogtestResponse(
                            serviceResponse.getMessage(), RestStatus.fromCode(serviceResponse.getStatus())));
        } catch (Exception e) {
            listener.onResponse(
                    new LogtestResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR));
        }
    }
}
