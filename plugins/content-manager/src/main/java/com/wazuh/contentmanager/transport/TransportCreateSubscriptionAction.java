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

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import com.wazuh.contentmanager.action.CreateSubscriptionAction;
import com.wazuh.contentmanager.action.CreateSubscriptionRequest;
import com.wazuh.contentmanager.action.CreateSubscriptionResponse;
import com.wazuh.contentmanager.cti.catalog.service.SubscriptionServiceImpl;
import com.wazuh.contentmanager.utils.Constants;

public class TransportCreateSubscriptionAction
        extends HandledTransportAction<CreateSubscriptionRequest, CreateSubscriptionResponse> {

    private final SubscriptionServiceImpl subscriptionService;

    @Inject
    public TransportCreateSubscriptionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SubscriptionServiceImpl subscriptionService) {
        super(
                CreateSubscriptionAction.NAME,
                transportService,
                actionFilters,
                CreateSubscriptionRequest::new);
        this.subscriptionService = subscriptionService;
    }

    @Override
    protected void doExecute(
            Task task,
            CreateSubscriptionRequest request,
            ActionListener<CreateSubscriptionResponse> listener) {
        String accessToken = request.getToken();
        try {
            this.subscriptionService.register(accessToken);
            listener.onResponse(
                    new CreateSubscriptionResponse(
                            Constants.S_201_ACCESS_TOKEN_RECEIVED, RestStatus.CREATED));
        } catch (IllegalStateException e) {
            if (e.getMessage().equals(Constants.E_412_UNPROTECTED_CREDENTIALS_INDEX)) {
                listener.onResponse(
                        new CreateSubscriptionResponse(e.getMessage(), RestStatus.PRECONDITION_FAILED));
                return;
            }
            listener.onFailure(e);
        } catch (Exception e) {
            listener.onResponse(
                    new CreateSubscriptionResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR));
        }
    }
}
