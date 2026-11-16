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

import com.wazuh.contentmanager.action.DeleteSubscriptionAction;
import com.wazuh.contentmanager.action.DeleteSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.cti.catalog.service.SubscriptionServiceImpl;
import com.wazuh.contentmanager.utils.Constants;

public class TransportDeleteSubscriptionAction
        extends HandledTransportAction<DeleteSubscriptionRequest, MessageStatusResponse> {

    private final SubscriptionServiceImpl subscriptionService;

    @Inject
    public TransportDeleteSubscriptionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SubscriptionServiceImpl subscriptionService) {
        super(
                DeleteSubscriptionAction.NAME,
                transportService,
                actionFilters,
                DeleteSubscriptionRequest::new);
        this.subscriptionService = subscriptionService;
    }

    @Override
    protected void doExecute(
            Task task,
            DeleteSubscriptionRequest request,
            ActionListener<MessageStatusResponse> listener) {
        // With the security plugin enabled this branch is unreachable in check mode: SecurityFilter
        // answers with its own PermissionCheckResponse before the action executes
        if (request.isPermissionCheckOnly()) {
            listener.onResponse(
                    new MessageStatusResponse(Constants.S_200_PERMISSION_CHECK_ALLOWED, RestStatus.OK));
            return;
        }

        this.subscriptionService.unregister(
                ActionListener.wrap(
                        v ->
                                listener.onResponse(
                                        new MessageStatusResponse("Credentials removed", RestStatus.OK)),
                        e ->
                                listener.onResponse(
                                        new MessageStatusResponse(
                                                e.getMessage() != null
                                                        ? e.getMessage()
                                                        : "An unexpected error occurred while processing your request.",
                                                RestStatus.INTERNAL_SERVER_ERROR))));
    }
}
