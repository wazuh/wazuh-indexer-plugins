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

import com.wazuh.contentmanager.action.IndexSubscriptionAction;
import com.wazuh.contentmanager.action.IndexSubscriptionRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.cti.catalog.service.SubscriptionServiceImpl;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

public class TransportIndexSubscriptionAction
        extends HandledTransportAction<IndexSubscriptionRequest, MessageStatusResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexSubscriptionAction.class);

    private final SubscriptionServiceImpl subscriptionService;

    @Inject
    public TransportIndexSubscriptionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SubscriptionServiceImpl subscriptionService) {
        super(
                IndexSubscriptionAction.NAME,
                transportService,
                actionFilters,
                IndexSubscriptionRequest::new);
        this.subscriptionService = subscriptionService;
    }

    @Override
    protected void doExecute(
            Task task, IndexSubscriptionRequest request, ActionListener<MessageStatusResponse> listener) {
        String accessToken = request.getToken();
        this.subscriptionService.register(
                accessToken,
                ActionListener.wrap(
                        v ->
                                listener.onResponse(
                                        new MessageStatusResponse(
                                                Constants.S_201_ACCESS_TOKEN_RECEIVED, RestStatus.CREATED)),
                        e -> {
                            if (e instanceof IllegalStateException
                                    && Constants.E_412_UNPROTECTED_CREDENTIALS_INDEX.equals(e.getMessage())) {
                                listener.onResponse(
                                        new MessageStatusResponse(e.getMessage(), RestStatus.PRECONDITION_FAILED));
                                return;
                            }
                            RestResponse classified = TransportActionHelper.classifyException(e);
                            if (classified != null) {
                                log.warn("Access token registration rejected: {}", classified.getMessage());
                                listener.onResponse(
                                        new MessageStatusResponse(
                                                classified.getMessage(), RestStatus.fromCode(classified.getStatus())));
                                return;
                            }
                            log.error("Access token registration failed: {}", e.getMessage(), e);
                            listener.onResponse(
                                    new MessageStatusResponse(
                                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
                        }));
    }
}
