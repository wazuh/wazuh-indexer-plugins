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

import com.wazuh.contentmanager.action.GetSubscriptionAction;
import com.wazuh.contentmanager.action.GetSubscriptionRequest;
import com.wazuh.contentmanager.action.GetSubscriptionResponse;
import com.wazuh.contentmanager.cti.catalog.service.SubscriptionServiceImpl;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

public class TransportGetSubscriptionAction
        extends HandledTransportAction<GetSubscriptionRequest, GetSubscriptionResponse> {

    private static final Logger log = LogManager.getLogger(TransportGetSubscriptionAction.class);

    private final SubscriptionServiceImpl subscriptionService;

    @Inject
    public TransportGetSubscriptionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SubscriptionServiceImpl subscriptionService) {
        super(GetSubscriptionAction.NAME, transportService, actionFilters, GetSubscriptionRequest::new);
        this.subscriptionService = subscriptionService;
    }

    @Override
    protected void doExecute(
            Task task, GetSubscriptionRequest request, ActionListener<GetSubscriptionResponse> listener) {
        this.subscriptionService.getPlan(
                ActionListener.wrap(
                        plan -> {
                            boolean isRegistered = PluginSettings.getInstance().getAccessToken() != null;
                            listener.onResponse(
                                    new GetSubscriptionResponse(
                                            plan != null ? plan.getName() : null,
                                            plan != null && plan.isPublic(),
                                            isRegistered));
                        },
                        e -> {
                            RestResponse classified = TransportActionHelper.classifyException(e);
                            if (classified != null) {
                                log.warn("Failed to retrieve subscription plan: {}", classified.getMessage());
                                listener.onResponse(
                                        new GetSubscriptionResponse(
                                                classified.getMessage(), RestStatus.fromCode(classified.getStatus())));
                                return;
                            }
                            log.error("Failed to retrieve subscription plan: {}", e.getMessage(), e);
                            listener.onResponse(
                                    new GetSubscriptionResponse(
                                            Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
                        }));
    }
}
