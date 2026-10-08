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
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

public class TransportIndexSubscriptionAction
        extends HandledTransportAction<IndexSubscriptionRequest, MessageStatusResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexSubscriptionAction.class);

    private final SubscriptionServiceImpl subscriptionService;
    private final CatalogSyncJob catalogSyncJob;

    @Inject
    public TransportIndexSubscriptionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SubscriptionServiceImpl subscriptionService,
            CatalogSyncJob catalogSyncJob) {
        super(
                IndexSubscriptionAction.NAME,
                transportService,
                actionFilters,
                IndexSubscriptionRequest::new);
        this.subscriptionService = subscriptionService;
        this.catalogSyncJob = catalogSyncJob;
    }

    @Override
    protected void doExecute(
            Task task, IndexSubscriptionRequest request, ActionListener<MessageStatusResponse> listener) {
        // With the security plugin enabled this branch is unreachable in check mode: SecurityFilter
        // answers with its own PermissionCheckResponse before the action executes. Reaching it means
        // no filter intercepted -> security is disabled -> every caller may register.
        if (request.isPermissionCheckOnly()) {
            listener.onResponse(
                    new MessageStatusResponse(Constants.S_200_PERMISSION_CHECK_ALLOWED, RestStatus.OK));
            return;
        }

        String accessToken = request.getToken();
        this.subscriptionService.register(
                accessToken,
                ActionListener.wrap(
                        v -> {
                            listener.onResponse(
                                    new MessageStatusResponse(
                                            Constants.S_201_ACCESS_TOKEN_RECEIVED, RestStatus.CREATED));
                            this.triggerContentUpdate();
                        },
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

    /**
     * Starts a content update once a token is registered. The token can change the environment's
     * plan, and with it the data source of each consumer; without this, the new content would only
     * arrive with the next scheduled synchronization. Runs on this node, the one that holds the new
     * token in memory.
     */
    private void triggerContentUpdate() {
        try {
            this.catalogSyncJob.triggerOnRegistration();
        } catch (Exception e) {
            log.error(Constants.E_LOG_REGISTRATION_UPDATE_FAILED, e.getMessage(), e);
        }
    }
}
