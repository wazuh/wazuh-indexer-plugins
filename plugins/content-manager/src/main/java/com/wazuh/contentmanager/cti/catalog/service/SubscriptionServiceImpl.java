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
package com.wazuh.contentmanager.cti.catalog.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/** Centralizes CTI subscription logic: get status, register, and unregister. */
public class SubscriptionServiceImpl implements SubscriptionService {
    private static final Logger log = LogManager.getLogger(SubscriptionServiceImpl.class);

    private final PlansService plansService;
    private final CredentialsIndex credentialsIndex;
    private final boolean isCredentialsIndexProtected;

    /**
     * Constructs a new SubscriptionServiceImpl.
     *
     * @param plansService the service used to fetch CTI plans from the console API.
     * @param credentialsIndex the index used to persist and remove the access token.
     * @param isCredentialsIndexProtected whether the credentials index is declared as a system index.
     *     When false, registration is blocked and any stored token is wiped on first access.
     */
    public SubscriptionServiceImpl(
            PlansService plansService,
            CredentialsIndex credentialsIndex,
            boolean isCredentialsIndexProtected) {
        this.plansService = plansService;
        this.credentialsIndex = credentialsIndex;
        this.isCredentialsIndexProtected = isCredentialsIndexProtected;
    }

    @Override
    public Plan getPlan() {
        String accessToken = this.getAccessToken();
        if (accessToken != null) {
            Plan plan = this.plansService.getMyPlan(new Token(accessToken, "Bearer"));
            if (plan != null) {
                return plan;
            }
            log.info(Constants.I_LOG_ACCESS_TOKEN_EXPIRED_OR_INVALID);
            try {
                this.credentialsIndex.deleteDocument();
            } catch (Exception e) {
                log.warn("Failed to delete invalid credentials document: {}", e.getMessage());
            }
            PluginSettings.getInstance().setAccessToken(null);
        }
        return this.plansService.getPlan();
    }

    /**
     * Retrieves the access token. The method ensures the in-memory access token is populated. If the
     * token is already loaded, returns it immediately. Otherwise, attempts a single read from the
     * credentials index.
     *
     * @return the access token, or null if no token is stored.
     */
    private String getAccessToken() {
        String accessToken = PluginSettings.getInstance().getAccessToken();
        if (accessToken != null) {
            return accessToken;
        }
        try {
            if (this.credentialsIndex.exists()) {
                String token = this.credentialsIndex.getAccessToken();
                if (token != null) {
                    PluginSettings.getInstance().setAccessToken(token);
                    log.info(Constants.I_LOG_ACCESS_TOKEN_READ_FROM_INDEX);
                    return token;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to load access token from credentials index: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public void register(String accessToken) throws Exception {
        if (!this.isCredentialsIndexProtected) {
            throw new IllegalStateException(Constants.E_412_UNPROTECTED_CREDENTIALS_INDEX);
        }
        this.credentialsIndex.storeCredentials(accessToken);
        PluginSettings.getInstance().setAccessToken(accessToken);
        log.info(Constants.I_LOG_ACCESS_TOKEN_SET);
    }

    @Override
    public void unregister() throws Exception {
        this.credentialsIndex.deleteDocument();
        PluginSettings.getInstance().setAccessToken(null);
        log.info(Constants.I_LOG_ACCESS_TOKEN_REMOVED);
    }
}
