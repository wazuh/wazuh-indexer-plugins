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

import org.opensearch.core.action.ActionListener;

import com.wazuh.contentmanager.cti.console.model.Plan;

/** Service interface for managing the CTI subscription: get status, register, and unregister. */
public interface SubscriptionService {

    /**
     * Returns the active CTI plan for this environment and notifies the listener with the result.
     *
     * <p>If a valid access token is present, the authenticated plan is returned. If the CTI Console
     * rejects the token ({@code 401}), the credentials document is deleted, the in-memory token is
     * cleared, and the public plan is returned as a fallback. Any other failure to obtain the plan
     * (network error, timeout, another error status) leaves the token in place and fails the listener
     * with a {@link com.wazuh.contentmanager.cti.console.service.CtiConsoleUnavailableException}.
     *
     * @param listener listener notified with the active {@link Plan}, or the public plan if the token
     *     was rejected or is absent.
     */
    void getPlan(ActionListener<Plan> listener);

    /**
     * Stores the access token in the credentials index, updates the in-memory token, and notifies the
     * listener on completion.
     *
     * @param accessToken the CTI access token to persist.
     * @param listener listener notified on success or failure.
     */
    void register(String accessToken, ActionListener<Void> listener);

    /**
     * Removes the credentials document from the index, clears the in-memory token, and notifies the
     * listener on completion.
     *
     * @param listener listener notified on success or failure.
     */
    void unregister(ActionListener<Void> listener);
}
