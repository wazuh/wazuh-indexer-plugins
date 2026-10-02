/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.console.service;

import org.opensearch.core.action.ActionListener;

import java.util.List;

import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;

/** Service interface definition for managing CTI Plans. */
public interface PlansService extends ClosableHttpClient {

    /**
     * Retrieves the list of available CTI plans authorized by the provided token.
     *
     * @param token the authentication {@link Token} required to validate the request.
     * @return a {@link List} of {@link Plan} objects available to the user. Returns an empty list if
     *     no plans are found.
     */
    List<Plan> getPlans(Token token);

    /**
     * Retrieves the applicable plan based on the registration state. For unregistered instances,
     * returns the public plan.
     *
     * @return the applicable {@link Plan}, or {@code null} if the public plan cannot be retrieved.
     * @throws TokenRejectedException if the instance is registered and the CTI Console rejects its
     *     token.
     * @throws PlanUnavailableException if the instance is registered and its plan cannot be obtained
     *     for any other reason.
     */
    Plan getPlan() throws TokenRejectedException, PlanUnavailableException;

    /**
     * Retrieves the plan for the registered environment using the provided token.
     *
     * @param token the authentication {@link Token}.
     * @return the environment's active {@link Plan}, or {@code null} if {@code token} is {@code
     *     null}.
     * @throws TokenRejectedException if the CTI Console rejects the token ({@code 401}). Only this
     *     failure means the token is no longer valid.
     * @throws PlanUnavailableException if the plan cannot be obtained for any other reason: network
     *     error, timeout, another error status, or an unusable response.
     */
    Plan getMyPlan(Token token) throws TokenRejectedException, PlanUnavailableException;

    /**
     * Async variant of {@link #getMyPlan(Token)}. Retrieves the plan for the registered environment
     * and notifies the listener with the result.
     *
     * @param token the authentication {@link Token}.
     * @param listener notified with the active {@link Plan} ({@code null} if {@code token} is {@code
     *     null}), or failed with a {@link TokenRejectedException} when the CTI Console rejects the
     *     token, or with a {@link PlanUnavailableException} for any other failure.
     */
    void getMyPlan(Token token, ActionListener<Plan> listener);

    /**
     * Async variant of {@link #getPlan()}. Retrieves the applicable plan and notifies the listener
     * with the result.
     *
     * @param listener listener notified with the applicable {@link Plan}, or null on error.
     */
    void getPlan(ActionListener<Plan> listener);
}
