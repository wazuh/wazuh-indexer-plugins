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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.action.ActionListener;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.model.CatalogPlansResponse;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Implementation of the PlansService interface. */
public class PlansServiceImpl extends AbstractService implements PlansService {
    private static final Logger log = LogManager.getLogger(PlansServiceImpl.class);

    /** Default constructor. */
    public PlansServiceImpl() {
        super();
    }

    /**
     * Obtains the specific plan for the registered environment. Communicates with GET
     * /platform/environments/me.
     *
     * @return the environment's active plan, or {@code null} if {@code token} is {@code null}.
     * @throws TokenRejectedException if the CTI Console rejects the token ({@code 401}).
     * @throws PlanUnavailableException if the plan cannot be obtained for any other reason.
     */
    public Plan getMyPlan(Token token) throws TokenRejectedException, PlanUnavailableException {
        if (token == null) {
            log.warn("Cannot fetch environment plan: Token is null. Instance might not be registered.");
            return null;
        }
        SimpleHttpResponse response;
        try {
            // Perform request to the environment-specific endpoint
            response = this.client.getEnvironmentMe(token);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw this.requestFailed(e);
        } catch (ExecutionException | TimeoutException e) {
            throw this.requestFailed(e);
        }
        return this.toEnvironmentPlan(response);
    }

    /**
     * Reads the active plan out of a {@code GET /platform/environments/me} response. Only a {@code
     * 401} is taken as a rejected token; any other unusable response leaves the token's validity
     * unknown.
     *
     * @param response the CTI Console response.
     * @return the environment's active plan.
     * @throws TokenRejectedException if the response is a {@code 401}.
     * @throws PlanUnavailableException if the response is any other non-{@code 200} status, cannot be
     *     parsed, or lists no plan.
     */
    private Plan toEnvironmentPlan(SimpleHttpResponse response)
            throws TokenRejectedException, PlanUnavailableException {
        if (response.getCode() == 401) {
            log.warn("Authentication failed: The environment token is invalid or missing.");
            throw new TokenRejectedException("The CTI Console rejected the access token (status 401).");
        }
        if (response.getCode() != 200) {
            log.warn(
                    "Operation to fetch environment plan failed: { \"status_code\": {}, \"message\": {}",
                    response.getCode(),
                    response.getBodyText());
            throw new PlanUnavailableException(
                    "The CTI Console answered status " + response.getCode() + " to the plan lookup.");
        }
        List<Plan> plans;
        try {
            // The API returns a list of plans, but for this endpoint
            // it contains only ONE active plan for the environment.
            JsonNode root = this.mapper.readTree(response.getBodyText()).get("plans");
            plans = this.mapper.readerFor(new TypeReference<List<Plan>>() {}).readValue(root);
        } catch (IOException | IllegalArgumentException e) {
            log.error("Failed to parse environment plan: {}", e.getMessage());
            throw new PlanUnavailableException("Failed to parse the environment plan.", e);
        }
        if (plans == null || plans.isEmpty()) {
            log.warn("The CTI Console returned no plan for the registered environment.");
            throw new PlanUnavailableException("The CTI Console returned no plan for the environment.");
        }
        log.info(
                "Active plan for registered environment retrieved successfully from CTI"
                        + " Console. Active plan is: {}.",
                plans.get(0).getName());
        return plans.get(0);
    }

    private PlanUnavailableException requestFailed(Exception e) {
        log.error("Couldn't obtain environment plan from CTI: {}", e.getMessage());
        return new PlanUnavailableException("The plan lookup request to the CTI Console failed.", e);
    }

    /**
     * Obtains the list of plans the instance is subscribed to, including all associated products.
     *
     * @param token permanent token
     * @return list of plans the instance has access to.
     */
    public List<Plan> getPlans(Token token) {
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getPlans(token);

            if (response.getCode() == 200) {
                // Parse response
                JsonNode root = this.mapper.readTree(response.getBodyText()).get("data").get("plans");

                return this.mapper.readValue(root.toString(), new TypeReference<List<Plan>>() {});
            } else {
                log.warn(
                        "Operation to fetch a plans failed: { \"status_code\": {}, \"message\": {}",
                        response.getCode(),
                        response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain plans from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse plans: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public Plan getPlan() throws TokenRejectedException, PlanUnavailableException {
        String accessToken = PluginSettings.getInstance().getAccessToken();
        if (accessToken != null) {
            return getMyPlan(new Token(accessToken, "Bearer"));
        }
        return getPublicPlan();
    }

    @Override
    public void getMyPlan(Token token, ActionListener<Plan> listener) {
        if (token == null) {
            log.warn("Cannot fetch environment plan: Token is null. Instance might not be registered.");
            listener.onResponse(null);
            return;
        }

        this.client.getEnvironmentMe(
                token,
                ActionListener.wrap(
                        response -> {
                            Plan plan;
                            try {
                                plan = this.toEnvironmentPlan(response);
                            } catch (TokenRejectedException | PlanUnavailableException e) {
                                listener.onFailure(e);
                                return;
                            }
                            listener.onResponse(plan);
                        },
                        e -> listener.onFailure(this.requestFailed(e))));
    }

    @Override
    public void getPlan(ActionListener<Plan> listener) {
        String accessToken = PluginSettings.getInstance().getAccessToken();
        if (accessToken != null) {
            getMyPlan(new Token(accessToken, "Bearer"), listener);
        } else {
            getPublicPlan(listener);
        }
    }

    private void getPublicPlan(ActionListener<Plan> listener) {
        this.client.getCatalogPlans(
                ActionListener.wrap(
                        response -> {
                            if (response.getCode() == 200) {
                                try {
                                    CatalogPlansResponse parsedResponse =
                                            this.mapper.readValue(response.getBodyText(), CatalogPlansResponse.class);
                                    if (parsedResponse.getPlans() != null) {
                                        Plan publicPlan =
                                                parsedResponse.getPlans().stream()
                                                        .filter(Plan::isPublic)
                                                        .findFirst()
                                                        .orElse(null);
                                        if (publicPlan != null) {
                                            log.info(
                                                    "Public plan retrieved successfully from CTI"
                                                            + " Console. Active plan is: {}.",
                                                    publicPlan.getName());
                                        }
                                        listener.onResponse(publicPlan);
                                    } else {
                                        listener.onResponse(null);
                                    }
                                } catch (IOException e) {
                                    log.error("Failed to parse catalog plans response: {}", e.getMessage());
                                    listener.onResponse(null);
                                }
                            } else {
                                log.warn(
                                        "Failed to fetch catalog plans: status={}, body={}",
                                        response.getCode(),
                                        response.getBodyText());
                                listener.onResponse(null);
                            }
                        },
                        e -> {
                            log.error("Couldn't obtain catalog plans from CTI: {}", e.getMessage());
                            listener.onResponse(null);
                        }));
    }

    private Plan getPublicPlan() {
        try {
            SimpleHttpResponse response = this.client.getCatalogPlans();

            if (response.getCode() == 200) {
                CatalogPlansResponse parsedResponse =
                        this.mapper.readValue(response.getBodyText(), CatalogPlansResponse.class);

                if (parsedResponse.getPlans() != null) {
                    Plan publicPlan =
                            parsedResponse.getPlans().stream().filter(Plan::isPublic).findFirst().orElse(null);
                    if (publicPlan != null) {
                        log.info(
                                "Public plan retrieved successfully from CTI Console. Active plan" + " is: {}.",
                                publicPlan.getName());
                    }
                    return publicPlan;
                }
            } else {
                log.warn(
                        "Failed to fetch catalog plans: status={}, body={}",
                        response.getCode(),
                        response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain catalog plans from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse catalog plans response: {}", e.getMessage());
        }
        return null;
    }
}
