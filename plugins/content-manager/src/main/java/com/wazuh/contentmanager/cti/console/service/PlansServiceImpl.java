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

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;

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
     * @return the environment's active plan.
     */
    public Plan getMyPlan(Token token) {
        try {

            if (token == null) {
                log.warn("Cannot fetch environment plan: Token is null. Instance might not be registered.");
                return null;
            }

            // Perform request to the environment-specific endpoint
            SimpleHttpResponse response = this.client.getEnvironmentMe(token);

            log.info("CTI Response Status: {}", response.getCode());
            log.info("CTI Response Body: {}", response.getBodyText());

            if (response.getCode() == 401) {
                log.error("Authentication failed: The environment token is invalid or missing.");
            } else if (response.getCode() == 200) {
                // The API returns a list of plans, but for this endpoint
                // it contains only ONE active plan for the environment.
                JsonNode root = this.mapper.readTree(response.getBodyText()).get("plans");

                List<Plan> plans =
                        this.mapper.readerFor(new TypeReference<List<Plan>>() {}).readValue(root);

                return (plans != null && !plans.isEmpty()) ? plans.get(0) : null;
            } else {
                log.warn(
                        "Operation to fetch environment plan failed: { \"status_code\": {}, \"message\": {}",
                        response.getCode(),
                        response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain environment plan from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse environment plan: {}", e.getMessage());
        }
        return null;
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
}
