/*
 * Copyright (C) 2024, Wazuh Inc.
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
