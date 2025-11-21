package com.wazuh.contentmanager.cti.console.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.wazuh.contentmanager.cti.console.model.Plan;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * Implementation of the PlansService interface.
 */
public class PlansServiceImpl extends AbstractService implements PlansService {
    private static final Logger log = LogManager.getLogger(PlansServiceImpl.class);

    /**
     * Default constructor.
     */
    public PlansServiceImpl() {
        super();
    }

    /**
     * Obtains the list of plans the instance is subscribed to, including all associated products.
     * @param permanentToken access token
     * @return list of plans the instance has access to.
     */
    public List<Plan> getPlans(String permanentToken) {
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getPlans(permanentToken);

            if (response.getCode() == 200) {
                // Parse response
                JsonNode root = mapper.readTree(response.getBodyText()).get("data").get("plans");

                return this.mapper.readValue(root.toString(), new TypeReference<List<Plan>>() {});
            } else {
                log.warn("Operation to fetch a plans failed: { \"status_code\": {}, \"message\": {}", response.getCode(), response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain plans from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse plans: {}", e.getMessage());
        }
        return null;
    }
}
