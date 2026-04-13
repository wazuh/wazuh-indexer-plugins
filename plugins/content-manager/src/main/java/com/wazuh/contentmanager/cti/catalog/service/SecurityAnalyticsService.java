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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.rest.RestRequest.Method;

import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Space;

/**
 * Service interface for managing interactions with the Security Analytics Plugin (SAP). Defines
 * synchronous and asynchronous operations for synchronizing Integrations, Rules, and Detectors.
 */
public interface SecurityAnalyticsService {

    /**
     * Creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     * @param space The space the integration belongs to.
     * @param method The HTTP method (POST/PUT).
     */
    void upsertIntegration(JsonNode doc, Space space, Method method);

    /**
     * Asynchronously creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     * @param space The space the integration belongs to.
     * @param method The HTTP method (POST/PUT).
     * @param listener The listener to be notified when the operation completes.
     */
    void upsertIntegrationAsync(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener);

    /**
     * Deletes an Integration from SAP. This typically involves deleting the associated Detector
     * first.
     *
     * @param id The identifier of the integration to delete.
     * @param space The space the integration belongs to.
     */
    void deleteIntegration(String id, Space space);

    /**
     * Asynchronously deletes an Integration from SAP.
     *
     * @param id The identifier of the integration to delete.
     * @param space The space the integration belongs to.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteIntegrationAsync(
            String id, Space space, ActionListener<? extends ActionResponse> listener);

    // --------------------------------------------------------------------- //

    /**
     * Creates or updates a Rule in SAP.
     *
     * @param doc The JSON document containing the rule data.
     * @param space The space the rule belongs to.
     * @param method The HTTP method (POST/PUT).
     */
    void upsertRule(JsonNode doc, Space space, Method method);

    /**
     * Asynchronously creates or updates a Rule in SAP.
     *
     * @param doc The JSON document containing the rule data.
     * @param space The space the rule belongs to.
     * @param method The HTTP method (POST/PUT).
     * @param listener The listener to be notified when the operation completes.
     */
    void upsertRuleAsync(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener);

    /**
     * Deletes a Rule from SAP.
     *
     * @param id The identifier of the rule to delete.
     * @param space The space the rule belongs to.
     */
    void deleteRule(String id, Space space);

    /**
     * Asynchronously deletes a Rule from SAP.
     *
     * @param id The identifier of the rule to delete.
     * @param space The space the rule belongs to.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteRuleAsync(String id, Space space, ActionListener<? extends ActionResponse> listener);

    // --------------------------------------------------------------------- //

    /**
     * Creates or updates a Threat Detector in SAP.
     *
     * @param doc The JSON document containing the integration data used to build the detector.
     * @param rawCategory Whether to use the raw category string (true) or formatted/pretty (false).
     * @param method The HTTP method (POST/PUT).
     */
    void upsertDetector(JsonNode doc, boolean rawCategory, Method method);

    /**
     * Asynchronously creates or updates a Threat Detector in SAP.
     *
     * @param doc The JSON document containing the integration data used to build the detector.
     * @param rawCategory Whether to use the raw category string (true) or formatted/pretty (false).
     * @param method The HTTP method (POST/PUT).
     * @param listener The listener to be notified when the operation completes.
     */
    void upsertDetectorAsync(
            JsonNode doc,
            boolean rawCategory,
            Method method,
            ActionListener<? extends ActionResponse> listener);

    /**
     * Deletes a Threat Detector from SAP.
     *
     * @param id The identifier of the detector to delete.
     */
    void deleteDetector(String id);

    /**
     * Asynchronously deletes a Threat Detector from SAP.
     *
     * @param id The identifier of the detector to delete.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteDetectorAsync(String id, ActionListener<? extends ActionResponse> listener);

    /**
     * Evaluates a list of Sigma rules against a normalized event.
     *
     * @param eventJson The normalized event as a JSON string.
     * @param ruleBodies The list of Sigma rule bodies to evaluate.
     * @return The evaluation result as a JSON string.
     */
    String evaluateRules(String eventJson, List<String> ruleBodies);

    /**
     * Deletes all Security Analytics resources (integrations, rules, and detectors) belonging to the
     * given space. Sends a single bulk-delete action to SAP, which handles the deletion internally.
     *
     * @param space The space whose resources should be deleted.
     */
    void deleteSpaceResources(Space space);
}
