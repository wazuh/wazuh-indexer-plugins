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
     * @param space The space of the integration.
     * @param method The HTTP method (POST/PUT).
     */
    void upsertIntegration(JsonNode doc, Space space, Method method);

    /**
     * Deletes an Integration from SAP. This typically involves deleting the associated Detector
     * first.
     *
     * @param id The identifier of the integration to delete.
     * @param isStandard Whether the integration is a Standard integration (true) or Custom (false).
     */
    void deleteIntegration(String id, boolean isStandard);

    /**
     * Creates or updates a Rule in SAP.
     *
     * @param doc The JSON document containing the rule data.
     * @param space The space the rule belongs to (determines if it's standard or custom).
     * @param method The HTTP method (POST/PUT).
     */
    void upsertRule(JsonNode doc, Space space, Method method);

    /**
     * Deletes a Rule from SAP.
     *
     * @param id The identifier of the rule to delete.
     * @param isStandard Whether the rule is a Standard rule (true) or Custom rule (false).
     */
    void deleteRule(String id, boolean isStandard);

    /**
     * Creates or updates a Threat Detector in SAP.
     *
     * @param doc The JSON document containing the integration data used to build the detector.
     * @param rawCategory Whether to use the raw category string (true) or formatted/pretty (false).
     * @param method The HTTP method (POST/PUT).
     */
    void upsertDetector(JsonNode doc, boolean rawCategory, Method method);

    /**
     * Deletes a Threat Detector from SAP.
     *
     * @param id The identifier of the detector to delete.
     */
    void deleteDetector(String id);

    /**
     * Asynchronously creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     * @param space The space of the integration.
     * @param method The HTTP method (POST/PUT).
     * @param listener The listener to be notified when the operation completes.
     */
    void upsertIntegrationAsync(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener);

    /**
     * Asynchronously deletes an Integration from SAP.
     *
     * @param id The identifier of the integration to delete.
     * @param isStandard Whether the integration is a Standard integration (true) or Custom (false).
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteIntegrationAsync(
            String id, boolean isStandard, ActionListener<? extends ActionResponse> listener);

    /**
     * Asynchronously creates or updates a Rule in SAP.
     *
     * @param doc The JSON document containing the rule data.
     * @param space The space the rule belongs to (determines if it's standard or custom).
     * @param method The HTTP method (POST/PUT).
     * @param listener The listener to be notified when the operation completes.
     */
    void upsertRuleAsync(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener);

    /**
     * Asynchronously deletes a Rule from SAP.
     *
     * @param id The identifier of the rule to delete.
     * @param isStandard Whether the rule is a Standard rule (true) or Custom rule (false).
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteRuleAsync(
            String id, boolean isStandard, ActionListener<? extends ActionResponse> listener);

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
     * Asynchronously deletes a Threat Detector from SAP.
     *
     * @param id The identifier of the detector to delete.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteDetectorAsync(String id, ActionListener<? extends ActionResponse> listener);
}
