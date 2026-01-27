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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.gson.JsonObject;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;

/**
 * Service interface for managing interactions with the Security Analytics Plugin (SAP). Defines
 * operations for synchronizing Integrations, Rules, and Detectors.
 */
public interface SecurityAnalyticsService {

    /**
     * Creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     */
    WIndexIntegrationResponse upsertIntegration(JsonObject doc);

    /**
     * Creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     */
    WIndexIntegrationResponse upsertIntegration(JsonNode doc) throws JsonProcessingException;

    /**
     * Deletes an Integration from SAP. This typically involves deleting the associated Detector
     * first.
     *
     * @param id The identifier of the integration to delete.
     */
    void deleteIntegration(String id);

    /**
     * Creates or updates a Rule in SAP.
     *
     * @param doc The JSON document containing the rule data.
     */
    void upsertRule(JsonObject doc);

    /**
     * Deletes a Rule from SAP.
     *
     * @param id The identifier of the rule to delete.
     */
    void deleteRule(String id);

    /**
     * Creates or updates a Threat Detector in SAP.
     *
     * @param doc The JSON document containing the integration data used to build the detector.
     * @param rawCategory Whether to use the raw category string (true) or formatted/pretty (false).
     */
    void upsertDetector(JsonObject doc, boolean rawCategory);

    /**
     * Deletes a Threat Detector from SAP.
     *
     * @param id The identifier of the detector to delete.
     */
    void deleteDetector(String id);
}
