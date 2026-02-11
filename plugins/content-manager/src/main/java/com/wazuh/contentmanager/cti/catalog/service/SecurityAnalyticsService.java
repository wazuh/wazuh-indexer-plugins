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

import com.google.gson.JsonObject;
import org.opensearch.OpenSearchException;
import org.opensearch.rest.RestRequest.Method;

import com.wazuh.contentmanager.cti.catalog.model.Space;

/**
 * Service interface for managing interactions with the Security Analytics Plugin (SAP). Defines
 * operations for synchronizing Integrations, Rules, and Detectors.
 */
public interface SecurityAnalyticsService {

    /**
     * Creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     * @param space
     * @param method
     * @throws OpenSearchException if the upsert operation fails.
     */
    void upsertIntegration(JsonObject doc, Space space, Method method) throws OpenSearchException;

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
