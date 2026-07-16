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
     * Asynchronously creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     * @param space The space the integration belongs to.
     * @param method The HTTP method (POST/PUT).
     * @param listener The listener to be notified when the operation completes.
     */
    void upsertIntegration(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener);

    /**
     * Asynchronously deletes an Integration from SAP.
     *
     * @param id The identifier of the integration to delete.
     * @param space The space the integration belongs to.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteIntegration(String id, Space space, ActionListener<? extends ActionResponse> listener);

    // --------------------------------------------------------------------- //

    /**
     * Asynchronously creates or updates a Rule in SAP.
     *
     * @param doc The JSON document containing the rule data.
     * @param space The space the rule belongs to.
     * @param method The HTTP method (POST/PUT).
     * @param listener The listener to be notified when the operation completes.
     */
    void upsertRule(
            JsonNode doc, Space space, Method method, ActionListener<? extends ActionResponse> listener);

    /**
     * Asynchronously deletes a Rule from SAP.
     *
     * @param id The identifier of the rule to delete.
     * @param space The space the rule belongs to.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteRule(String id, Space space, ActionListener<? extends ActionResponse> listener);

    // --------------------------------------------------------------------- //

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
     * Asynchronously enables or disables an existing Threat Detector in SAP without otherwise
     * modifying it. The detector is identified by the owning integration's id (they share the same
     * id). A missing detector is a no-op.
     *
     * @param id The identifier of the detector (== integration document id).
     * @param enabled The desired enabled state.
     * @param listener The listener to be notified when the operation completes.
     */
    void setDetectorEnabled(
            String id, boolean enabled, ActionListener<? extends ActionResponse> listener);

    /**
     * Asynchronously deletes a Threat Detector from SAP.
     *
     * @param id The identifier of the detector to delete.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteDetector(String id, ActionListener<? extends ActionResponse> listener);

    /**
     * Asynchronously evaluates a list of Sigma rules against a normalized event.
     *
     * @param eventJson The normalized event as a JSON string.
     * @param ruleBodies The list of Sigma rule bodies to evaluate.
     * @param listener The listener to be notified with the evaluation result JSON string.
     */
    void evaluateRulesAsync(
            String eventJson, List<String> ruleBodies, ActionListener<String> listener);

    /**
     * Asynchronously deletes all Security Analytics resources belonging to the given space.
     *
     * @param space The space whose resources should be deleted.
     * @param listener The listener to be notified when the operation completes.
     */
    void deleteSpaceResources(Space space, ActionListener<? extends ActionResponse> listener);
}
