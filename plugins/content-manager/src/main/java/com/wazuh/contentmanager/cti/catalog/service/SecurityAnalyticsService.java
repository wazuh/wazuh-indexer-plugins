package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.JsonObject;

/**
 * Service interface for managing interactions with the Security Analytics Plugin (SAP).
 * Defines operations for synchronizing Integrations, Rules, and Detectors.
 */
public interface SecurityAnalyticsService {

    /**
     * Creates or updates an Integration in SAP.
     *
     * @param doc The JSON document containing the integration data.
     */
    void upsertIntegration(JsonObject doc);

    /**
     * Deletes an Integration from SAP.
     * This typically involves deleting the associated Detector first.
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
