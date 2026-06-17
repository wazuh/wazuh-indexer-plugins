/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.JsonNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsException;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * POST /_plugins/content-manager/rules
 *
 * <p>Creates a new Rule in the draft space.
 *
 * <p>This action ensures that:
 *
 * <ul>
 *   <li>The payload contains all mandatory fields (title).
 *   <li>The parent integration exists and is in the draft space.
 *   <li>The rule's logsource.product matches the integration's metadata.title.
 *   <li>A new UUID and creation timestamps are generated.
 *   <li>The rule is created in the Security Analytics Plugin (SAP).
 *   <li>The rule is indexed in the draft space.
 *   <li>The new rule is linked to the parent Integration.
 * </ul>
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>201 Created: Rule created successfully.
 *   <li>400 Bad Request: Missing fields, invalid payload, duplicate name, parent integration
 *       validation failure, or product/title mismatch.
 *   <li>500 Internal Server Error: SAP error or unexpected error.
 * </ul>
 */
public class RestPostRuleAction extends AbstractCreateAction {

    private static final Logger log = LogManager.getLogger(RestPostRuleAction.class);
    private static final String ENDPOINT_NAME = "content_manager_rule_create";

    public RestPostRuleAction() {
        super(null);
    }

    /** Return a short identifier for this handler. */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Return the route configuration for this handler.
     *
     * @return route configuration for the update endpoint
     */
    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, PluginSettings.RULES_URI));
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_RULES;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_RULE;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(resource, List.of(Constants.KEY_TITLE));
        if (metadataValidation != null) return metadataValidation;

        String title = resource.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText();
        RestResponse duplicateValidation =
                this.documentValidations.validateDuplicateTitle(
                        client, Constants.INDEX_RULES, Space.DRAFT.toString(), title, null, Constants.KEY_RULE);
        if (duplicateValidation != null) return duplicateValidation;

        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        String spaceError =
                this.documentValidations.validateDocumentInSpace(
                        client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
        if (spaceError != null) return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());

        // Validate that logsource.product matches the integration's metadata.title
        GetResponse integrationResponse =
                client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();
        if (integrationResponse.isExists()) {
            Map<String, Object> source = integrationResponse.getSourceAsMap();
            if (source != null && source.containsKey(Constants.KEY_DOCUMENT)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> doc = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
                if (doc != null && doc.containsKey(Constants.KEY_METADATA)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> metadata = (Map<String, Object>) doc.get(Constants.KEY_METADATA);
                    String integrationTitle =
                            metadata != null ? (String) metadata.get(Constants.KEY_TITLE) : null;

                    String ruleProduct = null;
                    if (resource.has(Constants.KEY_LOGSOURCE)
                            && resource.get(Constants.KEY_LOGSOURCE).has(Constants.KEY_PRODUCT)) {
                        ruleProduct = resource.get(Constants.KEY_LOGSOURCE).get(Constants.KEY_PRODUCT).asText();
                    }

                    if (integrationTitle == null || !integrationTitle.equals(ruleProduct)) {
                        return new RestResponse(
                                "Rule logsource.product ('"
                                        + ruleProduct
                                        + "') must match the integration's metadata.title ('"
                                        + integrationTitle
                                        + "').",
                                RestStatus.BAD_REQUEST.getStatus());
                    }
                }
            }
        }

        // Enforce max rules limit
        int maxRules = PluginSettings.getInstance().getMaxRules();
        SearchRequest countRequest = new SearchRequest(Constants.INDEX_RULES);
        SearchSourceBuilder countSource = new SearchSourceBuilder();
        countSource.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
        countSource.size(0);
        countSource.trackTotalHits(true);
        countRequest.source(countSource);
        try {
            SearchResponse countResponse = client.search(countRequest).actionGet();
            long count =
                    countResponse.getHits().getTotalHits() != null
                            ? countResponse.getHits().getTotalHits().value()
                            : 0;
            if (count >= maxRules) {
                log.info(Constants.I_LOG_MAX_RULES_REACHED, maxRules);
                return new RestResponse(
                        String.format(Locale.ROOT, Constants.E_400_TOO_MANY_RULES, maxRules),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        } catch (Exception e) {
            // If counting fails (e.g., index does not exist yet), allow creation to proceed.
            log.warn("Failed to count existing rules for limit check: {}", e.getMessage());
        }

        return null;
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        try {
            this.securityAnalyticsService.upsertRule(resource, Space.DRAFT, Method.POST);
            return null;
        } catch (SecurityAnalyticsException e) {
            return new RestResponse(
                    Constants.E_SECURITY_ANALYTICS_ERROR + " " + e.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            OpenSearchSecurityException secEx = AbstractContentAction.extractSecurityException(e);
            if (secEx != null) {
                return new RestResponse(secEx.getMessage(), secEx.status().getStatus());
            }
            String msg = e.getMessage() != null ? e.getMessage() : "Unknown error";
            return new RestResponse(
                    Constants.E_SECURITY_ANALYTICS_ERROR + " " + msg,
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    @Override
    protected void linkToParent(Client client, String id, JsonNode root) throws IOException {
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        this.integrationService.linkResourceToIntegration(integrationId, id, Constants.KEY_RULES);
    }
}
