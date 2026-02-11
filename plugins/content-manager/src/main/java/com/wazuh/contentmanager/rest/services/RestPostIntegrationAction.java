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
package com.wazuh.contentmanager.rest.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.PolicyHashService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.ContentUtils;
import com.wazuh.contentmanager.utils.DocumentValidations;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * REST handler for creating integration resources.
 *
 * <p>Endpoint: POST /_plugins/_content_manager/integrations
 *
 * <p>Creates an integration in the draft space.
 *
 * <p>HTTP responses:
 *
 * <ul>
 *   <li>202 Accepted: Decoder created successfully
 *   <li>400 Bad Request: Invalid payload or validation error
 *   <li>500 Internal Server Error: Engine unavailable or unexpected error
 * </ul>
 */
public class RestPostIntegrationAction extends BaseRestHandler {

    private static final String ENDPOINT_NAME = "content_manager_integration_create";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/integration_create";

    private ContentIndex integrationsIndex;
    private ContentIndex policiesIndex;
    private PolicyHashService policyHashService;
    private SecurityAnalyticsService service;
    private final EngineService engine;
    private final Logger log = LogManager.getLogger(RestPostIntegrationAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Constructs the action with the required engine service.
     *
     * @param engine The engine service used for resource validation.
     */
    public RestPostIntegrationAction(EngineService engine) {
        this.engine = engine;
    }

    /**
     * Returns the name of this action.
     *
     * @return The action name {@code content_manager_integration_create}.
     */
    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    /**
     * Defines the routes supported by this REST handler.
     *
     * @return An immutable list containing the POST route for creating integrations.
     */
    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.INTEGRATIONS_URI)
                        .method(POST)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    /**
     * Prepares the request for execution.
     *
     * <p>Initializes the necessary services and indices (PolicyHashService, ContentIndex,
     * SecurityAnalyticsService) using the provided client, and sets up the consumer to handle the
     * response from the business logic.
     *
     * @param request The incoming REST request.
     * @param client The node client to interface with OpenSearch.
     * @return A consumer that sends the REST response.
     * @throws IOException If an I/O error occurs during preparation.
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        this.setPolicyHashService(new PolicyHashService(client));
        this.setIntegrationsContentIndex(new ContentIndex(client, Constants.INDEX_INTEGRATIONS, null));
        this.setPoliciesContentIndex(new ContentIndex(client, Constants.INDEX_POLICIES, null));
        this.setSecurityAnalyticsService(new SecurityAnalyticsServiceImpl(client));
        return channel -> channel.sendResponse(this.handleRequest(request).toBytesRestResponse());
    }

    /**
     * Sets the policy hash service.
     *
     * @param policyHashService The service responsible for calculating policy hashes.
     */
    public void setPolicyHashService(PolicyHashService policyHashService) {
        this.policyHashService = policyHashService;
    }

    /**
     * Sets the content index for integrations.
     *
     * @param integrationsIndex The index wrapper for integration documents.
     */
    public void setIntegrationsContentIndex(ContentIndex integrationsIndex) {
        this.integrationsIndex = integrationsIndex;
    }

    /**
     * Sets the content index for policies.
     *
     * @param policiesIndex The index wrapper for policy documents.
     */
    public void setPoliciesContentIndex(ContentIndex policiesIndex) {
        this.policiesIndex = policiesIndex;
    }

    /**
     * Sets the Security Analytics service.
     *
     * @param service The service interface for Security Analytics operations.
     */
    public void setSecurityAnalyticsService(SecurityAnalyticsService service) {
        this.service = service;
    }

    /**
     * Handles the core business logic for creating an integration.
     *
     * <p>This method performs the following steps:
     *
     * <ol>
     *   <li>Validates dependencies and the incoming request payload.
     *   <li>Generates a UUID and timestamps for the new integration.
     *   <li>Upserts the integration into the Security Analytics service.
     *   <li>Validates the integration payload using the Engine service.
     *   <li>Indexes the integration into the {@code .cti-integrations} index.
     *   <li>Updates the associated draft policy in {@code .cti-policies} to include the new
     *       integration ID.
     *   <li>Recalculates the space hash for the draft space.
     * </ol>
     *
     * <p>If any step fails, appropriate rollback mechanisms (deletions) are triggered to maintain
     * consistency.
     *
     * @param request The REST request containing the integration JSON body.
     * @return A {@link RestResponse} indicating the outcome (Created, Bad Request, or Internal
     *     Error).
     * @throws IOException If an I/O error occurs during JSON parsing or response handling.
     */
    public RestResponse handleRequest(RestRequest request) throws IOException {
        this.log.debug(
                "POST integration request received (hasContent={}, uri={})",
                request.hasContent(),
                request.uri());

        if (this.engine == null) {
            this.log.error(Constants.E_LOG_ENGINE_IS_NULL);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        if (this.service == null) {
            this.log.error(Constants.E_LOG_SECURITY_ANALYTICS_IS_NULL);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // Validate prerequisites
        RestResponse validationError = DocumentValidations.validatePrerequisites(this.engine, request);
        if (validationError != null) {
            return validationError;
        }

        // Check request's payload is valid JSON
        JsonNode requestBody;
        try {
            requestBody = MAPPER.readTree(request.content().streamInput()).deepCopy();
        } catch (IOException ex) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // Check that there is no ID field
        if (!requestBody.at("/resource/id").isMissingNode()) {
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        JsonNode resource = requestBody.at("/resource");
        if (!resource.isObject()) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_RESOURCE),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // Validate mandatory fields
        if (!resource.has(Constants.KEY_TITLE)
                || resource.get(Constants.KEY_TITLE).asText().isBlank()) {
            return new RestResponse(
                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_TITLE),
                RestStatus.BAD_REQUEST.getStatus());
        }
        if (!resource.has(Constants.KEY_AUTHOR)
                || resource.get(Constants.KEY_AUTHOR).asText().isBlank()) {
            return new RestResponse(
                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_AUTHOR),
                RestStatus.BAD_REQUEST.getStatus());
        }
        if (!resource.has(Constants.KEY_CATEGORY)
                || resource.get(Constants.KEY_CATEGORY).asText().isBlank()) {
            return new RestResponse(
                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_CATEGORY),
                RestStatus.BAD_REQUEST.getStatus());
        }

        // Optional fields
        if (!resource.has(Constants.KEY_DESCRIPTION)) {
            ((ObjectNode) resource).put(Constants.KEY_DESCRIPTION, "");
        }
        if (!resource.has("documentation")) {
            ((ObjectNode) resource).put("documentation", "");
        }
        if (!resource.has("references")) {
            ((ObjectNode) resource).set("references", MAPPER.createArrayNode());
        }

        // Check non-modifiable fields
        RestResponse metadataError = ContentUtils.validateMetadataFields(resource, false);
        if (metadataError != null) {
            return metadataError;
        }

        String id = UUID.randomUUID().toString();

        // Insert ID
        ((ObjectNode) resource).put(Constants.KEY_ID, id);

        // Insert date
        ContentUtils.updateTimestampMetadata((ObjectNode) resource, true, false);

        // Check if enabled is set (if it's not, set it to true by default)
        if (!resource.has(Constants.KEY_ENABLED)) {
            ((ObjectNode) resource).put(Constants.KEY_ENABLED, true);
        }

        // Insert "draft" into /resource/space/name
        ((ObjectNode) requestBody)
                .putObject(Constants.KEY_SPACE)
                .put(Constants.KEY_NAME, Space.DRAFT.toString());

        // Overwrite rules, decoders and kvdbs arrays with empty ones
        ((ObjectNode) resource).set(Constants.KEY_RULES, MAPPER.createArrayNode());
        ((ObjectNode) resource).set(Constants.KEY_DECODERS, MAPPER.createArrayNode());
        ((ObjectNode) resource).set(Constants.KEY_KVDBS, MAPPER.createArrayNode());

        // Calculate and add a hash to the integration
        String hash = HashCalculator.sha256(resource.toString());
        ((ObjectNode) requestBody).putObject(Constants.KEY_HASH).put(Constants.KEY_SHA256, hash);

        // TODO: Instead of adding the Integration in the SAP and then validate it with the engine we
        // can do it in reverse order to guarantee that when a integration is not valid we don't need to
        // delete it from the SAP
        // Create integration in SAP
        this.service.upsertIntegration(
                JsonParser.parseString(
                                MAPPER.createObjectNode().set(Constants.KEY_DOCUMENT, resource).toString())
                        .getAsJsonObject(),
                Space.DRAFT,
                POST);

        // Construct engine validation payload
        this.log.debug(Constants.D_LOG_VALIDATING, Constants.KEY_INTEGRATION, id);
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set(Constants.KEY_RESOURCE, resource);
        enginePayload.put(Constants.KEY_TYPE, Constants.KEY_INTEGRATION);

        // Validate integration with Wazuh Engine
        final RestResponse validationResponse = this.engine.validate(enginePayload);

        try {
            MAPPER.readTree(validationResponse.getMessage()).isObject();
        } catch (Exception e) {
            this.log.error(Constants.E_LOG_ENGINE_VALIDATION, validationResponse.getMessage(), e);
            this.service.deleteIntegration(id);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        // If validation failed, delete the created integration in SAP
        if (validationResponse.getStatus() != RestStatus.OK.getStatus()) {
            this.log.error(Constants.E_LOG_ENGINE_VALIDATION, validationResponse.getMessage());
            this.service.deleteIntegration(id);
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        // From here on, we should roll back SAP integration on any error to avoid partial state.
        try {
            JsonNode ctiWrapper = ContentUtils.buildCtiWrapper(resource, Space.DRAFT.toString());

            IndexResponse integrationIndexResponse = this.integrationsIndex.create(id, ctiWrapper);

            if (integrationIndexResponse == null
                    || integrationIndexResponse.status() != RestStatus.CREATED) {
                this.log.error(
                        Constants.E_LOG_FAILED_TO,
                        "index",
                        Constants.KEY_INTEGRATION,
                        id,
                        integrationIndexResponse);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Search for the draft policy (scoped to policies index, limit 1)
            TermQueryBuilder queryBuilder =
                    new TermQueryBuilder(Constants.Q_SPACE_NAME, Space.DRAFT.toString());
            JsonObject draftPolicyHit;
            JsonNode draftPolicy;
            String draftPolicyId;

            try {
                JsonObject searchResult = this.policiesIndex.searchByQuery(queryBuilder);
                if (searchResult == null
                        || !searchResult.has(Constants.Q_HITS)
                        || searchResult.getAsJsonArray(Constants.Q_HITS).isEmpty()) {
                    throw new IllegalStateException("No hits found");
                }
                JsonArray hitsArray = searchResult.getAsJsonArray(Constants.Q_HITS);
                draftPolicyHit = hitsArray.get(0).getAsJsonObject();
                draftPolicyId = draftPolicyHit.get(Constants.KEY_ID).getAsString();
                draftPolicy = MAPPER.readTree(draftPolicyHit.toString());
            } catch (Exception e) {
                this.log.error(
                        Constants.E_LOG_FAILED_TO,
                        "find",
                        Constants.KEY_POLICY,
                        Space.DRAFT,
                        e.getMessage(),
                        e);
                this.integrationsIndex.delete(id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            JsonNode draftPolicyDocument = draftPolicy.at("/document");
            if (draftPolicyDocument.isMissingNode()) {
                this.log.error(
                        Constants.E_LOG_FAILED_TO,
                        "retrieve",
                        Constants.KEY_POLICY,
                        Space.DRAFT,
                        Constants.KEY_DOCUMENT);
                this.integrationsIndex.delete(id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Retrieve the integrations array from the policy document
            ArrayNode draftPolicyIntegrations =
                    (ArrayNode) draftPolicyDocument.get(Constants.KEY_INTEGRATIONS);
            if (draftPolicyIntegrations == null || !draftPolicyIntegrations.isArray()) {
                this.log.error(
                        Constants.E_LOG_FAILED_TO,
                        "retrieve",
                        Constants.KEY_INTEGRATIONS,
                        Space.DRAFT,
                        Constants.KEY_POLICY);
                this.integrationsIndex.delete(id);
                this.service.deleteIntegration(id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            // Add the new integration ID to the integrations array
            draftPolicyIntegrations.add(id);

            // Update the hash
            String integrationHash = HashCalculator.sha256(draftPolicyDocument.asText());
            ((ObjectNode) draftPolicy.at("/hash")).put(Constants.KEY_SHA256, integrationHash);

            IndexResponse indexDraftPolicyResponse =
                    this.policiesIndex.create(draftPolicyId, draftPolicy);

            if (indexDraftPolicyResponse == null || indexDraftPolicyResponse.status() != RestStatus.OK) {
                this.log.error(
                        Constants.E_LOG_FAILED_TO,
                        "update",
                        Constants.KEY_POLICY,
                        Space.DRAFT,
                        indexDraftPolicyResponse);
                this.service.deleteIntegration(id);
                this.integrationsIndex.delete(id);
                return new RestResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            return new RestResponse(id, RestStatus.CREATED.getStatus());
        } catch (Exception e) {
            this.log.error(
                    Constants.E_LOG_UNEXPECTED, "creating", Constants.KEY_INTEGRATION, id, e.getMessage(), e);
            this.service.deleteIntegration(id);
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }
}
