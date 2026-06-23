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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.wazuh.contentmanager.action.CreateFilterAction;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for creating Filter resources (Spaces variant). */
public class TransportCreateFilterAction extends AbstractTransportCreateActionSpaces {

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);
    private String spaceName = "";

    @Inject
    public TransportCreateFilterAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(CreateFilterAction.NAME, transportService, actionFilters, client, engine);
    }

    @Override
    protected boolean supportsYamlField() {
        return true;
    }

    @Override
    protected boolean requiresIntegrationId() {
        return false;
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_FILTERS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_FILTER;
    }

    @Override
    protected String getSpaceName() {
        return this.spaceName;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        if (resource.has(Constants.KEY_ID)) {
            return new RestResponse(
                    Constants.E_400_UUID_SHOULD_NOT_BE_PROVIDED, RestStatus.BAD_REQUEST.getStatus());
        }

        RestResponse fieldValidation =
                this.documentValidations.validateRequiredFields(resource, List.of(Constants.KEY_NAME));
        if (fieldValidation != null) return fieldValidation;

        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(
                        resource, List.of(Constants.KEY_TITLE, Constants.KEY_AUTHOR));
        if (metadataValidation != null) return metadataValidation;

        String spaceValue = root.path(Constants.KEY_SPACE).asText(null);
        if (!isValidSpace(spaceValue)) {
            return new RestResponse(
                    Constants.E_400_RESOURCE_SPACE_INVALID, RestStatus.BAD_REQUEST.getStatus());
        }
        this.spaceName = spaceValue;

        return null;
    }

    private boolean isValidSpace(String spaceValue) {
        if (spaceValue == null) return false;
        try {
            return validSpaces.contains(Space.fromValue(spaceValue));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        RestResponse engineValidation = this.engine.validateResource(Constants.KEY_FILTER, resource);
        if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    Constants.E_400_ENGINE_VALIDATION_FAILED + engineValidation.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    @Override
    protected void linkToParent(Client client, String id, JsonNode root) throws IOException {
        ContentIndex policiesIndex = new ContentIndex(client, Constants.INDEX_POLICIES);
        TermQueryBuilder queryBuilder =
                new TermQueryBuilder(Constants.Q_SPACE_NAME, this.getSpaceName());
        ObjectNode searchResult = policiesIndex.searchByQuery(queryBuilder);

        if (searchResult == null
                || !searchResult.has(Constants.Q_HITS)
                || searchResult.get(Constants.Q_HITS).isEmpty()) {
            throw new IllegalStateException(
                    String.format(Locale.ROOT, "%s policy not found", this.getSpaceName()));
        }

        ArrayNode hitsArray = (ArrayNode) searchResult.get(Constants.Q_HITS);
        JsonNode policyHit = hitsArray.get(0);
        String policyId = policyHit.get(Constants.KEY_ID).asText();
        JsonNode document = policyHit.get(Constants.KEY_DOCUMENT);

        ArrayNode filters;
        if (document.has(Constants.KEY_FILTERS)) {
            filters = (ArrayNode) document.get(Constants.KEY_FILTERS);
        } else {
            filters = MAPPER.createArrayNode();
            ((ObjectNode) document).set(Constants.KEY_FILTERS, filters);
        }

        filters.add(id);

        String hash = Resource.computeSha256(document.toString());
        ((ObjectNode) policyHit.at("/hash")).put(Constants.KEY_SHA256, hash);

        policiesIndex.create(policyId, policyHit);
    }
}
