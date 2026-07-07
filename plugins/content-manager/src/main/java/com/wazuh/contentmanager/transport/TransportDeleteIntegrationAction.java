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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Locale;

import com.wazuh.contentmanager.action.DeleteIntegrationAction;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for deleting Integration resources. */
public class TransportDeleteIntegrationAction extends AbstractTransportDeleteAction {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    public TransportDeleteIntegrationAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(DeleteIntegrationAction.NAME, transportService, actionFilters, client, engine);
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_INTEGRATIONS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_INTEGRATION;
    }

    @Override
    protected RestResponse validateDelete(
            Client client,
            String id,
            com.wazuh.contentmanager.cti.catalog.service.SpaceService spaceService) {
        ContentIndex index = new ContentIndex(client, Constants.INDEX_INTEGRATIONS, null);
        JsonNode doc = index.getDocument(id);

        if (doc != null && doc.has(Constants.KEY_DOCUMENT)) {
            JsonNode document = doc.get(Constants.KEY_DOCUMENT);
            if (isListNotEmpty(document.get(Constants.KEY_DECODERS))) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_DECODERS),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            if (isListNotEmpty(document.get(Constants.KEY_RULES))) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_RULES),
                        RestStatus.BAD_REQUEST.getStatus());
            }
            if (isListNotEmpty(document.get(Constants.KEY_KVDBS))) {
                return new RestResponse(
                        String.format(
                                Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_KVDBS),
                        RestStatus.BAD_REQUEST.getStatus());
            }
        }
        return null;
    }

    @Override
    protected void deleteExternalServices(
            String id, SecurityAnalyticsService securityAnalyticsService) {
        securityAnalyticsService.deleteIntegration(id, Space.DRAFT);
    }

    @Override
    protected void unlinkFromParent(Client client, String id, IntegrationService integrationService)
            throws java.io.IOException {
        ContentIndex policiesIndex = new ContentIndex(client, Constants.INDEX_POLICIES);
        TermQueryBuilder queryBuilder =
                new TermQueryBuilder(Constants.Q_SPACE_NAME, Space.DRAFT.toString());
        ObjectNode searchResult = policiesIndex.searchByQuery(queryBuilder);

        if (searchResult == null
                || !searchResult.has(Constants.Q_HITS)
                || searchResult.get(Constants.Q_HITS).isEmpty()) {
            throw new IllegalStateException(Constants.E_500_MISSING_DRAFT_POLICY);
        }

        ArrayNode hitsArray = (ArrayNode) searchResult.get(Constants.Q_HITS);
        JsonNode draftPolicyHit = hitsArray.get(0);
        String draftPolicyId = draftPolicyHit.get(Constants.KEY_ID).asText();
        JsonNode document = draftPolicyHit.get(Constants.KEY_DOCUMENT);

        ArrayNode integrations = (ArrayNode) document.get(Constants.KEY_INTEGRATIONS);
        if (integrations == null) return;

        ArrayNode updatedIntegrations = MAPPER.createArrayNode();
        boolean removed = false;
        for (JsonNode integrationId : integrations) {
            if (!integrationId.asText().equals(id)) {
                updatedIntegrations.add(integrationId);
            } else {
                removed = true;
            }
        }

        if (removed) {
            ((ObjectNode) document).set(Constants.KEY_INTEGRATIONS, updatedIntegrations);
            String hash = Resource.computeSha256(document.toString());
            ((ObjectNode) draftPolicyHit.at("/hash")).put(Constants.KEY_SHA256, hash);
            policiesIndex.create(draftPolicyId, draftPolicyHit);
        }
    }

    private boolean isListNotEmpty(JsonNode node) {
        return node != null && node.isArray() && !node.isEmpty();
    }
}
