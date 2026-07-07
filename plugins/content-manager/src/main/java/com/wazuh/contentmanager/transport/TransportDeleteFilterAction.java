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
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Set;

import com.wazuh.contentmanager.action.DeleteFilterAction;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for deleting Filter resources (Spaces variant). */
public class TransportDeleteFilterAction extends AbstractTransportDeleteActionSpaces {

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    public TransportDeleteFilterAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(DeleteFilterAction.NAME, transportService, actionFilters, client, engine);
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
    protected Set<Space> getAllowedSpaces() {
        return validSpaces;
    }

    @Override
    protected void deleteExternalServices(String id) {
        // Not applicable for this implementation.
    }

    @Override
    protected void unlinkFromParent(Client client, String id, String spaceName) throws Exception {
        ContentIndex policiesIndex = new ContentIndex(client, Constants.INDEX_POLICIES);
        TermQueryBuilder queryBuilder = new TermQueryBuilder(Constants.Q_SPACE_NAME, spaceName);
        ObjectNode searchResult = policiesIndex.searchByQuery(queryBuilder);

        if (searchResult == null
                || !searchResult.has(Constants.Q_HITS)
                || searchResult.get(Constants.Q_HITS).isEmpty()) {
            throw new IllegalStateException("Policy not found");
        }

        ArrayNode hitsArray = (ArrayNode) searchResult.get(Constants.Q_HITS);
        JsonNode draftPolicyHit = hitsArray.get(0);
        String draftPolicyId = draftPolicyHit.get(Constants.KEY_ID).asText();
        JsonNode document = draftPolicyHit.get(Constants.KEY_DOCUMENT);

        ArrayNode filters = (ArrayNode) document.get(Constants.KEY_FILTERS);
        if (filters == null) return;

        ArrayNode updatedFilters = MAPPER.createArrayNode();
        boolean removed = false;
        for (JsonNode filterId : filters) {
            if (!filterId.asText().equals(id)) {
                updatedFilters.add(filterId);
            } else {
                removed = true;
            }
        }

        if (removed) {
            ((ObjectNode) document).set(Constants.KEY_FILTERS, updatedFilters);
            String hash = Resource.computeSha256(document.toString());
            ((ObjectNode) draftPolicyHit.at("/hash")).put(Constants.KEY_SHA256, hash);
            policiesIndex.create(draftPolicyId, draftPolicyHit);
        }
    }
}
