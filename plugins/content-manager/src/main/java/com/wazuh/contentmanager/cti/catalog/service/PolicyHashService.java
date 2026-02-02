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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;

/**
 * Service responsible for calculating and updating policy hashes. Computes aggregate hashes (hash
 * of hashes) for policies based on their integrations.
 */
public class PolicyHashService {

    private static final Logger log = LogManager.getLogger(PolicyHashService.class);

    /** Field name for the space metadata within documents. */
    public static final String SPACE = "space";

    /** Field name for the main document content within index records. */
    public static final String DOCUMENT = "document";

    /** Field name for the decoders collection within integration documents. */
    public static final String DECODERS = "decoders";

    /** Field name for the key-value databases collection within integration documents. */
    public static final String KVDBS = "kvdbs";

    /** Field name for the rules collection within integration documents. */
    public static final String RULES = "rules";

    /** Field name for the integrations collection within policy documents. */
    public static final String INTEGRATIONS = "integrations";

    /** OpenSearch client for executing index operations and search requests. */
    private final Client client;

    /**
     * Constructs a new PolicyHashService.
     *
     * @param client The OpenSearch client.
     */
    public PolicyHashService(Client client) {
        this.client = client;
    }

    /**
     * Calculates and updates the aggregate hash for all policies in the given consumer context.
     *
     * @param policyIndex The index containing policy document.
     * @param integrationIndex The index containing integration documents.
     * @param decoderIndex The index containing decoder documents.
     * @param kvdbIndex The index containing kvdb documents.
     * @param ruleIndex The index containing rule documents.
     */
    public void calculateAndUpdate(
            String policyIndex,
            String integrationIndex,
            String decoderIndex,
            String kvdbIndex,
            String ruleIndex) {
        try {
            if (!this.client.admin().indices().prepareExists(policyIndex).get().isExists()) {
                log.warn("Policy index [{}] does not exist. Skipping hash calculation.", policyIndex);
                return;
            }

            SearchRequest searchRequest = new SearchRequest(policyIndex);
            searchRequest.source().query(QueryBuilders.matchAllQuery()).size(5);
            SearchResponse response = this.client.search(searchRequest).actionGet();

            BulkRequest bulkUpdateRequest = new BulkRequest();

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> source = hit.getSourceAsMap();

                Map<String, Object> space = (Map<String, Object>) source.get(SPACE);
                if (space != null) {
                    String spaceName = (String) space.get("name");
                    if (Space.DRAFT.equals(spaceName) || Space.TEST.equals(spaceName)) {
                        log.info(
                                "Skipping hash calculation for policy [{}] because it is in space [{}]",
                                hit.getId(),
                                spaceName);
                        continue;
                    }
                }

                List<String> spaceHashes = new ArrayList<>();
                spaceHashes.add(HashCalculator.extractHash(source));

                Map<String, Object> document = (Map<String, Object>) source.get(DOCUMENT);
                if (document != null && document.containsKey(INTEGRATIONS)) {
                    List<String> integrationIds = (List<String>) document.get(INTEGRATIONS);

                    for (String integrationId : integrationIds) {
                        Map<String, Object> integrationSource =
                                IndexHelper.getDocumentSource(this.client, integrationIndex, integrationId);
                        if (integrationSource == null) {
                            continue;
                        }

                        spaceHashes.add(HashCalculator.extractHash(integrationSource));

                        Map<String, Object> integration = (Map<String, Object>) integrationSource.get(DOCUMENT);
                        if (integration != null) {
                            this.addHashes(integration, DECODERS, decoderIndex, spaceHashes);
                            this.addHashes(integration, KVDBS, kvdbIndex, spaceHashes);
                            this.addHashes(integration, RULES, ruleIndex, spaceHashes);
                        }
                    }
                }

                String spaceHash = HashCalculator.sha256(String.join("", spaceHashes));

                Map<String, Object> updateMap = new HashMap<>();
                Map<String, Object> spaceMap =
                        (Map<String, Object>) source.getOrDefault(SPACE, new HashMap<>());
                Map<String, Object> hashMap =
                        (Map<String, Object>) spaceMap.getOrDefault("hash", new HashMap<>());

                hashMap.put("sha256", spaceHash);
                spaceMap.put("hash", hashMap);
                updateMap.put(SPACE, spaceMap);

                bulkUpdateRequest.add(
                        new UpdateRequest(policyIndex, hit.getId()).doc(updateMap, XContentType.JSON));
            }

            if (bulkUpdateRequest.numberOfActions() > 0) {
                this.client.bulk(bulkUpdateRequest).actionGet();
                log.info("Updated policy hashes.");
            }

        } catch (Exception e) {
            log.error("Error calculating policy hashes: {}", e.getMessage(), e);
        }
    }

    /**
     * Adds hashes from resources of a specific type within an integration to the hash list.
     *
     * @param integration The integration document.
     * @param resource The resource type (decoders, kvdbs, rules).
     * @param resourceIndex The index containing the resources.
     * @param spaceHashes The list to add hashes to.
     */
    private void addHashes(
            Map<String, Object> integration,
            String resource,
            String resourceIndex,
            List<String> spaceHashes) {
        if (integration.containsKey(resource)) {
            List<String> resourceIds = (List<String>) integration.get(resource);
            for (String id : resourceIds) {
                Map<String, Object> resourceSource =
                        IndexHelper.getDocumentSource(this.client, resourceIndex, id);
                if (resourceSource != null) {
                    spaceHashes.add(HashCalculator.extractHash(resourceSource));
                }
            }
        }
    }
}
