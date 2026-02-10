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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Service responsible for calculating and updating policy hashes. Computes aggregate hashes (hash
 * of hashes) for policies based on their integrations.
 */
public class PolicyHashService {

    private static final Logger log = LogManager.getLogger(PolicyHashService.class);

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
     * This is a wrapper for its overloaded counterpart, intended to provide a default behavior that
     * processes only production spaces.
     */
    public void calculateAndUpdate() {

        List<String> productionSpaces =
                Arrays.stream(Space.values())
                        .filter(space -> !space.equals(Space.DRAFT) && !space.equals(Space.TEST))
                        .map(Space::toString)
                        .collect(Collectors.toList());

        this.calculateAndUpdate(productionSpaces);
    }

    /**
     * Calculates and updates the aggregate hash for all policies in the given consumer context.
     *
     * @param targetSpaces The list of target spaces to process.
     */
    public void calculateAndUpdate(List<String> targetSpaces) {
        try {
            if (!this.client.admin().indices().prepareExists(Constants.INDEX_POLICIES).get().isExists()) {
                log.warn(
                        "Policy index [{}] does not exist. Skipping hash calculation.",
                        Constants.INDEX_POLICIES);
                return;
            }

            SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
            searchRequest.source().query(QueryBuilders.matchAllQuery()).size(5);
            SearchResponse response = this.client.search(searchRequest).actionGet();

            BulkRequest bulkUpdateRequest = new BulkRequest();

            for (SearchHit hit : response.getHits().getHits()) {
                Map<String, Object> source = hit.getSourceAsMap();

                Map<String, Object> space = (Map<String, Object>) source.get(Constants.KEY_SPACE);
                if (space != null) {
                    String spaceName = (String) space.get(Constants.KEY_NAME);
                    // Check if the policy is in one of the target spaces
                    if (!targetSpaces.contains(spaceName)) {
                        log.info(
                                "Skipping hash calculation for policy [{}] because it is in space [{}]",
                                hit.getId(),
                                spaceName);
                        continue;
                    }
                }

                List<String> spaceHashes = new ArrayList<>();
                spaceHashes.add(HashCalculator.extractHash(source));

                Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
                if (document != null && document.containsKey(Constants.KEY_INTEGRATIONS)) {
                    List<String> integrationIds = (List<String>) document.get(Constants.KEY_INTEGRATIONS);

                    for (String integrationId : integrationIds) {
                        Map<String, Object> integrationSource =
                                IndexHelper.getDocumentSource(
                                        this.client, Constants.INDEX_INTEGRATIONS, integrationId);
                        if (integrationSource == null) {
                            continue;
                        }

                        spaceHashes.add(HashCalculator.extractHash(integrationSource));

                        Map<String, Object> integration =
                                (Map<String, Object>) integrationSource.get(Constants.KEY_DOCUMENT);
                        if (integration != null) {
                            this.addHashes(
                                    integration, Constants.KEY_DECODERS, Constants.INDEX_DECODERS, spaceHashes);
                            this.addHashes(integration, Constants.KEY_KVDBS, Constants.INDEX_KVDBS, spaceHashes);
                            this.addHashes(integration, Constants.KEY_RULES, Constants.INDEX_RULES, spaceHashes);
                        }
                    }
                }

                String spaceHash = HashCalculator.sha256(String.join("", spaceHashes));

                Map<String, Object> updateMap = new HashMap<>();
                Map<String, Object> spaceMap =
                        (Map<String, Object>) source.getOrDefault(Constants.KEY_SPACE, new HashMap<>());
                Map<String, Object> hashMap =
                        (Map<String, Object>) spaceMap.getOrDefault(Constants.KEY_HASH, new HashMap<>());

                hashMap.put(Constants.KEY_SHA256, spaceHash);
                spaceMap.put(Constants.KEY_HASH, hashMap);
                updateMap.put(Constants.KEY_SPACE, spaceMap);

                bulkUpdateRequest.add(
                        new UpdateRequest(Constants.INDEX_POLICIES, hit.getId())
                                .doc(updateMap, XContentType.JSON));
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
