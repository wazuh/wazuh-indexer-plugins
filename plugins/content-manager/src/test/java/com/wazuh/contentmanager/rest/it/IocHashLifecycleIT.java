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
package com.wazuh.contentmanager.rest.it;

import com.fasterxml.jackson.databind.JsonNode;

import org.opensearch.client.ResponseException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for IOC hash lifecycle behavior. Verifies that per-type SHA-256 hashes are
 * computed correctly and reflect changes when IOC documents are created, updated, or deleted.
 *
 * <p>These tests replicate the hash computation algorithm from {@code ConsumerIocService} using
 * REST API calls against a real OpenSearch test cluster, ensuring end-to-end correctness. Types are
 * discovered dynamically from the index rather than relying on a hardcoded set.
 */
public class IocHashLifecycleIT extends ContentManagerRestTestCase {

    private static final String IOC_INDEX = Constants.INDEX_IOCS;

    /**
     * Recreates the IOC index with the strict mapping from the plugin resources, replacing the
     * dynamic mapping created by the base class.
     */
    private void recreateIocIndexWithStrictMapping() throws IOException {
        try {
            this.makeRequest("DELETE", IOC_INDEX);
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() != 404) {
                throw e;
            }
        }

        String mapping;
        try (InputStream is = getClass().getResourceAsStream("/mappings/cti-ioc-mappings.json")) {
            assertNotNull("IOC mapping resource should exist", is);
            mapping = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        // spotless:off
        String indexBody = String.format(Locale.ROOT, """
                {
                    "settings": {"index": {"hidden": true, "number_of_replicas": 0}},
                    "mappings": %s
                }
                """, mapping);
        // spotless:on
        this.makeRequest("PUT", IOC_INDEX, indexBody);
    }

    /**
     * Indexes an IOC document with the given type and content.
     *
     * @param docId the document ID
     * @param type the IOC type (e.g., "connection", "url-full")
     * @param name the IOC name field
     */
    private void indexIocDocument(String docId, String type, String name) throws IOException {
        // spotless:off
        String doc = String.format(Locale.ROOT, """
                {
                    "document": {
                        "type": "%s",
                        "name": "%s",
                        "id": "%s",
                        "provider": "test",
                        "confidence": 80,
                        "feed": {"name": "test-feed"},
                        "tags": ["test"]
                    },
                    "hash": {
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    }
                }
                """, type, name, docId);
        // spotless:on
        this.makeRequest("PUT", IOC_INDEX + "/_doc/" + docId + "?refresh=true", doc);
    }

    /**
     * Deletes an IOC document by its ID.
     *
     * @param docId the document ID to delete
     */
    private void deleteIocDocument(String docId) throws IOException {
        this.makeRequest("DELETE", IOC_INDEX + "/_doc/" + docId + "?refresh=true");
    }

    /**
     * Discovers all distinct IOC types in the index using a terms aggregation, excluding the hash
     * summary document.
     *
     * @return a set of IOC type names present in the index
     */
    private Set<String> discoverTypes() throws IOException {
        this.refreshIndex(IOC_INDEX);
        // spotless:off
        String query = String.format(Locale.ROOT, """
                {
                    "size": 0,
                    "query": {
                        "bool": {
                            "must_not": [{"ids": {"values": ["%s"]}}]
                        }
                    },
                    "aggs": {
                        "ioc_types": {
                            "terms": {"field": "%s", "size": 1000}
                        }
                    }
                }
                """, Constants.IOC_TYPE_HASHES_ID, Constants.Q_DOCUMENT_TYPE);
        // spotless:on
        JsonNode result = this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_search", query));
        JsonNode buckets = result.path("aggregations").path("ioc_types").path("buckets");

        Set<String> types = new java.util.LinkedHashSet<>();
        for (JsonNode bucket : buckets) {
            types.add(bucket.path("key").asText());
        }
        return types;
    }

    /**
     * Computes per-type SHA-256 hashes by replicating the algorithm from {@code
     * ConsumerIocService.computeHashForType}. Types are discovered dynamically via aggregation.
     *
     * @return a map of IOC type to its computed SHA-256 hash
     */
    private Map<String, String> computeTypeHashes() throws IOException {
        Map<String, String> hashes = new HashMap<>();
        Set<String> types = this.discoverTypes();

        for (String type : types) {
            StringBuilder concatenated = new StringBuilder();

            // spotless:off
            String query = String.format(Locale.ROOT, """
                    {
                        "query": {"term": {"%s": "%s"}},
                        "sort": [{"_id": "asc"}],
                        "size": 10000
                    }
                    """, Constants.Q_DOCUMENT_TYPE, type);
            // spotless:on
            this.refreshIndex(IOC_INDEX);
            JsonNode searchResult =
                    this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_search", query));
            JsonNode hits = searchResult.path("hits").path("hits");

            for (JsonNode hit : hits) {
                concatenated.append(MAPPER.writeValueAsString(hit.path("_source")));
            }

            hashes.put(type, computeSha256(concatenated.toString()));
        }

        return hashes;
    }

    /**
     * Computes the SHA-256 hash of a string. Mirrors {@code Resource.computeSha256()}.
     *
     * @param payload the string to hash
     * @return the hexadecimal SHA-256 hash
     */
    private static String computeSha256(String payload) {
        try {
            byte[] hash =
                    MessageDigest.getInstance("SHA-256").digest(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /** Tests that creating IOC documents produces distinct hashes per type. */
    public void testHashChangesOnIocCreation() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Compute hashes with empty index — no types should be discovered
        Map<String, String> emptyHashes = this.computeTypeHashes();
        assertTrue("No types should be discovered on empty index", emptyHashes.isEmpty());

        // Index one IOC document of type "connection"
        this.indexIocDocument("ioc-conn-1", "connection", "malicious-conn-1");

        // Recompute hashes
        Map<String, String> afterCreateHashes = this.computeTypeHashes();

        // Only "connection" should be discovered
        assertEquals("Only connection type should exist", 1, afterCreateHashes.size());
        assertTrue("connection type should be discovered", afterCreateHashes.containsKey("connection"));

        String emptyHash = computeSha256("");
        assertNotEquals(
                "connection hash should differ from empty hash",
                emptyHash,
                afterCreateHashes.get("connection"));
    }

    /** Tests that updating an IOC document changes only the hash of its type. */
    public void testHashChangesOnIocUpdate() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Seed documents for two types
        this.indexIocDocument("ioc-conn-1", "connection", "malicious-conn-1");
        this.indexIocDocument("ioc-domain-1", "url-domain", "evil-domain-1");

        Map<String, String> beforeUpdateHashes = this.computeTypeHashes();

        // Update the connection document (re-index with different content)
        this.indexIocDocument("ioc-conn-1", "connection", "updated-malicious-conn-1");

        Map<String, String> afterUpdateHashes = this.computeTypeHashes();

        // connection hash should have changed
        assertNotEquals(
                "connection hash should change after updating a connection IOC",
                beforeUpdateHashes.get("connection"),
                afterUpdateHashes.get("connection"));

        // url-domain hash should remain the same
        assertEquals(
                "url-domain hash should remain unchanged when only connection IOCs are updated",
                beforeUpdateHashes.get("url-domain"),
                afterUpdateHashes.get("url-domain"));
    }

    /** Tests that deleting an IOC document changes only the hash of its type. */
    public void testHashChangesOnIocDeletion() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Seed documents for two types
        this.indexIocDocument("ioc-conn-1", "connection", "malicious-conn-1");
        this.indexIocDocument("ioc-domain-1", "url-domain", "evil-domain-1");

        Map<String, String> beforeDeleteHashes = this.computeTypeHashes();

        // Delete the connection document
        this.deleteIocDocument("ioc-conn-1");

        Map<String, String> afterDeleteHashes = this.computeTypeHashes();

        // connection type should no longer be discovered
        assertFalse(
                "connection should no longer appear after deleting all connection IOCs",
                afterDeleteHashes.containsKey("connection"));

        // url-domain hash should remain unchanged
        assertEquals(
                "url-domain hash should remain unchanged when only connection IOCs are deleted",
                beforeDeleteHashes.get("url-domain"),
                afterDeleteHashes.get("url-domain"));
    }

    /** Tests that hashes are deterministic across multiple computations. */
    public void testHashComputationIsDeterministic() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Index several documents
        this.indexIocDocument("ioc-conn-1", "connection", "malicious-conn-1");
        this.indexIocDocument("ioc-conn-2", "connection", "malicious-conn-2");
        this.indexIocDocument("ioc-domain-1", "url-domain", "evil-domain-1");

        // Compute hashes twice
        Map<String, String> hashes1 = this.computeTypeHashes();
        Map<String, String> hashes2 = this.computeTypeHashes();

        // All hashes should be identical
        assertEquals("Discovered types should be the same", hashes1.keySet(), hashes2.keySet());
        for (String type : hashes1.keySet()) {
            assertEquals(
                    "Hash for type '" + type + "' should be deterministic across computations",
                    hashes1.get(type),
                    hashes2.get(type));
        }
    }

    /** Tests the full create-update-delete lifecycle for multiple IOC types. */
    public void testFullLifecycle() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Phase 1: Empty state
        Map<String, String> emptyHashes = this.computeTypeHashes();
        assertTrue("No types should be discovered on empty index", emptyHashes.isEmpty());

        // Phase 2: Create IOCs for multiple types
        this.indexIocDocument("ioc-conn-1", "connection", "malicious-conn-1");
        this.indexIocDocument("ioc-conn-2", "connection", "malicious-conn-2");
        this.indexIocDocument("ioc-url-1", "url-full", "phishing-url-1");

        Map<String, String> afterCreateHashes = this.computeTypeHashes();
        assertEquals("Should discover 2 types", 2, afterCreateHashes.size());
        assertTrue("connection should be discovered", afterCreateHashes.containsKey("connection"));
        assertTrue("url-full should be discovered", afterCreateHashes.containsKey("url-full"));

        // Phase 3: Update one connection IOC
        this.indexIocDocument("ioc-conn-1", "connection", "updated-malicious-conn-1");

        Map<String, String> afterUpdateHashes = this.computeTypeHashes();
        assertNotEquals(
                "connection hash should change on update",
                afterCreateHashes.get("connection"),
                afterUpdateHashes.get("connection"));
        assertEquals(
                "url-full hash should remain unchanged",
                afterCreateHashes.get("url-full"),
                afterUpdateHashes.get("url-full"));

        // Phase 4: Delete all connection IOCs
        this.deleteIocDocument("ioc-conn-1");
        this.deleteIocDocument("ioc-conn-2");

        Map<String, String> afterDeleteHashes = this.computeTypeHashes();
        assertFalse(
                "connection should no longer be discovered after deleting all connection IOCs",
                afterDeleteHashes.containsKey("connection"));
        assertEquals(
                "url-full hash should remain unchanged through connection deletions",
                afterCreateHashes.get("url-full"),
                afterDeleteHashes.get("url-full"));
    }
}
