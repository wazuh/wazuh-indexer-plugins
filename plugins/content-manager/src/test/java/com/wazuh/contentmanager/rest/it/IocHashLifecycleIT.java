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

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for IOC hash lifecycle behavior. Verifies that per-type SHA-256 hashes are
 * computed correctly and reflect changes when IOC documents are created, updated, or deleted.
 *
 * <p>These tests replicate the hash computation algorithm from {@code ConsumerIocService} using
 * REST API calls against a real OpenSearch test cluster, ensuring end-to-end correctness.
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
     * @param type the IOC type (ipv4-addr, domain-name, url, file, geo)
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
     * Computes per-type SHA-256 hashes by replicating the algorithm from {@code
     * ConsumerIocService.computeHashForType}. For each IOC type, searches for all matching documents
     * sorted by {@code _id} ascending, concatenates their {@code _source} JSON, and computes the
     * SHA-256 hash.
     *
     * @return a map of IOC type to its computed SHA-256 hash
     */
    private Map<String, String> computeTypeHashes() throws IOException {
        Map<String, String> hashes = new HashMap<>();

        for (String type : Constants.IOC_TYPES) {
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
                // Use the raw _source JSON string, matching hit.getSourceAsString()
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

        // Compute hashes with empty index — all types should hash to SHA-256("")
        Map<String, String> emptyHashes = this.computeTypeHashes();
        String emptyHash = computeSha256("");
        for (String type : Constants.IOC_TYPES) {
            assertEquals(
                    "Hash for type '" + type + "' should be SHA-256 of empty string on empty index",
                    emptyHash,
                    emptyHashes.get(type));
        }

        // Index one IOC document of type "ipv4-addr"
        this.indexIocDocument("ioc-ip-1", "ipv4-addr", "malicious-ip-1");

        // Recompute hashes
        Map<String, String> afterCreateHashes = this.computeTypeHashes();

        // ipv4-addr hash should have changed
        assertNotEquals(
                "ipv4-addr hash should change after creating an ipv4-addr IOC",
                emptyHashes.get("ipv4-addr"),
                afterCreateHashes.get("ipv4-addr"));

        // All other types should remain unchanged
        for (String type : Constants.IOC_TYPES) {
            if (!"ipv4-addr".equals(type)) {
                assertEquals(
                        "Hash for type '"
                                + type
                                + "' should remain unchanged when only ipv4-addr IOCs are added",
                        emptyHashes.get(type),
                        afterCreateHashes.get(type));
            }
        }
    }

    /** Tests that updating an IOC document changes only the hash of its type. */
    public void testHashChangesOnIocUpdate() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Seed documents for two types
        this.indexIocDocument("ioc-ip-1", "ipv4-addr", "malicious-ip-1");
        this.indexIocDocument("ioc-domain-1", "domain-name", "evil-domain-1");

        Map<String, String> beforeUpdateHashes = this.computeTypeHashes();

        // Update the ipv4-addr document (re-index with different content)
        this.indexIocDocument("ioc-ip-1", "ipv4-addr", "updated-malicious-ip-1");

        Map<String, String> afterUpdateHashes = this.computeTypeHashes();

        // ip hash should have changed
        assertNotEquals(
                "ipv4-addr hash should change after updating an ipv4-addr IOC",
                beforeUpdateHashes.get("ipv4-addr"),
                afterUpdateHashes.get("ipv4-addr"));

        // domain-name hash should remain the same
        assertEquals(
                "domain-name hash should remain unchanged when only ipv4-addr IOCs are updated",
                beforeUpdateHashes.get("domain-name"),
                afterUpdateHashes.get("domain-name"));

        // Other empty types should also remain unchanged
        for (String type : Constants.IOC_TYPES) {
            if (!"ipv4-addr".equals(type)) {
                assertEquals(
                        "Hash for type '"
                                + type
                                + "' should remain unchanged when only ipv4-addr IOCs are updated",
                        beforeUpdateHashes.get(type),
                        afterUpdateHashes.get(type));
            }
        }
    }

    /** Tests that deleting an IOC document changes only the hash of its type. */
    public void testHashChangesOnIocDeletion() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Seed documents for two types
        this.indexIocDocument("ioc-ip-1", "ipv4-addr", "malicious-ip-1");
        this.indexIocDocument("ioc-domain-1", "domain-name", "evil-domain-1");

        Map<String, String> beforeDeleteHashes = this.computeTypeHashes();

        // Delete the ipv4-addr document
        this.deleteIocDocument("ioc-ip-1");

        Map<String, String> afterDeleteHashes = this.computeTypeHashes();

        // ipv4-addr hash should revert to the empty hash
        String emptyHash = computeSha256("");
        assertEquals(
                "ipv4-addr hash should revert to empty hash after deleting all ip IOCs",
                emptyHash,
                afterDeleteHashes.get("ipv4-addr"));
        assertNotEquals(
                "ipv4-addr hash should differ from the pre-delete value",
                beforeDeleteHashes.get("ipv4-addr"),
                afterDeleteHashes.get("ipv4-addr"));

        // domain-name hash should remain unchanged
        assertEquals(
                "domain-name hash should remain unchanged when only ipv4-addr IOCs are deleted",
                beforeDeleteHashes.get("domain-name"),
                afterDeleteHashes.get("domain-name"));
    }

    /** Tests that hashes are deterministic across multiple computations. */
    public void testHashComputationIsDeterministic() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Index several documents
        this.indexIocDocument("ioc-ip-1", "ipv4-addr", "malicious-ip-1");
        this.indexIocDocument("ioc-ip-2", "ipv4-addr", "malicious-ip-2");
        this.indexIocDocument("ioc-domain-1", "domain-name", "evil-domain-1");

        // Compute hashes twice
        Map<String, String> hashes1 = this.computeTypeHashes();
        Map<String, String> hashes2 = this.computeTypeHashes();

        // All hashes should be identical
        for (String type : Constants.IOC_TYPES) {
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
        String emptyHash = computeSha256("");

        // Phase 2: Create IOCs for multiple types
        this.indexIocDocument("ioc-ip-1", "ipv4-addr", "malicious-ip-1");
        this.indexIocDocument("ioc-ip-2", "ipv4-addr", "malicious-ip-2");
        this.indexIocDocument("ioc-url-1", "url", "phishing-url-1");

        Map<String, String> afterCreateHashes = this.computeTypeHashes();
        assertNotEquals("ip hash should change", emptyHash, afterCreateHashes.get("ipv4-addr"));
        assertNotEquals("url hash should change", emptyHash, afterCreateHashes.get("url"));
        assertEquals(
                "domain-name hash should remain empty", emptyHash, afterCreateHashes.get("domain-name"));

        // Phase 3: Update one ipv4-addr IOC
        this.indexIocDocument("ioc-ip-1", "ipv4-addr", "updated-malicious-ip-1");

        Map<String, String> afterUpdateHashes = this.computeTypeHashes();
        assertNotEquals(
                "ip hash should change on update",
                afterCreateHashes.get("ipv4-addr"),
                afterUpdateHashes.get("ipv4-addr"));
        assertEquals(
                "url hash should remain unchanged",
                afterCreateHashes.get("url"),
                afterUpdateHashes.get("url"));

        // Phase 4: Delete all ip IOCs
        this.deleteIocDocument("ioc-ip-1");
        this.deleteIocDocument("ioc-ip-2");

        Map<String, String> afterDeleteHashes = this.computeTypeHashes();
        assertEquals(
                "ipv4-addr hash should revert to empty after deleting all ipv4-addr IOCs",
                emptyHash,
                afterDeleteHashes.get("ipv4-addr"));
        assertEquals(
                "url hash should remain unchanged through ipv4-addr deletions",
                afterCreateHashes.get("url"),
                afterDeleteHashes.get("url"));
    }
}
