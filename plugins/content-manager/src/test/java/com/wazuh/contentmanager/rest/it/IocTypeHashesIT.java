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
import java.util.List;
import java.util.Locale;
import java.util.StringJoiner;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for per-type IOC hash summary documents. Verifies that the IOC index mapping
 * accepts both regular IOC documents and the hash summary document with a dynamic {@code
 * type_hashes} field.
 */
public class IocTypeHashesIT extends ContentManagerRestTestCase {

    private static final String IOC_INDEX = Constants.INDEX_IOCS;
    private static final String HASH_DOC_ID = Constants.IOC_TYPE_HASHES_ID;

    /**
     * Recreates the IOC index with the strict mapping from the plugin resources, replacing the
     * dynamic mapping created by the base class.
     */
    private void recreateIocIndexWithStrictMapping() throws IOException {
        // Delete the index created by the base class (dynamic mapping)
        try {
            this.makeRequest("DELETE", IOC_INDEX);
        } catch (ResponseException e) {
            // 404 is fine — index may not exist
            if (e.getResponse().getStatusLine().getStatusCode() != 404) {
                throw e;
            }
        }

        // Read the strict mapping from the plugin resources
        String mapping;
        try (InputStream is = getClass().getResourceAsStream("/mappings/cti-ioc-mappings.json")) {
            assertNotNull("IOC mapping resource should exist", is);
            mapping = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        // Create the index with strict mapping
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
     * Indexes an IOC document with the given type.
     *
     * @param docId the document ID
     * @param type the IOC type (e.g., "connection", "url-full")
     */
    private void indexIocDocument(String docId, String type) throws IOException {
        // spotless:off
        String doc = String.format(Locale.ROOT, """
                {
                    "document": {
                        "type": "%s",
                        "name": "test-ioc-%s",
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
                """, type, docId, docId);
        // spotless:on
        this.makeRequest("PUT", IOC_INDEX + "/_doc/" + docId + "?refresh=true", doc);
    }

    /**
     * Indexes a hash summary document with per-type SHA-256 hashes under the {@code type_hashes}
     * wrapper.
     *
     * @param types the IOC type names
     * @param hash the hash value to use for all types
     */
    private void indexHashSummaryDocument(List<String> types, String hash) throws IOException {
        StringJoiner entries = new StringJoiner(",\n        ");
        for (String type : types) {
            entries.add(
                    String.format(Locale.ROOT, "\"%s\": {\"hash\": {\"sha256\": \"%s\"}}", type, hash));
        }
        // spotless:off
        String doc = String.format(Locale.ROOT, """
                {
                    "type_hashes": {
                        %s
                    }
                }
                """, entries);
        // spotless:on
        this.makeRequest("PUT", IOC_INDEX + "/_doc/" + HASH_DOC_ID + "?refresh=true", doc);
    }

    /** Tests that the mapping accepts the hash summary document with type_hashes wrapper. */
    public void testMappingAcceptsHashSummaryDocument() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        List<String> types = List.of("connection", "url-full", "url-domain");
        String hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        this.indexHashSummaryDocument(types, hash);

        // Retrieve the document and verify structure
        JsonNode result =
                this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_doc/" + HASH_DOC_ID));
        assertTrue("Document should be found", result.path("found").asBoolean());

        JsonNode typeHashes = result.path("_source").path(Constants.KEY_TYPE_HASHES);
        for (String type : types) {
            String actual = typeHashes.path(type).path("hash").path("sha256").asText("");
            assertEquals("Hash for type '" + type + "' should match", hash, actual);
        }
    }

    /** Tests that the mapping accepts both IOC documents and the hash summary document. */
    public void testMappingAcceptsBothDocumentTypes() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Index IOC documents of different types
        this.indexIocDocument("ioc-conn-1", "connection");
        this.indexIocDocument("ioc-domain-1", "url-domain");
        this.indexIocDocument("ioc-url-1", "url-full");

        // Index the hash summary document with dynamic types
        List<String> types = List.of("connection", "url-domain", "url-full");
        String hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        this.indexHashSummaryDocument(types, hash);

        // Verify IOC documents exist
        // spotless:off
        String query = """
                {"query": {"term": {"document.type": "connection"}}}
                """;
        // spotless:on
        JsonNode searchResult = this.searchIndex(IOC_INDEX, query);
        long totalHits = searchResult.path("hits").path("total").path("value").asLong(0);
        assertTrue("Should find the connection IOC document", totalHits > 0);

        // Verify hash summary document exists and is distinct from IOC documents
        JsonNode hashDoc =
                this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_doc/" + HASH_DOC_ID));
        assertTrue("Hash summary document should exist", hashDoc.path("found").asBoolean());
        assertFalse(
                "Hash summary document should not have a 'document' field",
                hashDoc.path("_source").has("document"));
    }

    /**
     * Tests that the mapping accepts hash summary documents with arbitrary (previously unknown) type
     * names, thanks to the dynamic type_hashes field.
     */
    public void testMappingAcceptsArbitraryTypeNames() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        List<String> types = List.of("custom-type-1", "my-new-ioc-type", "another_type");
        String hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        this.indexHashSummaryDocument(types, hash);

        JsonNode result =
                this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_doc/" + HASH_DOC_ID));
        assertTrue("Document should be found", result.path("found").asBoolean());

        JsonNode typeHashes = result.path("_source").path(Constants.KEY_TYPE_HASHES);
        for (String type : types) {
            String actual = typeHashes.path(type).path("hash").path("sha256").asText("");
            assertEquals("Hash for type '" + type + "' should match", hash, actual);
        }
    }

    /** Tests that a document with an unmapped field is rejected by the strict mapping. */
    public void testStrictMappingRejectsUnmappedField() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // spotless:off
        String invalidDoc = """
                {
                    "unknown_field": "this should be rejected"
                }
                """;
        // spotless:on
        ResponseException exception =
                expectThrows(
                        ResponseException.class,
                        () ->
                                this.makeRequest("PUT", IOC_INDEX + "/_doc/invalid-doc?refresh=true", invalidDoc));
        assertTrue(
                "Should be a 400 strict mapping rejection",
                exception.getResponse().getStatusLine().getStatusCode() == 400);
    }

    /** Tests that the hash summary document can be updated (overwritten). */
    public void testHashSummaryDocumentCanBeUpdated() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        List<String> types = List.of("connection", "url-full");
        String hash1 = "1111111111111111111111111111111111111111111111111111111111111111";
        String hash2 = "2222222222222222222222222222222222222222222222222222222222222222";

        // Index initial hash summary
        this.indexHashSummaryDocument(types, hash1);

        // Overwrite with new hashes
        this.indexHashSummaryDocument(types, hash2);

        // Verify the document was updated
        JsonNode result =
                this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_doc/" + HASH_DOC_ID));
        JsonNode typeHashes = result.path("_source").path(Constants.KEY_TYPE_HASHES);

        for (String type : types) {
            String actual = typeHashes.path(type).path("hash").path("sha256").asText("");
            assertEquals("Hash for type '" + type + "' should be the updated value", hash2, actual);
        }
    }

    /** Tests that the hash summary document is not returned by type-filtered queries. */
    public void testHashSummaryExcludedFromTypeQueries() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Index an IOC document and the hash summary
        this.indexIocDocument("ioc-conn-1", "connection");
        this.indexHashSummaryDocument(
                List.of("connection"), "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");

        // Query by document.type — hash summary has no document.type, so it should be excluded
        // spotless:off
        String query = """
                {"query": {"exists": {"field": "document.type"}}}
                """;
        // spotless:on
        JsonNode searchResult = this.searchIndex(IOC_INDEX, query);
        long totalHits = searchResult.path("hits").path("total").path("value").asLong(0);
        assertEquals("Only the IOC document should match, not the hash summary", 1, totalHits);
    }
}
