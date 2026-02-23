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
import java.util.Locale;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for per-type IOC hash summary documents. Verifies that the strict IOC index
 * mapping accepts both regular IOC documents and the hash summary document structure.
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
     * @param type the IOC type (ip, domain-name, url, file, geo)
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
     * Indexes a hash summary document with per-type SHA-256 hashes.
     *
     * @param hashes the hash values per type in order: ip, domain-name, url, file, geo
     */
    private void indexHashSummaryDocument(String... hashes) throws IOException {
        assertEquals("Must provide exactly 5 hashes", Constants.IOC_TYPES.size(), hashes.length);
        // spotless:off
        String doc = String.format(Locale.ROOT, """
                {
                    "ip": {"hash": {"sha256": "%s"}},
                    "domain-name": {"hash": {"sha256": "%s"}},
                    "url": {"hash": {"sha256": "%s"}},
                    "file": {"hash": {"sha256": "%s"}},
                    "geo": {"hash": {"sha256": "%s"}}
                }
                """, (Object[]) hashes);
        // spotless:on
        this.makeRequest("PUT", IOC_INDEX + "/_doc/" + HASH_DOC_ID + "?refresh=true", doc);
    }

    /** Tests that the strict mapping accepts the hash summary document. */
    public void testStrictMappingAcceptsHashSummaryDocument() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        String hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        this.indexHashSummaryDocument(hash, hash, hash, hash, hash);

        // Retrieve the document and verify structure
        JsonNode result =
                this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_doc/" + HASH_DOC_ID));
        assertTrue("Document should be found", result.path("found").asBoolean());

        JsonNode source = result.path("_source");
        for (String type : Constants.IOC_TYPES) {
            String actual = source.path(type).path("hash").path("sha256").asText("");
            assertEquals("Hash for type '" + type + "' should match", hash, actual);
        }
    }

    /** Tests that the strict mapping accepts both IOC documents and the hash summary document. */
    public void testStrictMappingAcceptsBothDocumentTypes() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Index IOC documents of different types
        this.indexIocDocument("ioc-ip-1", "ip");
        this.indexIocDocument("ioc-domain-1", "domain-name");
        this.indexIocDocument("ioc-url-1", "url");

        // Index the hash summary document
        String hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        this.indexHashSummaryDocument(hash, hash, hash, hash, hash);

        // Verify IOC documents exist
        // spotless:off
        String query = """
                {"query": {"term": {"document.type": "ip"}}}
                """;
        // spotless:on
        JsonNode searchResult = this.searchIndex(IOC_INDEX, query);
        long totalHits = searchResult.path("hits").path("total").path("value").asLong(0);
        assertTrue("Should find the ip IOC document", totalHits > 0);

        // Verify hash summary document exists and is distinct from IOC documents
        JsonNode hashDoc =
                this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_doc/" + HASH_DOC_ID));
        assertTrue("Hash summary document should exist", hashDoc.path("found").asBoolean());
        assertFalse(
                "Hash summary document should not have a 'document' field",
                hashDoc.path("_source").has("document"));
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

        String hash1 = "1111111111111111111111111111111111111111111111111111111111111111";
        String hash2 = "2222222222222222222222222222222222222222222222222222222222222222";

        // Index initial hash summary
        this.indexHashSummaryDocument(hash1, hash1, hash1, hash1, hash1);

        // Overwrite with new hashes
        this.indexHashSummaryDocument(hash2, hash2, hash2, hash2, hash2);

        // Verify the document was updated
        JsonNode result =
                this.responseAsJson(this.makeRequest("GET", IOC_INDEX + "/_doc/" + HASH_DOC_ID));
        JsonNode source = result.path("_source");

        for (String type : Constants.IOC_TYPES) {
            String actual = source.path(type).path("hash").path("sha256").asText("");
            assertEquals("Hash for type '" + type + "' should be the updated value", hash2, actual);
        }
    }

    /** Tests that the hash summary document is not returned by type-filtered queries. */
    public void testHashSummaryExcludedFromTypeQueries() throws IOException {
        this.recreateIocIndexWithStrictMapping();

        // Index an IOC document and the hash summary
        this.indexIocDocument("ioc-ip-1", "ip");
        String hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        this.indexHashSummaryDocument(hash, hash, hash, hash, hash);

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
