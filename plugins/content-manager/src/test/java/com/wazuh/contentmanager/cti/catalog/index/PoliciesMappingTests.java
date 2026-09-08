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
package com.wazuh.contentmanager.cti.catalog.index;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.test.OpenSearchTestCase;

import java.io.InputStream;

import com.wazuh.contentmanager.utils.Constants;

/** Unit tests for the policies index mapping, which also hosts the user-overrides registry. */
public class PoliciesMappingTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonNode policiesMapping() throws Exception {
        try (InputStream stream =
                PoliciesMappingTests.class.getResourceAsStream(Constants.MAPPING_POLICIES)) {
            assertNotNull("mapping resource " + Constants.MAPPING_POLICIES + " not found", stream);
            return MAPPER.readTree(stream);
        }
    }

    /**
     * The registry subtree must be declared with indexing disabled.
     *
     * <p>This mapping is {@code dynamic: "true"}, so an undeclared subtree would auto-map every field
     * of every stored filter into the policies index. Two filters whose documents disagree on a
     * field's type would then make the write fail outright.
     */
    public void testUserOverridesSubtreeIsNotIndexed() throws Exception {
        JsonNode subtree = policiesMapping().path("properties").path(Constants.KEY_USER_OVERRIDES);

        assertFalse("user_overrides must be declared", subtree.isMissingNode());
        assertEquals("object", subtree.path("type").asText());
        assertFalse(
                "user_overrides must not be indexed, or stored filters would pollute this mapping",
                subtree.path("enabled").asBoolean(true));
    }

    /**
     * The registry is a sibling of {@code space}, not nested inside {@code document}, so that the
     * document-level hash and the space-scoped queries never see it.
     */
    public void testUserOverridesIsATopLevelField() throws Exception {
        JsonNode properties = policiesMapping().path("properties");

        assertTrue(properties.has(Constants.KEY_USER_OVERRIDES));
        assertFalse(
                "user_overrides must not live under 'document'",
                properties
                        .path(Constants.KEY_DOCUMENT)
                        .path("properties")
                        .has(Constants.KEY_USER_OVERRIDES));
    }

    /**
     * The policy's {@code filters} array holds plain document ids. The apply step appends restored
     * filter ids to it as strings, so a change to this type would silently break that.
     */
    public void testPolicyFiltersHoldKeywordIds() throws Exception {
        JsonNode filters =
                policiesMapping()
                        .path("properties")
                        .path(Constants.KEY_DOCUMENT)
                        .path("properties")
                        .path(Constants.KEY_FILTERS);

        assertEquals("keyword", filters.path("type").asText());
    }
}
