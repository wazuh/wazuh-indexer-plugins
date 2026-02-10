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
package com.wazuh.contentmanager.rest.services;

import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.Before;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** Unit tests for the {@link RestGetPromoteAction} class. */
public class RestGetPromoteActionTests extends OpenSearchTestCase {

    private RestGetPromoteAction action;
    private SpaceService spaceService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.spaceService = mock(SpaceService.class);
        this.action = new RestGetPromoteAction(this.spaceService);
    }

    /**
     * Test successful promotion preview from "draft" to "test".
     *
     * <p>This test validates the difference calculation logic for Decoders:
     *
     * <ul>
     *   <li><b>UPDATE:</b> ID "2" exists in both spaces but with different hashes.
     *   <li><b>ADD:</b> ID "3" exists in "draft" (source) but not in "test" (target).
     *   <li><b>REMOVE:</b> ID "4" exists in "test" (target) but not in "draft" (source).
     *   <li><b>NO-OP:</b> ID "1" exists in both with the same hash (should be ignored).
     * </ul>
     *
     * @throws IOException if parsing the response fails.
     */
    public void testGetPromote200_Draft() throws IOException {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("space", "draft"))
                        .build();

        // Mock
        Map<String, String> sourceDecoders = new HashMap<>();
        sourceDecoders.put("1", "hashA"); // Same
        sourceDecoders.put("2", "hashB"); // Update
        sourceDecoders.put("3", "hashC"); // Add

        Map<String, String> targetDecoders = new HashMap<>();
        targetDecoders.put("1", "hashA"); // Same
        targetDecoders.put("2", "hashModified"); // Update
        targetDecoders.put("4", "hashD"); // Remove

        Map<String, Map<String, String>> sourceResources = new HashMap<>();
        sourceResources.put("decoders", sourceDecoders);
        sourceResources.put("filters", Collections.emptyMap());
        sourceResources.put("integrations", Collections.emptyMap());

        Map<String, Map<String, String>> targetResources = new HashMap<>();
        targetResources.put("decoders", targetDecoders);
        targetResources.put("filters", Collections.emptyMap());
        targetResources.put("integrations", Collections.emptyMap());

        when(this.spaceService.getSpaceResources("draft")).thenReturn(sourceResources);
        when(this.spaceService.getSpaceResources("test")).thenReturn(targetResources);

        // Act
        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.OK, response.status());

        // Parse Response Body
        Map<String, Object> map =
                XContentHelper.convertToMap(response.content(), false, XContentType.JSON).v2();
        assertTrue(map.containsKey("changes"));
        Map<String, Object> changes = (Map<String, Object>) map.get("changes");

        assertTrue(changes.containsKey("decoders"));
        List<Map<String, Object>> decoders = (List<Map<String, Object>>) changes.get("decoders");

        // Helper to find item by ID
        Map<String, Object> id2 = this.findItem(decoders, "2");
        Map<String, Object> id3 = this.findItem(decoders, "3");
        Map<String, Object> id4 = this.findItem(decoders, "4");
        Map<String, Object> id1 = this.findItem(decoders, "1");

        assertNotNull("ID 2 should be present", id2);
        assertEquals("update", id2.get("operation"));

        assertNotNull("ID 3 should be present", id3);
        assertEquals("add", id3.get("operation"));

        assertNotNull("ID 4 should be present", id4);
        assertEquals("remove", id4.get("operation"));

        assertNull("ID 1 should NOT be present (no change)", id1);

        verify(this.spaceService).getSpaceResources("draft");
        verify(this.spaceService).getSpaceResources("test");
    }

    /**
     * Test successful promotion preview from "test" to "custom".
     *
     * <p>This test verifies that resources (specifically filters/rules) are correctly identified for
     * addition when they exist in the source space but are missing from the target.
     *
     * @throws IOException if parsing the response fails.
     */
    public void testGetPromote200_Test() throws IOException {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("space", "test"))
                        .build();

        // Mock
        Map<String, String> sourceFilters = Map.of("rule-1", "hashXYZ");
        Map<String, String> targetFilters = Collections.emptyMap(); // Target empty -> ADD

        Map<String, Map<String, String>> sourceResources = new HashMap<>();
        sourceResources.put("filters", sourceFilters);

        Map<String, Map<String, String>> targetResources = new HashMap<>();
        targetResources.put("filters", targetFilters);

        when(this.spaceService.getSpaceResources("test")).thenReturn(sourceResources);
        when(this.spaceService.getSpaceResources("custom")).thenReturn(targetResources);

        // Act
        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.OK, response.status());

        Map<String, Object> map =
                XContentHelper.convertToMap(response.content(), false, XContentType.JSON).v2();
        Map<String, Object> changes = (Map<String, Object>) map.get("changes");

        assertTrue(changes.containsKey("filters"));
        List<Map<String, Object>> filters = (List<Map<String, Object>>) changes.get("filters");

        Map<String, Object> item = this.findItem(filters, "rule-1");
        assertNotNull("rule-1 should be present", item);
        assertEquals("add", item.get("operation"));

        verify(this.spaceService).getSpaceResources("test");
        verify(this.spaceService).getSpaceResources("custom");
    }

    /**
     * * Helper utility to search for an item in a list of maps by its "id" field. * @param list The
     * list of change objects.
     *
     * @param id The ID to search for.
     * @return The map containing the item if found, null otherwise.
     */
    private Map<String, Object> findItem(List<Map<String, Object>> list, String id) {
        if (list == null) return null;
        for (Map<String, Object> item : list) {
            if (id.equals(item.get("id"))) {
                return item;
            }
        }
        return null;
    }

    /**
     * Test validation failure when the required 'space' parameter is missing. Expected outcome: 400
     * Bad Request.
     */
    public void testGetPromote400_MissingSpace() {
        RestRequest request = new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY).build();

        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(response.content().utf8ToString().contains("Missing required parameter"));
    }

    /**
     * Test validation failure when the 'space' parameter is empty. Expected outcome: 400 Bad Request.
     */
    public void testGetPromote400_EmptySpace() {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("space", ""))
                        .build();

        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        assertEquals(RestStatus.BAD_REQUEST, response.status());
    }

    /**
     * Test validation failure when the 'space' parameter contains an invalid value (e.g. 'prod').
     * Expected outcome: 400 Bad Request.
     */
    public void testGetPromote400_InvalidSpace() {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("space", "prod"))
                        .build();

        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(response.content().utf8ToString().contains("Unknown space"));
    }

    /**
     * Test validation failure when trying to promote from a space that has no subsequent target
     * (e.g., 'custom'). Expected outcome: 400 Bad Request.
     */
    public void testGetPromote400_NoPromotionTarget() {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("space", "custom"))
                        .build();

        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(response.content().utf8ToString().contains("cannot be promoted"));
    }

    /**
     * Test internal server error handling when the backend service throws an exception. Expected
     * outcome: 500 Internal Server Error.
     */
    public void testGetPromote500() {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("space", "draft"))
                        .build();

        // Simulate service failure
        when(this.spaceService.getSpaceResources(anyString()))
                .thenThrow(new RuntimeException("Service Error"));

        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }

    /**
     * Test that the response body contains only plural resource keys (no singular duplicates).
     *
     * <p>This test ensures the changes body does not contain duplicate keys like "decoder" alongside
     * "decoders", "rule" alongside "rules", etc. Only the plural forms should be present.
     *
     * @throws IOException if parsing the response fails.
     */
    @SuppressWarnings("unchecked")
    public void testGetPromote200_ResponseContainsOnlyPluralKeys() throws IOException {
        RestRequest request =
                new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                        .withParams(Map.of("space", "draft"))
                        .build();

        // Mock all resource types to ensure comprehensive coverage (excluding policy to simplify)
        Map<String, Map<String, String>> sourceResources = new HashMap<>();
        sourceResources.put("decoders", Collections.emptyMap());
        sourceResources.put("rules", Collections.emptyMap());
        sourceResources.put("kvdbs", Collections.emptyMap());
        sourceResources.put("integrations", Collections.emptyMap());
        sourceResources.put("filters", Collections.emptyMap());

        Map<String, Map<String, String>> targetResources = new HashMap<>();
        targetResources.put("decoders", Collections.emptyMap());
        targetResources.put("rules", Collections.emptyMap());
        targetResources.put("kvdbs", Collections.emptyMap());
        targetResources.put("integrations", Collections.emptyMap());
        targetResources.put("filters", Collections.emptyMap());

        when(this.spaceService.getSpaceResources("draft")).thenReturn(sourceResources);
        when(this.spaceService.getSpaceResources("test")).thenReturn(targetResources);

        // Act
        RestResponse restResponse = this.action.handleRequest(request);
        BytesRestResponse response = restResponse.toBytesRestResponse();

        // Assert
        assertEquals(RestStatus.OK, response.status());

        Map<String, Object> map =
                XContentHelper.convertToMap(response.content(), false, XContentType.JSON).v2();
        assertTrue(map.containsKey("changes"));
        Map<String, Object> changes = (Map<String, Object>) map.get("changes");

        // Define allowed keys (plural forms only)
        Set<String> allowedKeys =
                Set.of("decoders", "rules", "kvdbs", "integrations", "filters", "policy");

        // Define forbidden singular keys that should NOT be present
        Set<String> forbiddenKeys = Set.of("decoder", "rule", "kvdb", "integration");

        // Verify no forbidden singular keys are present
        for (String forbiddenKey : forbiddenKeys) {
            assertFalse(
                    "Response should not contain singular key '" + forbiddenKey + "'",
                    changes.containsKey(forbiddenKey));
        }

        // Verify all keys in response are from the allowed set
        for (String key : changes.keySet()) {
            assertTrue(
                    "Unexpected key '" + key + "' in changes body. Allowed keys: " + allowedKeys,
                    allowedKeys.contains(key));
        }
    }
}
