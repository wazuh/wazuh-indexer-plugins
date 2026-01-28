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

import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.service.SpaceService;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** Unit tests for the {@link RestGetPromotePreviewAction} class. */
public class RestGetPromotePreviewActionTests extends OpenSearchTestCase {

    private RestGetPromotePreviewAction action;
    private Client client;
    private SpaceService spaceService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.spaceService = mock(SpaceService.class);
        this.action = new RestGetPromotePreviewAction(this.spaceService);
    }

    /**
     * Test successful preview generation for "draft" space (Draft -> Test).
     *
     * <p>Scenarios covered:
     *
     * <ul>
     *   <li><b>ADD:</b> ID '3' is in Draft but not in Test.
     *   <li><b>UPDATE:</b> ID '2' is in both, but hashes differ.
     *   <li><b>REMOVE:</b> ID '4' is in Test but not in Draft.
     *   <li><b>NO OP:</b> ID '1' is in both with same hash (should not appear in output).
     * </ul>
     */
    public void testGetPromotePreview200_Draft() throws IOException {
        RestRequest request = mock(RestRequest.class);
        when(request.param("space")).thenReturn("draft");

        // 1. Prepare Mock Data for Source (Draft) and Target (Test)
        // We will simulate these changes specifically for the "decoders" type
        Map<String, String> sourceDecoders = new HashMap<>();
        sourceDecoders.put("1", "hashA"); // Same
        sourceDecoders.put("2", "hashB"); // Update
        sourceDecoders.put("3", "hashC"); // Add

        Map<String, String> targetDecoders = new HashMap<>();
        targetDecoders.put("1", "hashA"); // Same
        targetDecoders.put("2", "hashModified"); // Update
        targetDecoders.put("4", "hashD"); // Remove

        // Build the full map structure required by SpaceService
        Map<String, Map<String, String>> sourceResources = new HashMap<>();
        sourceResources.put("decoders", sourceDecoders);
        // Ensure other types are present but empty to avoid NPEs if logic assumes existence
        sourceResources.put("filters", Collections.emptyMap());
        sourceResources.put("integrations", Collections.emptyMap());

        Map<String, Map<String, String>> targetResources = new HashMap<>();
        targetResources.put("decoders", targetDecoders);
        targetResources.put("filters", Collections.emptyMap());
        targetResources.put("integrations", Collections.emptyMap());

        // 2. Mock Service calls
        when(this.spaceService.getSpaceResources("draft")).thenReturn(sourceResources);
        when(this.spaceService.getSpaceResources("test")).thenReturn(targetResources);

        // 3. Execute
        BytesRestResponse response = this.action.handleRequest(request);

        // 4. Verify
        assertEquals(RestStatus.OK, response.status());
        String content = response.content().utf8ToString();

        // Check Structure
        assertTrue("Response should contain changes object", content.contains("\"changes\":"));
        assertTrue("Response should contain decoders array", content.contains("\"decoders\":["));

        // Check Operations logic
        // ID 2 -> Update (Hashes differ)
        assertTrue(
                "ID 2 should be updated",
                content.matches(".*\\{\"operation\":\"update\",\"id\":\"2\"\\}.*"));

        // ID 3 -> Add (In Source, not Target)
        assertTrue(
                "ID 3 should be added", content.matches(".*\\{\"operation\":\"add\",\"id\":\"3\"\\}.*"));

        // ID 4 -> Remove (In Target, not Source)
        // Note: The action maps OP_REMOVE_VAL to "remove"
        assertTrue(
                "ID 4 should be removed",
                content.matches(".*\\{\"operation\":\"remove\",\"id\":\"4\"\\}.*"));

        // ID 1 -> No Change (Should not be in the list)
        assertFalse(
                "ID 1 should not be present", content.matches(".*\\{\"operation\":.*,\"id\":\"1\"\\}.*"));

        // Verify service interaction
        verify(this.spaceService).getSpaceResources("draft");
        verify(this.spaceService).getSpaceResources("test");
    }

    /**
     * Test successful preview generation for "test" space (Test -> Custom). Verify that 'filters'
     * (rules) are processed correctly.
     */
    public void testGetPromotePreview200_Test() throws IOException {
        RestRequest request = mock(RestRequest.class);
        when(request.param("space")).thenReturn("test");

        // Mock data for Filters/Rules
        Map<String, String> sourceFilters = Map.of("rule-1", "hashXYZ");
        Map<String, String> targetFilters = Collections.emptyMap(); // Target empty -> ADD

        Map<String, Map<String, String>> sourceResources = new HashMap<>();
        sourceResources.put("filters", sourceFilters);

        Map<String, Map<String, String>> targetResources = new HashMap<>();
        targetResources.put("filters", targetFilters);

        when(this.spaceService.getSpaceResources("test")).thenReturn(sourceResources);
        when(this.spaceService.getSpaceResources("custom")).thenReturn(targetResources);

        BytesRestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.OK, response.status());
        String content = response.content().utf8ToString();

        // Verify filters are present and operation is ADD
        assertTrue(content.contains("\"filters\":["));
        assertTrue(content.matches(".*\\{\"operation\":\"add\",\"id\":\"rule-1\"\\}.*"));

        verify(this.spaceService).getSpaceResources("test");
        verify(this.spaceService).getSpaceResources("custom");
    }

    /** Test validation failure when space param is missing (400 Bad Request). */
    public void testGetPromotePreview400_MissingSpace() {
        RestRequest request = mock(RestRequest.class);
        when(request.param("space")).thenReturn(null);

        BytesRestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(response.content().utf8ToString().contains("Missing required parameter"));
    }

    /** Test validation failure when space param is empty (400 Bad Request). */
    public void testGetPromotePreview400_EmptySpace() {
        RestRequest request = mock(RestRequest.class);
        when(request.param("space")).thenReturn("");

        BytesRestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST, response.status());
    }

    /** Test validation failure when space param is invalid (e.g. 'prod') (400 Bad Request). */
    public void testGetPromotePreview400_InvalidSpace() {
        RestRequest request = mock(RestRequest.class);
        when(request.param("space")).thenReturn("prod"); // Valid are 'draft' or 'test'

        BytesRestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.BAD_REQUEST, response.status());
        assertTrue(response.content().utf8ToString().contains("Invalid space parameter"));
    }

    /** Test internal server error handling. */
    public void testGetPromotePreview500() {
        RestRequest request = mock(RestRequest.class);
        when(request.param("space")).thenReturn("draft");

        // Simulate service failure
        when(this.spaceService.getSpaceResources(anyString()))
                .thenThrow(new RuntimeException("Service Error"));

        BytesRestResponse response = this.action.handleRequest(request);

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }
}
