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

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.action.GetPolicyResourcesRequest;
import com.wazuh.contentmanager.action.GetPolicyResourcesResponse;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.Mockito.*;

public class TransportGetPolicyResourcesActionTests extends OpenSearchTestCase {
    private SpaceService spaceService;
    private TransportGetPolicyResourcesAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.spaceService = mock(SpaceService.class);
        this.action =
                new TransportGetPolicyResourcesAction(
                        mock(TransportService.class), mock(ActionFilters.class), this.spaceService);
    }

    private static String toJson(GetPolicyResourcesResponse response) {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            response.toXContent(builder, ToXContent.EMPTY_PARAMS);
            return BytesReference.bytes(builder).utf8ToString();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    /** Makes the mocked service answer the given resources for any space. */
    @SuppressWarnings("unchecked")
    private void stubResources(Map<String, Map<String, String>> resources) {
        doAnswer(
                        invocation -> {
                            ActionListener<Map<String, Map<String, String>>> listener = invocation.getArgument(1);
                            listener.onResponse(resources);
                            return null;
                        })
                .when(this.spaceService)
                .getSpaceResourcesAsync(anyString(), any(ActionListener.class));
    }

    private static Map<String, String> idToHash(String... ids) {
        Map<String, String> map = new HashMap<>();
        for (String id : ids) {
            map.put(id, "hash-" + id);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private GetPolicyResourcesResponse execute(String space) {
        ActionListener<GetPolicyResourcesResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), new GetPolicyResourcesRequest(space), listener);
        org.mockito.ArgumentCaptor<GetPolicyResourcesResponse> captor =
                org.mockito.ArgumentCaptor.forClass(GetPolicyResourcesResponse.class);
        verify(listener).onResponse(captor.capture());
        return captor.getValue();
    }

    /** An engine-empty space returns 200 with every resource list empty. */
    public void testDoExecute_emptySpace() {
        Map<String, Map<String, String>> resources = new HashMap<>();
        resources.put(Constants.KEY_DECODERS, new HashMap<>());
        resources.put(Constants.KEY_FILTERS, new HashMap<>());
        resources.put(Constants.KEY_KVDBS, new HashMap<>());
        resources.put(Constants.KEY_RULES, new HashMap<>());
        stubResources(resources);

        GetPolicyResourcesResponse response = execute("test");

        // The requested space must be the one queried, not a hardcoded one.
        verify(this.spaceService).getSpaceResourcesAsync(eq("test"), any());
        Assert.assertEquals(RestStatus.OK, response.getStatus());
        String json = toJson(response);
        Assert.assertTrue(
                json.contains("\"normalization\":{\"decoders\":[],\"filters\":[],\"kvdbs\":[]}"));
        Assert.assertTrue(json.contains("\"detection\":{\"rules\":[]}"));
        Assert.assertTrue(json.contains("\"status\":200"));
    }

    /** A space holding only kvdbs and filters lists them under normalization. */
    public void testDoExecute_spaceWithOnlyKvdbsAndFilters() {
        Map<String, Map<String, String>> resources = new HashMap<>();
        resources.put(Constants.KEY_DECODERS, new HashMap<>());
        resources.put(Constants.KEY_FILTERS, idToHash("filter-1"));
        resources.put(Constants.KEY_KVDBS, idToHash("kvdb-1"));
        resources.put(Constants.KEY_RULES, new HashMap<>());
        stubResources(resources);

        GetPolicyResourcesResponse response = execute("test");

        Assert.assertEquals(RestStatus.OK, response.getStatus());
        String json = toJson(response);
        Assert.assertTrue(json.contains("\"decoders\":[]"));
        Assert.assertTrue(json.contains("\"filters\":[\"filter-1\"]"));
        Assert.assertTrue(json.contains("\"kvdbs\":[\"kvdb-1\"]"));
        Assert.assertTrue(json.contains("\"rules\":[]"));
    }

    /** Ids are listed sorted, and a missing resource-type key yields an empty list. */
    public void testDoExecute_sortsIdsAndToleratesMissingTypes() {
        Map<String, Map<String, String>> resources = new HashMap<>();
        resources.put(Constants.KEY_DECODERS, idToHash("d-b", "d-a"));
        // filters, kvdbs and rules keys intentionally absent
        stubResources(resources);

        GetPolicyResourcesResponse response = execute("custom");

        verify(this.spaceService).getSpaceResourcesAsync(eq("custom"), any());
        Assert.assertEquals(RestStatus.OK, response.getStatus());
        String json = toJson(response);
        Assert.assertTrue(json.contains("\"decoders\":[\"d-a\",\"d-b\"]"));
        Assert.assertTrue(json.contains("\"filters\":[]"));
        Assert.assertTrue(json.contains("\"kvdbs\":[]"));
        Assert.assertTrue(json.contains("\"rules\":[]"));
    }

    /** A missing space is rejected with 400. */
    public void testDoExecute_missingSpace() {
        GetPolicyResourcesResponse response = execute(null);
        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.KEY_SPACE));
        verify(this.spaceService, never()).getSpaceResourcesAsync(anyString(), any());
    }

    /** A blank space is rejected with 400. */
    public void testDoExecute_blankSpace() {
        GetPolicyResourcesResponse response = execute("  ");
        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
    }

    /** An unknown space is rejected with 400. */
    public void testDoExecute_unknownSpace() {
        GetPolicyResourcesResponse response = execute("bogus");
        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        verify(this.spaceService, never()).getSpaceResourcesAsync(anyString(), any());
    }

    /** The standard space is not supported and is rejected with 400. */
    public void testDoExecute_standardSpaceUnsupported() {
        GetPolicyResourcesResponse response = execute("standard");
        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(
                response.getMessage().toLowerCase(java.util.Locale.ROOT).contains("standard"));
        verify(this.spaceService, never()).getSpaceResourcesAsync(anyString(), any());
    }
}
