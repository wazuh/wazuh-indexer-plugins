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
import java.util.List;
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

    /** Makes the mocked service answer the given resource ids for any space. */
    @SuppressWarnings("unchecked")
    private void stubResources(Map<String, List<String>> resources) {
        doAnswer(
                        invocation -> {
                            ActionListener<Map<String, List<String>>> listener = invocation.getArgument(2);
                            listener.onResponse(resources);
                            return null;
                        })
                .when(this.spaceService)
                .getSpaceResourceIdsAsync(anyString(), anyList(), any(ActionListener.class));
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
        Map<String, List<String>> resources = new HashMap<>();
        resources.put(Constants.KEY_DECODERS, List.of());
        resources.put(Constants.KEY_FILTERS, List.of());
        resources.put(Constants.KEY_KVDBS, List.of());
        resources.put(Constants.KEY_RULES, List.of());
        stubResources(resources);

        GetPolicyResourcesResponse response = execute("test");

        // The requested space must be the one queried, not a hardcoded one.
        verify(this.spaceService).getSpaceResourceIdsAsync(eq("test"), anyList(), any());
        Assert.assertEquals(RestStatus.OK, response.getStatus());
        String json = toJson(response);
        Assert.assertTrue(
                json.contains("\"normalization\":{\"decoders\":[],\"filters\":[],\"kvdbs\":[]}"));
        Assert.assertTrue(json.contains("\"detection\":{\"rules\":[]}"));
        Assert.assertTrue(json.contains("\"status\":200"));
    }

    /** A space holding only kvdbs and filters lists them under normalization. */
    public void testDoExecute_spaceWithOnlyKvdbsAndFilters() {
        Map<String, List<String>> resources = new HashMap<>();
        resources.put(Constants.KEY_DECODERS, List.of());
        resources.put(Constants.KEY_FILTERS, List.of("filter-1"));
        resources.put(Constants.KEY_KVDBS, List.of("kvdb-1"));
        resources.put(Constants.KEY_RULES, List.of());
        stubResources(resources);

        GetPolicyResourcesResponse response = execute("test");

        Assert.assertEquals(RestStatus.OK, response.getStatus());
        String json = toJson(response);
        Assert.assertTrue(json.contains("\"decoders\":[]"));
        Assert.assertTrue(json.contains("\"filters\":[\"filter-1\"]"));
        Assert.assertTrue(json.contains("\"kvdbs\":[\"kvdb-1\"]"));
        Assert.assertTrue(json.contains("\"rules\":[]"));
    }

    /** The ids the service returns are passed through to the response, per type. */
    public void testDoExecute_passesResourceIdsThrough() {
        Map<String, List<String>> resources = new HashMap<>();
        resources.put(Constants.KEY_DECODERS, List.of("d-a", "d-b"));
        resources.put(Constants.KEY_FILTERS, List.of());
        resources.put(Constants.KEY_KVDBS, List.of());
        resources.put(Constants.KEY_RULES, List.of());
        stubResources(resources);

        GetPolicyResourcesResponse response = execute("custom");

        verify(this.spaceService).getSpaceResourceIdsAsync(eq("custom"), anyList(), any());
        Assert.assertEquals(RestStatus.OK, response.getStatus());
        String json = toJson(response);
        Assert.assertTrue(json.contains("\"decoders\":[\"d-a\",\"d-b\"]"));
        Assert.assertTrue(json.contains("\"filters\":[]"));
        Assert.assertTrue(json.contains("\"kvdbs\":[]"));
        Assert.assertTrue(json.contains("\"rules\":[]"));
    }

    /**
     * A failure reading a resource index is reported as a failure, never masked as a 200 with empty
     * lists.
     */
    @SuppressWarnings("unchecked")
    public void testDoExecute_readFailureIsNotReportedAsEmpty() {
        RuntimeException boom = new RuntimeException("search failed");
        doAnswer(
                        invocation -> {
                            ActionListener<Map<String, List<String>>> listener = invocation.getArgument(2);
                            listener.onFailure(boom);
                            return null;
                        })
                .when(this.spaceService)
                .getSpaceResourceIdsAsync(anyString(), anyList(), any(ActionListener.class));

        ActionListener<GetPolicyResourcesResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), new GetPolicyResourcesRequest("test"), listener);

        verify(listener).onFailure(boom);
        verify(listener, never()).onResponse(any());
    }

    /** A missing space is rejected with 400. */
    public void testDoExecute_missingSpace() {
        GetPolicyResourcesResponse response = execute(null);
        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(response.getMessage().contains(Constants.KEY_SPACE));
        verify(this.spaceService, never()).getSpaceResourceIdsAsync(anyString(), anyList(), any());
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
        verify(this.spaceService, never()).getSpaceResourceIdsAsync(anyString(), anyList(), any());
    }

    /** The standard space is not supported and is rejected with 400. */
    public void testDoExecute_standardSpaceUnsupported() {
        GetPolicyResourcesResponse response = execute("standard");
        Assert.assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        Assert.assertTrue(
                response.getMessage().toLowerCase(java.util.Locale.ROOT).contains("standard"));
        verify(this.spaceService, never()).getSpaceResourceIdsAsync(anyString(), anyList(), any());
    }
}
