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

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequestBuilder;
import org.opensearch.action.admin.indices.get.GetIndexResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Answers;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IndexSwapHelper}. Validates shadow name resolution, covering both the
 * normal case (alias → -a → shadow is -b and vice versa) and error cases (unrecognized suffix,
 * multiple concrete indices).
 */
public class IndexSwapHelperTests extends OpenSearchTestCase {

    private Client client;
    private AutoCloseable closeable;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        PluginSettings.getInstance(Settings.EMPTY);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** When the alias points to suffix -a, the shadow name should be suffix -b. */
    public void testResolveShadowName_AToB() {
        String alias = "wazuh-threatintel-rules";
        String livePhysical = alias + ContentIndex.SUFFIX_A;

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {livePhysical});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        String shadow = IndexSwapHelper.resolveShadowName(this.client, alias);
        assertEquals(alias + ContentIndex.SUFFIX_B, shadow);
    }

    /** When the alias points to suffix -b, the shadow name should be suffix -a. */
    public void testResolveShadowName_BToA() {
        String alias = "wazuh-threatintel-rules";
        String livePhysical = alias + ContentIndex.SUFFIX_B;

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {livePhysical});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        String shadow = IndexSwapHelper.resolveShadowName(this.client, alias);
        assertEquals(alias + ContentIndex.SUFFIX_A, shadow);
    }

    /** When the alias resolves to multiple indices, an IllegalStateException must be thrown. */
    public void testResolveShadowName_MultipleIndices() {
        String alias = "wazuh-threatintel-rules";

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices())
                .thenReturn(new String[] {alias + ContentIndex.SUFFIX_A, alias + ContentIndex.SUFFIX_B});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        expectThrows(
                IllegalStateException.class, () -> IndexSwapHelper.resolveShadowName(this.client, alias));
    }

    /** When the physical index does not end with -a or -b, an IllegalStateException is thrown. */
    public void testResolveShadowName_UnrecognizedSuffix() {
        String alias = "wazuh-threatintel-rules";

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {alias});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        expectThrows(
                IllegalStateException.class, () -> IndexSwapHelper.resolveShadowName(this.client, alias));
    }

    /** resolveLivePhysicalName should return the concrete index the alias points to. */
    public void testResolveLivePhysicalName() {
        String alias = "wazuh-threatintel-rules";
        String livePhysical = alias + ContentIndex.SUFFIX_A;

        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {livePhysical});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);

        String result = IndexSwapHelper.resolveLivePhysicalName(this.client, alias);
        assertEquals(livePhysical, result);
    }

    /**
     * A leftover in the staging slot, which the alias does not point at, is deleted before the shadow
     * index is created; otherwise the creation fails with resource_already_exists.
     */
    @SuppressWarnings("unchecked")
    public void testCreateShadowIndices_DeletesLeftoverInStagingSlot() throws Exception {
        String alias = "wazuh-threatintel-rules";
        GetIndexResponse response = mock(GetIndexResponse.class);
        when(response.getIndices()).thenReturn(new String[] {alias + ContentIndex.SUFFIX_B});
        when(this.client.admin().indices().prepareGetIndex().setIndices(alias).get())
                .thenReturn(response);
        when(this.client
                        .admin()
                        .indices()
                        .prepareExists(alias + ContentIndex.SUFFIX_A)
                        .get()
                        .isExists())
                .thenReturn(true);
        when(this.client.admin().indices().prepareDelete(anyString()))
                .thenReturn(mock(DeleteIndexRequestBuilder.class));
        CreateIndexResponse created =
                new CreateIndexResponse(true, true, alias + ContentIndex.SUFFIX_A);
        ActionFuture<CreateIndexResponse> future = mock(ActionFuture.class);
        when(future.get(anyLong(), any(TimeUnit.class))).thenReturn(created);
        when(this.client.admin().indices().create(any(CreateIndexRequest.class))).thenReturn(future);

        Map<String, ContentIndex> shadows =
                IndexSwapHelper.createShadowIndices(
                        this.client, Map.of("rule", "/mappings/cti-rules-mappings.json"), t -> alias);

        verify(this.client.admin().indices()).prepareDelete(alias + ContentIndex.SUFFIX_A);
        assertEquals(alias + ContentIndex.SUFFIX_A, shadows.get("rule").getPhysicalName());
    }
}
