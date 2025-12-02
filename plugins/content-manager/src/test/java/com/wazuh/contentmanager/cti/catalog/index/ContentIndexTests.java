/*
 * Copyright (C) 2024, Wazuh Inc.
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

import com.google.gson.JsonObject;
import org.opensearch.action.get.GetResponse;
import org.opensearch.transport.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Changes;
import com.wazuh.contentmanager.cti.catalog.model.Offset;
import com.wazuh.contentmanager.cti.catalog.model.Operation;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentIndexTests extends OpenSearchIntegTestCase {
    private ContentIndex contentUpdaterSpy;

    @Mock private Environment mockEnvironment;
    @Mock private ClusterService mockClusterService;
    @InjectMocks private PluginSettings pluginSettings;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    public void setup() throws Exception {
        super.setUp();

        Settings settings =
                Settings.builder()
                        .put("content_manager.max_concurrent_bulks", 5)
                        .put("content_manager.max_items_per_bulk", 25)
                        .put("content_manager.client.timeout", "10")
                        .build();

        this.mockEnvironment = mock(Environment.class);
        when(this.mockEnvironment.settings()).thenReturn(settings);
        this.pluginSettings =
                PluginSettings.getInstance(this.mockEnvironment.settings(), this.mockClusterService);

        Client client = mock(Client.class);
        ContentIndex contentIndex = new ContentIndex(client, this.pluginSettings);
        this.contentUpdaterSpy = Mockito.spy(contentIndex);
    }

    /** Test the {@link ContentIndex#patch} method with an Offset with Create content type. */
    public void testPatchCreate() throws Exception {
        // Mock
        doNothing().when(this.contentUpdaterSpy).index((Offset) any());
        // Arrange
        Offset offset = new Offset("test", 1L, "test", Offset.Type.CREATE, 1L, null, null);
        // Act
        this.contentUpdaterSpy.patch(new Changes(List.of(offset)));
        // Assert
        verify(this.contentUpdaterSpy, times(1)).patch(any());
    }

    /** Test the {@link ContentIndex#patch} method with an Offset with Update content type. */
    public void testPatchUpdate() throws Exception {
        // Mock a GetResponse that returns a valid existing document
        GetResponse mockResponse = mock(GetResponse.class);
        when(mockResponse.isExists()).thenReturn(true);
        // Mock JsonObject
        JsonObject json = new JsonObject();
        json.addProperty("field", "value");
        doReturn(json).when(this.contentUpdaterSpy).getById(any());
        // Mock index() to avoid actual client call
        doNothing().when(this.contentUpdaterSpy).index((Offset) any());
        // Arrange
        Offset offset =
                new Offset(
                        "test",
                        1L,
                        "test",
                        Offset.Type.UPDATE,
                        1L,
                        List.of(new Operation("replace", "/field", null, "new_value")),
                        null);
        // Act
        this.contentUpdaterSpy.patch(new Changes(List.of(offset)));
        // Assert
        verify(this.contentUpdaterSpy, times(1)).index((Offset) any());
    }

    /** Test the {@link ContentIndex#patch} method with an Offset with Delete content type. */
    public void testPatchDelete() {
        // Mock a GetResponse that returns a valid existing document
        GetResponse mockResponse = mock(GetResponse.class);
        when(mockResponse.isExists()).thenReturn(true);
        // Mock this.delete() to avoid actual client call
        doNothing().when(this.contentUpdaterSpy).delete(any());
        // Arrange
        Offset offset = new Offset("test", 1L, "test", Offset.Type.DELETE, 1L, null, null);
        // Act
        this.contentUpdaterSpy.patch(new Changes(List.of(offset)));
        // Assert
        verify(this.contentUpdaterSpy, times(1)).delete(any());
    }
}
