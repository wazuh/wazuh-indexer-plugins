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
package com.wazuh.contentmanager.index;

import com.google.gson.JsonObject;
import org.opensearch.action.get.GetResponse;
import org.opensearch.client.Client;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.List;

import com.wazuh.contentmanager.model.ctiapi.ContentChanges;
import com.wazuh.contentmanager.model.ctiapi.Offset;
import com.wazuh.contentmanager.model.ctiapi.OperationType;
import com.wazuh.contentmanager.model.ctiapi.PatchOperation;
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

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    public void setup() throws Exception {
        super.setUp();
        Client client = mock(Client.class);
        ContentIndex contentIndex = new ContentIndex(client);
        this.contentUpdaterSpy = Mockito.spy(contentIndex);
    }

    /** Test the {@link ContentIndex#patch} method with an Offset with Create content type. */
    public void testPatchCreate() {
        // Mock
        doNothing().when(this.contentUpdaterSpy).index((Offset) any());
        // Arrange
        Offset offset = new Offset("test", 1L, "test", OperationType.CREATE, 1L, null, null);
        // Act
        this.contentUpdaterSpy.patch(new ContentChanges(List.of(offset)));
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
                        OperationType.UPDATE,
                        1L,
                        List.of(new PatchOperation("replace", "/field", null, "new_value")),
                        null);
        // Act
        this.contentUpdaterSpy.patch(new ContentChanges(List.of(offset)));
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
        Offset offset = new Offset("test", 1L, "test", OperationType.DELETE, 1L, null, null);
        // Act
        this.contentUpdaterSpy.patch(new ContentChanges(List.of(offset)));
        // Assert
        verify(this.contentUpdaterSpy, times(1)).delete(any());
    }
}
