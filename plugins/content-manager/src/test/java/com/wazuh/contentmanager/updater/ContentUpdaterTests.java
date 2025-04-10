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
package com.wazuh.contentmanager.updater;

import org.opensearch.client.Client;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.model.ctiapi.ContentChanges;
import com.wazuh.contentmanager.model.ctiapi.ContentType;
import com.wazuh.contentmanager.model.ctiapi.Offset;
import com.wazuh.contentmanager.model.ctiapi.PatchOperation;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

/** Tests of the Content Manager's updater */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterTests extends OpenSearchIntegTestCase {
    private ContentUpdater contentUpdaterSpy;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    public void setup() throws Exception {
        super.setUp();
        Client client = mock(Client.class);
        ContentUpdater contentUpdater = new ContentUpdater(client, mock(CTIClient.class));
        contentUpdaterSpy = Mockito.spy(contentUpdater);
    }

    /** Test Fetch and apply no new updates */
    public void testFetchAndApplyUpdatesNoNewUpdates() {
        // Mock current and latest offset.
        doReturn(100L).when(contentUpdaterSpy).getCurrentOffset();
        doReturn(100L).when(contentUpdaterSpy).getLatestOffset();
        // Act
        contentUpdaterSpy.fetchAndApplyUpdates(null, null);
        // Assert patchContextIndex is not called.
        verify(contentUpdaterSpy, never()).patchContextIndex(any());
    }

    /** Test fetch and apply new updates */
    public void testFetchAndApplyUpdatesNewUpdates() {
        Integer offsetsAmount = 3999;
        // Mock current and latest offset.
        doReturn(0L).when(contentUpdaterSpy).getCurrentOffset();
        doReturn((long) offsetsAmount).when(contentUpdaterSpy).getLatestOffset();
        // Mock getContextChanges method.
        doReturn(generateContextChanges(offsetsAmount))
                .when(contentUpdaterSpy)
                .getContextChanges(any(), any());
        // Mock postUpdateCommand method.
        doNothing().when(contentUpdaterSpy).postUpdateCommand();
        // Mock ContentIndex.patch
        doReturn(true).when(contentUpdaterSpy).patchContextIndex(any());
        // Act
        contentUpdaterSpy.fetchAndApplyUpdates(null, null);
        // Assert patchContextIndex is called 4 times (one each 1000 starting from 0).
        verify(contentUpdaterSpy, times(4)).patchContextIndex(any());
    }

    /** Test error fetching changes */
    //    public void testFetchAndApplyUpdatesErrorFetchingChanges() {
    //        int offsetsAmount = 3999;
    //        // Mock current and latest offset.
    //        doReturn(0L).when(contentUpdaterSpy).getCurrentOffset();
    //        doReturn((long) offsetsAmount).when(contentUpdaterSpy).getLatestOffset();
    //        // Mock getContextChanges method.
    //        doReturn(null).when(contentUpdaterSpy).getContextChanges(any(), any());
    //        // Act
    //        Exception exception =
    //                assertThrows(
    //                        RuntimeException.class, () ->
    // contentUpdaterSpy.fetchAndApplyUpdates(null, null));
    //        // Assert
    //        assertEquals("Unable to fetch changes for offsets 0 to 1000", exception.getMessage());
    //        verify(contentUpdaterSpy, times(1)).getContextChanges(any(), any());
    //    }
    //
    //    /** Test error on patchContextIndex method (method return false) */
    //    public void testFetchAndApplyUpdatesErrorOnPatchContextIndex() {
    //        int offsetsAmount = 3999;
    //        // Mock current and latest offset.
    //        doReturn(0L).when(contentUpdaterSpy).getCurrentOffset();
    //        doReturn((long) offsetsAmount).when(contentUpdaterSpy).getLatestOffset();
    //        // Mock getContextChanges method.
    //        doReturn(generateContextChanges(offsetsAmount))
    //                .when(contentUpdaterSpy)
    //                .getContextChanges(any(), any());
    //        // Mock patchContextIndex method.
    //        doReturn(false).when(contentUpdaterSpy).patchContextIndex(any());
    //        // Act
    //        contentUpdaterSpy.fetchAndApplyUpdates(null, null);
    //        // Assert
    //        verify(contentUpdaterSpy, times(1)).restartConsumerInfo();
    //    }

    /**
     * Generate context changes
     *
     * @param size of the generated changes list
     * @return A ContextChanges object
     */
    public ContentChanges generateContextChanges(Integer size) {
        List<Offset> offsets = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            offsets.add(
                    new Offset(
                            "context",
                            (long) i,
                            "resource",
                            ContentType.UPDATE,
                            0L,
                            List.of(new PatchOperation("op", "path", "from", "value")),
                            null));
        }
        return new ContentChanges(offsets);
    }
}
