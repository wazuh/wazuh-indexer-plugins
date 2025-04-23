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

import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ContentChanges;
import com.wazuh.contentmanager.model.ctiapi.Offset;
import com.wazuh.contentmanager.model.ctiapi.OperationType;
import com.wazuh.contentmanager.model.ctiapi.PatchOperation;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

/** Tests of the Content Manager's updater */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterTests extends OpenSearchIntegTestCase {
    private ContentUpdater contentUpdaterSpy;
    private ContextIndex contextIndex;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    public void setup() throws Exception {
        super.setUp();
        this.contextIndex = mock(ContextIndex.class);
        ContentUpdater contentUpdater =
                new ContentUpdater(mock(CTIClient.class), this.contextIndex, mock(ContentIndex.class));
        this.contentUpdaterSpy = Mockito.spy(contentUpdater);
    }

    /** Test Fetch and apply no new updates */
    public void testUpdateNoChanges() {
        // Mock current and latest offset.
        doReturn(0L).when(this.contextIndex).getOffset();
        doReturn(0L).when(this.contextIndex).getLastOffset();
        // Act
        this.contentUpdaterSpy.update();
        // Assert applyChangesToContextIndex is not called.
        verify(this.contentUpdaterSpy, never()).applyChanges(any());
    }

    /** Test fetch and apply new updates */
    public void testUpdateNewChanges() {
        long offsetsAmount = 3999L;
        // Mock current and latest offset.
        doReturn(0L).when(this.contextIndex).getOffset();
        doReturn(offsetsAmount).when(this.contextIndex).getLastOffset();
        // Mock getContextChanges method.
        doReturn(generateContextChanges((int) offsetsAmount))
                .when(this.contentUpdaterSpy)
                .getChanges(anyLong(), anyLong());
        // Mock postUpdateCommand method.
        doNothing().when(this.contentUpdaterSpy).postUpdateCommand();
        // Mock ContentIndex.patch
        doReturn(true).when(this.contentUpdaterSpy).applyChanges(any());
        // Act
        doNothing().when(contentUpdaterSpy).updateContext(anyLong(), anyLong());
        this.contentUpdaterSpy.update();
        // Assert applyChangesToContextIndex is called 4 times (one each 1000 starting from 0).
        verify(this.contentUpdaterSpy, times(4)).applyChanges(any());
    }

    /** Test error fetching changes */
    public void testUpdateErrorFetchingChanges() {
        long offsetsAmount = 3999L;
        // Mock current and latest offset.
        doReturn(0L).when(this.contextIndex).getOffset();
        doReturn(offsetsAmount).when(this.contextIndex).getLastOffset();
        // Mock getContextChanges method.
        doReturn(null).when(this.contentUpdaterSpy).getChanges(anyLong(), anyLong());
        doNothing().when(contentUpdaterSpy).updateContext(anyLong(), anyLong());
        // Act
        boolean updated = this.contentUpdaterSpy.update();
        // Assert
        assertFalse(updated);
    }

    /** Test error on applyChangesToContextIndex method (method return false) */
    public void testUpdateErrorOnPatchContextIndex() {
        long offsetsAmount = 3999L;
        // Mock current and latest offset.
        doReturn(0L).when(this.contextIndex).getOffset();
        doReturn(offsetsAmount).when(this.contextIndex).getLastOffset();
        // Mock getContextChanges method.
        doReturn(generateContextChanges((int) offsetsAmount))
                .when(this.contentUpdaterSpy)
                .getChanges(anyLong(), anyLong());
        // Mock applyChangesToContextIndex method.
        doReturn(false).when(this.contentUpdaterSpy).applyChanges(any());
        doNothing().when(contentUpdaterSpy).updateContext(anyLong(), anyLong());
        // Act
        boolean updated = this.contentUpdaterSpy.update();
        // Assert
        assertFalse(updated);
        verify(this.contentUpdaterSpy, times(1)).updateContext(0L, 0L);
    }

    /**
     * Generate context changes
     *
     * @param size of the generated changes list
     * @return A ContextChanges object
     */
    public ContentChanges generateContextChanges(int size) {
        List<Offset> offsets = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            offsets.add(
                    new Offset(
                            "context",
                            (long) i,
                            "resource",
                            OperationType.UPDATE,
                            0L,
                            List.of(
                                    new PatchOperation(
                                            PatchOperation.OP,
                                            PatchOperation.PATH,
                                            PatchOperation.FROM,
                                            PatchOperation.VALUE)),
                            null));
        }
        return new ContentChanges(offsets);
    }
}
