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
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.model.ctiapi.Offset;
import com.wazuh.contentmanager.model.ctiapi.Offsets;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterTests extends OpenSearchIntegTestCase {
    private CTIClient mockCtiClient;
    private CommandManagerClient mockCommandManagerClient;
    private Client client;
    private ClusterService clusterService;
    private ContentUpdater contentUpdater;

    @Before
    public void setup() throws Exception {
        super.setUp();
        contentUpdater = new ContentUpdater();
    }

    public void testFetchAndApplyUpdatesNoNewUpdates() throws IOException {
        ContentUpdater contentUpdaterSpy = Mockito.spy(contentUpdater);
        // Mock current and latest offset.
        doReturn(100L).when(contentUpdaterSpy).getCurrentOffset();
        doReturn(100L).when(contentUpdaterSpy).getLatestOffset();
        // Act
        contentUpdaterSpy.fetchAndApplyUpdates();
        // Assert
        verify(contentUpdaterSpy, never()).patchContextIndex(any());
    }

    public void testFetchAndApplyUpdatesNewUpdates() throws IOException {
        ContentUpdater contentUpdaterSpy = Mockito.spy(contentUpdater);
        // Maximum chunk size is 1000.
        Integer OffsetsAmount = 3999;
        // Mock current and latest offset.
        doReturn(0L).when(contentUpdaterSpy).getCurrentOffset();
        doReturn((long) OffsetsAmount).when(contentUpdaterSpy).getLatestOffset();
        // Mock getContextChanges method.
        doReturn(generateOffsets(OffsetsAmount))
                .when(contentUpdaterSpy)
                .getContextChanges(any(), any());
        // Mock postUpdateCommand method.
        doNothing().when(contentUpdaterSpy).postUpdateCommand((long) OffsetsAmount);
        // Act
        contentUpdaterSpy.fetchAndApplyUpdates();
        // Assert
        verify(contentUpdaterSpy, times(4)).patchContextIndex(any());
    }

    public Offsets generateOffsets(Integer size) {
        List<Offset> offsets = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            offsets.add(new Offset("context", (long) i, "resource", "type", 0L, new HashMap<>()));
        }
        return new Offsets(offsets);
    }
}
