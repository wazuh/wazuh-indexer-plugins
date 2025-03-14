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

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
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
        doReturn(100L).when(contentUpdaterSpy).getCurrentOffset();
        doReturn(100L).when(contentUpdaterSpy).getLatestOffset();
        contentUpdaterSpy.fetchAndApplyUpdates();
        verify(contentUpdaterSpy, never()).patchAndPostCommand(any());
    }
}
