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

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.cti.*;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

/** Tests of the Content Manager's updater */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterTests extends OpenSearchIntegTestCase {
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private CommandManagerClient commandClient;
    private CTIClient ctiClient;
    private Privileged privilegedSpy;
    private ConsumerInfo consumerInfo;
    private ContentUpdater updater;

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
        this.ctiClient = mock(CTIClient.class);
        this.commandClient = mock(CommandManagerClient.class);

        Settings settings = Settings.builder().put("content_manager.max_changes", 1000).build();
        this.mockEnvironment = mock(Environment.class);
        when(this.mockEnvironment.settings()).thenReturn(settings);
        this.pluginSettings =
                PluginSettings.getInstance(this.mockEnvironment.settings(), this.mockClusterService);

        this.contextIndex = mock(ContextIndex.class);
        this.contentIndex = mock(ContentIndex.class);
        this.privilegedSpy = Mockito.spy(Privileged.class);
        this.updater =
                Mockito.spy(
                        new ContentUpdater(
                                this.ctiClient,
                                this.commandClient,
                                this.contextIndex,
                                this.contentIndex,
                                this.privilegedSpy,
                                this.pluginSettings));
        this.consumerInfo = mock(ConsumerInfo.class);
    }

    /** Test Fetch and apply no new updates */
    public void testUpdateNoChanges() {
        // Mock current and latest offset.
        doReturn(this.consumerInfo).when(this.contextIndex).get(anyString(), anyString());
        // Act
        this.updater.update();
        // Assert applyChangesToContextIndex is not called.
        verify(this.updater, never()).applyChanges(any());
    }

    /** Test fetch and apply new updates */
    public void testUpdateNewChanges() {
        long offsetsAmount = 3999L;
        // Mock current and latest offset.
        doReturn(0L).when(this.consumerInfo).getOffset();
        doReturn(offsetsAmount).when(this.consumerInfo).getLastOffset();
        // Mock getContextChanges method.
        doReturn(generateContextChanges((int) offsetsAmount))
                .when(this.privilegedSpy)
                .getChanges(any(CTIClient.class), anyLong(), anyLong());
        // Mock ContentIndex.patch
        doReturn(true).when(this.updater).applyChanges(any());
        doReturn(this.consumerInfo).when(this.contextIndex).get(anyString(), anyString());
        // Act
        doNothing().when(this.consumerInfo).setOffset(anyLong());
        doNothing().when(this.consumerInfo).setLastOffset(anyLong());
        this.updater.update();
        // Assert applyChangesToContextIndex is called 4 times (one each 1000 starting from 0).
        verify(this.updater, times(4)).applyChanges(any());
    }

    /** Test error fetching changes */
    public void testUpdateErrorFetchingChanges() {
        long offsetsAmount = 3999L;
        // Mock current and latest offset.
        doReturn(0L).when(this.consumerInfo).getOffset();
        doReturn(offsetsAmount).when(this.consumerInfo).getLastOffset();
        // Mock getContextChanges method.
        doReturn(null).when(this.privilegedSpy).getChanges(any(CTIClient.class), anyLong(), anyLong());
        doNothing().when(this.consumerInfo).setOffset(anyLong());
        doNothing().when(this.consumerInfo).setLastOffset(anyLong());
        doReturn(this.consumerInfo).when(this.contextIndex).get(anyString(), anyString());
        // Act
        boolean updated = this.updater.update();
        // Assert
        assertFalse(updated);
    }

    /** Test error on applyChangesToContextIndex method (method return false) */
    public void testUpdateErrorOnPatchContextIndex() {
        long offsetsAmount = 3999L;
        // Mock current and latest offset.
        doReturn(0L).when(this.consumerInfo).getOffset();
        doReturn(offsetsAmount).when(this.consumerInfo).getLastOffset();
        // Mock getContextChanges method.
        doReturn(generateContextChanges((int) offsetsAmount))
                .when(this.privilegedSpy)
                .getChanges(any(CTIClient.class), anyLong(), anyLong());
        // Mock applyChangesToContextIndex method.
        doReturn(false).when(this.updater).applyChanges(any());
        doNothing().when(this.consumerInfo).setOffset(anyLong());
        doNothing().when(this.consumerInfo).setLastOffset(anyLong());
        doReturn(this.consumerInfo).when(this.contextIndex).get(anyString(), anyString());
        // Act
        boolean updated = this.updater.update();
        // Assert
        assertFalse(updated);
        verify(this.consumerInfo, times(1)).setOffset(0L);
        verify(this.consumerInfo, times(1)).setLastOffset(0L);
    }

    /**
     * Generate context changes
     *
     * @param size of the generated changes list
     * @return A ContextChanges object
     */
    public Changes generateContextChanges(int size) {
        List<Offset> offsets = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            offsets.add(
                    new Offset(
                            "context",
                            (long) i,
                            "resource",
                            Offset.Type.UPDATE,
                            0L,
                            List.of(new Operation(Operation.OP, Operation.PATH, Operation.FROM, Operation.VALUE)),
                            null));
        }
        return new Changes(offsets);
    }
}
