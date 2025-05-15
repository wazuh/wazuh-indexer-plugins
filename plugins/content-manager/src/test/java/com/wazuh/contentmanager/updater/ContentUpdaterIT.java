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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.cti.*;
import com.wazuh.contentmanager.model.cti.OperationType;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

/** Integration test for the {@link ContentUpdater} class. */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterIT extends OpenSearchIntegTestCase {
    private final String resourceId = "CVE-0000-0000";
    private Client client;
    private ContentUpdater updater;
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private CTIClient ctiClient;
    private Privileged privilegedSpy;

    /**
     * Sets up the test environment.
     *
     * @throws Exception if an error occurs during setup.
     */
    @Before
    public void setup() throws Exception {
        this.client = client();
        this.ctiClient = mock(CTIClient.class);
        CommandManagerClient commandClient = mock(CommandManagerClient.class);
        this.contextIndex = spy(new ContextIndex(client));
        this.contentIndex = new ContentIndex(client);
        this.privilegedSpy = Mockito.spy(Privileged.class);
        this.updater =
                Mockito.spy(
                        new ContentUpdater(
                                this.ctiClient,
                                commandClient,
                                this.contextIndex,
                                this.contentIndex,
                                this.privilegedSpy));

        this.prepareInitialCVEInfo(0);
        this.prepareInitialConsumerInfo();
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(ContentManagerPlugin.class);
    }

    /**
     * Tests whether a create-type patch is correctly applied to the {@link ContentIndex#INDEX_NAME}
     * index.
     *
     * <p>The test tries to add new content to the {@link ContentIndex#INDEX_NAME} index, which is
     * initially empty (offset 0). The new content consists on a single element, with offset 1.
     *
     * @throws InterruptedException thrown by {@link ContentIndex#get(String)}
     * @throws ExecutionException thrown by {@link ContentIndex#get(String)}
     * @throws TimeoutException thrown by {@link ContentIndex#get(String)}
     * @throws IOException thrown by {@link ContentIndex#get(String)}
     */
    public void testUpdate_ContentChangesTypeCreate()
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        // Fixtures
        // List of changes to apply (offset 1 == create)
        ContentChanges contentChanges =
                new ContentChanges(List.of(this.buildOffset(1, OperationType.CREATE)));
        ConsumerInfo testConsumer = this.buildTestConsumer(1);
        // Mock
        when(this.ctiClient.getChanges(0, 1, false)).thenReturn(contentChanges);
        when(this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID))
                .thenReturn(testConsumer);
        // Mock postUpdateCommand method.
        doNothing()
                .when(this.privilegedSpy)
                .postUpdateCommand(any(CommandManagerClient.class), any(ConsumerInfo.class));
        // Act
        boolean updated =
                this.updater.update(
                        this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID), 0L);

        // Ensure the index is refreshed.
        RefreshRequest request = new RefreshRequest(ContentIndex.INDEX_NAME);
        this.client.admin().indices().refresh(request).get(PluginSettings.TIMEOUT, TimeUnit.SECONDS);

        ConsumerInfo updatedConsumer =
                this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(1, updatedConsumer.getLastOffset());
    }

    /**
     * Tests whether an update-type patch is correctly applied to the {@link ContentIndex#INDEX_NAME}
     * index.
     *
     * <p>The test tries to update the content, which initially is on offset 0, to the latest offset
     * on the CTI API, which is 2 (mocked response). The list of changes is [offset 1: create, offset
     * 2: update]. The updated element is first created and then updated.
     *
     * @throws InterruptedException thrown by {@link ContentIndex#get(String)}
     * @throws ExecutionException thrown by {@link ContentIndex#get(String)}
     * @throws TimeoutException thrown by {@link ContentIndex#get(String)}
     * @throws IOException thrown by {@link ContentIndex#get(String)}
     */
    public void testUpdate_ContentChangesTypeUpdate()
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        // Fixtures
        // List of changes to apply (offset 1 == create, offset 2 == update)
        ContentChanges contentChanges =
                new ContentChanges(
                        List.of(
                                this.buildOffset(1, OperationType.CREATE),
                                this.buildOffset(2, OperationType.UPDATE)));
        ConsumerInfo testConsumer = this.buildTestConsumer(2);
        // Mock
        when(this.ctiClient.getChanges(0, 2, false)).thenReturn(contentChanges);
        when(this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID))
                .thenReturn(testConsumer);
        // Mock postUpdateCommand method.
        doNothing()
                .when(this.privilegedSpy)
                .postUpdateCommand(any(CommandManagerClient.class), any(ConsumerInfo.class));
        // Act
        boolean updated =
                this.updater.update(
                        this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID), 0L);

        // Ensure the index is refreshed.
        RefreshRequest request = new RefreshRequest(ContentIndex.INDEX_NAME);
        this.client.admin().indices().refresh(request).get(PluginSettings.TIMEOUT, TimeUnit.SECONDS);

        ConsumerInfo updatedConsumer =
                this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(2, updatedConsumer.getLastOffset());
    }

    /**
     * Tests whether a delete-type patch is correctly applied to the {@link ContentIndex#INDEX_NAME}
     * index.
     *
     * <p>The test tries to delete an element from the {@link ContentIndex#INDEX_NAME} index, which is
     * initially empty (offset 0). The test first created the element and the removes it, so the list
     * of changes is [offset 1: create, offset 2: delete]. The test finally ensures the element was
     * deleted.
     *
     * @throws InterruptedException thrown by {@link ContentIndex#get(String)}
     * @throws ExecutionException thrown by {@link ContentIndex#get(String)}
     * @throws TimeoutException thrown by {@link ContentIndex#get(String)}
     * @throws IOException thrown by {@link ContentIndex#get(String)}
     */
    public void testUpdate_ContentChangesTypeDelete()
            throws InterruptedException, ExecutionException, TimeoutException, IOException {
        // Fixtures
        ContentChanges contentChanges =
                new ContentChanges(
                        List.of(
                                this.buildOffset(1, OperationType.CREATE),
                                this.buildOffset(2, OperationType.DELETE)));
        ConsumerInfo testConsumer = this.buildTestConsumer(2);
        // Mock
        when(this.ctiClient.getChanges(0, 2, false)).thenReturn(contentChanges);
        when(this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID))
                .thenReturn(testConsumer);
        // Mock postUpdateCommand method.
        doNothing()
                .when(this.privilegedSpy)
                .postUpdateCommand(any(CommandManagerClient.class), any(ConsumerInfo.class));
        // Act
        boolean updated =
                this.updater.update(
                        this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID), 2L);

        // Ensure the index is refreshed.
        RefreshRequest request = new RefreshRequest(ContentIndex.INDEX_NAME);
        this.client.admin().indices().refresh(request).get(PluginSettings.TIMEOUT, TimeUnit.SECONDS);

        ConsumerInfo updatedConsumer =
                this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID);
        GetResponse getContent =
                this.contentIndex.get(this.resourceId).get(PluginSettings.TIMEOUT, TimeUnit.SECONDS);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(2, updatedConsumer.getLastOffset());
        assertFalse(getContent.isExists());
    }

    /**
     * Creates an Offset object with the specified ID and content type.
     *
     * @param id The ID of the offset.
     * @param type The content type (CREATE, UPDATE, DELETE).
     * @return An Offset object with the specified ID and content type.
     */
    private Offset buildOffset(long id, OperationType type) {
        List<PatchOperation> operations = null;
        Map<String, Object> payload = null;
        if (type == OperationType.UPDATE) {
            operations = List.of(new PatchOperation("add", "/newField", null, "test"));
        } else if (type == OperationType.CREATE) {
            payload = new HashMap<>();
            payload.put("name", "Dummy Threat");
            payload.put("indicators", List.of("192.168.1.1", "example.com"));
        }
        return new Offset(
                PluginSettings.CONTEXT_ID, id, this.resourceId, type, 1L, operations, payload);
    }

    /**
     * Build an instance of {@link ConsumerInfo}.
     *
     * @param lastOffset The initial lastOffset to set.
     * @return an instance of {@link ConsumerInfo}.
     */
    private ConsumerInfo buildTestConsumer(long lastOffset) {
        return new ConsumerInfo(
                PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID, 0, lastOffset, null);
    }

    /**
     * Prepares the initial ConsumerInfo document in the test index.
     *
     * @throws IOException If an error occurs while preparing the document.
     */
    public void prepareInitialConsumerInfo() throws IOException {
        // Create a ConsumerInfo document manually in the test index
        ConsumerInfo info = this.buildTestConsumer(0);
        this.client
                .prepareIndex(ContextIndex.INDEX_NAME)
                .setId(PluginSettings.CONTEXT_ID)
                .setSource(info.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }

    /**
     * Prepares the initial CVE information in the test index.
     *
     * @param offset The initial offset to set.
     * @throws IOException If an error occurs while preparing the document.
     */
    public void prepareInitialCVEInfo(long offset) throws IOException {
        // Create a ConsumerInfo document manually in the test index
        Offset mOffset = this.buildOffset(offset, OperationType.CREATE);
        this.client
                .prepareIndex(ContentIndex.INDEX_NAME)
                .setId(this.resourceId)
                .setSource(mOffset.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }
}
