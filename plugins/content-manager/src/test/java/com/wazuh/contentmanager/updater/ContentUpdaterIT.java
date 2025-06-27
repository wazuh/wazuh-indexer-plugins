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
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.env.Environment;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.transport.client.Client;
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
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterIT extends OpenSearchIntegTestCase {
    private final String resourceId = "CVE-0000-0000";
    private Client client;
    private ContentUpdater updater;
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private CommandManagerClient commandClient;
    private CTIClient ctiClient;
    private Privileged privilegedSpy;

    @Mock private Environment mockEnvironment;
    @Mock private ClusterService mockClusterService;
    @InjectMocks private PluginSettings pluginSettings;

    @Before
    public void setup() throws Exception {
        this.client = client();
        this.ctiClient = mock(CTIClient.class);
        this.contextIndex = spy(new ContextIndex(client));
        this.contentIndex = new ContentIndex(client);
        this.commandClient = mock(CommandManagerClient.class);
        Settings settings =
                Settings.builder()
                        .put("content_manager.max_changes", 1000)
                        .put("content_manager.cti.client.sleep_time", 60)
                        .put("content_manager.cti.context", "vd_1.0.0")
                        .put("content_manager.cti.consumer", "https://cti.wazuh.com/TEST/api/v1")
                        .build();
        this.mockEnvironment = mock(Environment.class);
        when(this.mockEnvironment.settings()).thenReturn(settings);
        this.pluginSettings =
                PluginSettings.getInstance(this.mockEnvironment.settings(), this.mockClusterService);

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
     * @throws InterruptedException thrown by {@link ContentIndex#getById(String)}
     * @throws ExecutionException thrown by {@link ContentIndex#getById(String)}
     * @throws TimeoutException thrown by {@link ContentIndex#getById(String)}
     */
    public void testUpdate_ContentChangesTypeCreate()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Fixtures
        // List of changes to apply (offset 1 == create)
        Offsets offsets = new Offsets(List.of(this.buildOffset(1, Offset.Type.CREATE)));
        ConsumerInfo testConsumer = this.buildTestConsumer(1);
        // Mock
        when(this.ctiClient.getChanges(0, 1, false)).thenReturn(offsets);
        when(this.contextIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId()))
                .thenReturn(testConsumer);
        // Mock postUpdateCommand method.
        doNothing()
                .when(this.privilegedSpy)
                .postUpdateCommand(any(CommandManagerClient.class), any(ConsumerInfo.class));
        // Act
        boolean updated = this.updater.update();

        // Ensure the index is refreshed.
        RefreshRequest request = new RefreshRequest(ContentIndex.INDEX_NAME);
        this.client
                .admin()
                .indices()
                .refresh(request)
                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

        ConsumerInfo updatedConsumer =
                this.contextIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId());
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(1, updatedConsumer.getLastOffset());
        assertEquals("2024-02-29T23:17:36.191970Z", offsets.getFirst().getInserted_at());
    }

    /**
     * Tests whether an update-type patch is correctly applied to the {@link ContentIndex#INDEX_NAME}
     * index.
     *
     * <p>The test tries to update the content, which initially is on offset 0, to the latest offset
     * on the CTI API, which is 2 (mocked response). The list of changes is [offset 1: create, offset
     * 2: update]. The updated element is first created and then updated.
     *
     * @throws InterruptedException thrown by {@link ContentIndex#getById(String)}
     * @throws ExecutionException thrown by {@link ContentIndex#getById(String)}
     * @throws TimeoutException thrown by {@link ContentIndex#getById(String)}
     */
    public void testUpdate_ContentChangesTypeUpdate()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Fixtures
        // List of changes to apply (offset 1 == create, offset 2 == update)
        Offsets offsets =
                new Offsets(
                        List.of(
                                this.buildOffset(1, Offset.Type.CREATE), this.buildOffset(2, Offset.Type.UPDATE)));
        ConsumerInfo testConsumer = this.buildTestConsumer(2);
        // Mock
        when(this.ctiClient.getChanges(0, 2, false)).thenReturn(offsets);
        when(this.contextIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId()))
                .thenReturn(testConsumer);
        // Mock postUpdateCommand method.
        doNothing()
                .when(this.privilegedSpy)
                .postUpdateCommand(any(CommandManagerClient.class), any(ConsumerInfo.class));
        // Act
        boolean updated = this.updater.update();

        // Ensure the index is refreshed.
        RefreshRequest request = new RefreshRequest(ContentIndex.INDEX_NAME);
        this.client
                .admin()
                .indices()
                .refresh(request)
                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

        ConsumerInfo updatedConsumer =
                this.contextIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId());
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
     * @throws InterruptedException thrown by {@link ContentIndex#getById(String)}
     * @throws ExecutionException thrown by {@link ContentIndex#getById(String)}
     * @throws TimeoutException thrown by {@link ContentIndex#getById(String)}
     */
    public void testUpdate_ContentChangesTypeDelete()
            throws InterruptedException, ExecutionException, TimeoutException {
        // Fixtures
        Offsets offsets =
                new Offsets(
                        List.of(
                                this.buildOffset(1, Offset.Type.CREATE), this.buildOffset(2, Offset.Type.DELETE)));
        ConsumerInfo testConsumer = this.buildTestConsumer(2);
        // Mock
        when(this.ctiClient.getChanges(0, 2, false)).thenReturn(offsets);
        when(this.contextIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId()))
                .thenReturn(testConsumer);
        // Mock postUpdateCommand method.
        doNothing()
                .when(this.privilegedSpy)
                .postUpdateCommand(any(CommandManagerClient.class), any(ConsumerInfo.class));
        // Act
        boolean updated = this.updater.update();

        // Ensure the index is refreshed.
        RefreshRequest request = new RefreshRequest(ContentIndex.INDEX_NAME);
        this.client
                .admin()
                .indices()
                .refresh(request)
                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

        ConsumerInfo updatedConsumer =
                this.contextIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId());
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(2, updatedConsumer.getLastOffset());
        assertThrows(IllegalArgumentException.class, () -> this.contentIndex.getById(this.resourceId));
    }

    /**
     * Creates an Offset object with the specified ID and content type.
     *
     * @param id The ID of the offset.
     * @param type The content type (CREATE, UPDATE, DELETE).
     * @return An Offset object with the specified ID and content type.
     */
    private Offset buildOffset(long id, Offset.Type type) {
        List<Operation> operations = null;
        Map<String, Object> payload = null;
        if (type == Offset.Type.UPDATE) {
            operations = List.of(new Operation(Operation.Type.ADD, "/newField", null, "test"));
        } else if (type == Offset.Type.CREATE) {
            payload = new HashMap<>();
            payload.put("name", "Dummy Threat");
            payload.put("indicators", List.of("192.168.1.1", "example.com"));
            // To test the new field inserted_at in the case of a Type.CREATE Offset, it will be created
            // with it
            return new Offset(
                    id, this.resourceId, type, 1L, operations, payload, "2024-02-29T23:17:36.191970Z");
        }
        return new Offset(id, this.resourceId, type, 1L, operations, payload, null);
    }

    /**
     * Build an instance of {@link ConsumerInfo}.
     *
     * @param lastOffset The initial lastOffset to set.
     * @return an instance of {@link ConsumerInfo}.
     */
    private ConsumerInfo buildTestConsumer(long lastOffset) {
        return new ConsumerInfo(
                this.pluginSettings.getConsumerId(),
                this.pluginSettings.getContextId(),
                0,
                lastOffset,
                null);
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
                .setId(this.pluginSettings.getContextId())
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
        Offset mOffset = this.buildOffset(offset, Offset.Type.CREATE);
        this.client
                .prepareIndex(ContentIndex.INDEX_NAME)
                .setId(this.resourceId)
                .setSource(mOffset.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }
}
