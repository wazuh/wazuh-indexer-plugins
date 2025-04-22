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

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

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
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.*;
import com.wazuh.contentmanager.model.ctiapi.OperationType;

import static com.wazuh.contentmanager.index.ContentIndex.TIMEOUT;
import static com.wazuh.contentmanager.settings.PluginSettings.CONSUMER_ID;
import static com.wazuh.contentmanager.settings.PluginSettings.CONTEXT_ID;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterIT extends OpenSearchIntegTestCase {
    long initialOffset = 0L;
    String testResource = "test";
    ContentUpdater updater;
    ContextIndex contextIndex;
    ContentIndex contentIndex;
    CTIClient ctiClient;

    @Before
    public void setup() throws Exception {
        Client client = client();
        this.ctiClient = mock(CTIClient.class);
        this.updater = new ContentUpdater(client, this.ctiClient);
        this.contextIndex = new ContextIndex(client);
        this.contentIndex = new ContentIndex(client);
        prepareInitialCVEInfo(client, this.initialOffset);
        prepareInitialConsumerInfo(client, this.initialOffset);
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(ContentManagerPlugin.class);
    }

    /**
     * @throws InterruptedException
     */
    public void testUpdate_ContentChangesTypeCreate() throws InterruptedException {
        // Arrange
        long offsetId = 1L;
        Offset createOffset = getOffset(offsetId, OperationType.CREATE);
        ContentChanges contentChanges = new ContentChanges(List.of(createOffset));
        ConsumerInfo testConsumer = new ConsumerInfo(CONSUMER_ID, CONTEXT_ID, offsetId, null);
        // Mock
        when(this.ctiClient.getChanges(this.initialOffset, 1, false)).thenReturn(contentChanges);
        when(this.ctiClient.getCatalog()).thenReturn(testConsumer);
        // Act
        boolean updated = this.updater.update();
        Thread.sleep(1000);
        ConsumerInfo updatedConsumer = this.contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(offsetId, updatedConsumer.getLastOffset());
    }

    /**
     * @throws InterruptedException
     */
    public void testUpdate_ContentChangesTypeUpdate() throws InterruptedException {
        // Arrange
        long offsetId = 2L;
        Offset createOffset = getOffset(offsetId - 1, OperationType.CREATE);
        Offset updateOffset = getOffset(offsetId, OperationType.UPDATE);
        ContentChanges contentChanges = new ContentChanges(List.of(createOffset, updateOffset));
        ConsumerInfo testConsumer = new ConsumerInfo(CONSUMER_ID, CONTEXT_ID, offsetId, null);
        // Mock
        when(this.ctiClient.getChanges(this.initialOffset, offsetId, false)).thenReturn(contentChanges);
        when(this.ctiClient.getCatalog()).thenReturn(testConsumer);
        // Act
        boolean updated = this.updater.update();
        Thread.sleep(1000);
        ConsumerInfo updatedConsumer = this.contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(offsetId, updatedConsumer.getLastOffset());
    }

    /**
     * TODO add Javadocs
     *
     * @throws InterruptedException
     * @throws ExecutionException
     * @throws TimeoutException
     */
    public void testUpdate_ContentChangesTypeDelete()
            throws InterruptedException, ExecutionException, TimeoutException {
        // Arrange
        long offsetId = 2L;
        Offset createOffset = getOffset(offsetId - 1, OperationType.CREATE);
        Offset deleteOffset = getOffset(offsetId, OperationType.DELETE);
        ContentChanges contentChanges = new ContentChanges(List.of(createOffset, deleteOffset));
        ConsumerInfo testConsumer = new ConsumerInfo(CONSUMER_ID, CONTEXT_ID, offsetId, null);
        // Mock
        when(this.ctiClient.getChanges(this.initialOffset, offsetId, false)).thenReturn(contentChanges);
        when(this.ctiClient.getCatalog()).thenReturn(testConsumer);
        // Act
        boolean updated = this.updater.update();
        Thread.sleep(1000);
        ConsumerInfo updatedConsumer = this.contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        GetResponse getContent =
                this.contentIndex.get(this.testResource).get(TIMEOUT, TimeUnit.SECONDS);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(offsetId, updatedConsumer.getLastOffset());
        assertFalse(getContent.isExists());
    }

    /**
     * Creates an Offset object with the specified ID and content type.
     *
     * @param id The ID of the offset.
     * @param type The content type (CREATE, UPDATE, DELETE).
     * @return An Offset object with the specified ID and content type.
     */
    private Offset getOffset(Long id, OperationType type) {
        List<PatchOperation> operations = null;
        Map<String, Object> payload = null;
        if (type == OperationType.UPDATE) {
            operations = List.of(new PatchOperation("add", "/newField", null, "test"));
        } else if (type == OperationType.CREATE) {
            payload = new HashMap<>();
            payload.put("name", "Dummy Threat");
            payload.put("indicators", List.of("192.168.1.1", "example.com"));
        }
        return new Offset(CONTEXT_ID, id, this.testResource, type, 1L, operations, payload);
    }

    /**
     * Prepares the initial ConsumerInfo document in the test index.
     *
     * @param client The OpenSearch client.
     * @param currentOffset The initial currentOffset to set.
     * @throws Exception If an error occurs while preparing the document.
     */
    @SuppressWarnings("unchecked")
    public void prepareInitialConsumerInfo(Client client, Long currentOffset) throws Exception {
        // Create a ConsumerInfo document manually in the test index
        ConsumerInfo info = new ConsumerInfo(CONSUMER_ID, CONTEXT_ID, currentOffset, null);
        client
                .prepareIndex(ContextIndex.INDEX_NAME)
                .setId(CONTEXT_ID)
                .setSource(info.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }

    /**
     * Prepares the initial CVE information in the test index.
     *
     * @param client The OpenSearch client.
     * @param offsetId The initial offset ID to set.
     * @throws Exception If an error occurs while preparing the document.
     */
    public void prepareInitialCVEInfo(Client client, Long offsetId) throws Exception {
        // Create a ConsumerInfo document manually in the test index
        Offset offset = getOffset(offsetId, OperationType.CREATE);
        client
                .prepareIndex(ContentIndex.INDEX_NAME)
                .setId(this.testResource)
                .setSource(offset.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }
}
