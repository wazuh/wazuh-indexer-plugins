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
package com.wazuh.contentmanager;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.*;
import com.wazuh.contentmanager.updater.ContentUpdater;

import static com.wazuh.contentmanager.index.ContentIndex.TIMEOUT;
import static com.wazuh.contentmanager.settings.PluginSettings.CONSUMER_ID;
import static com.wazuh.contentmanager.settings.PluginSettings.CONTEXT_ID;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterIT extends OpenSearchIntegTestCase {
    Long initialOffset = 0L;
    String testResource = "test";
    ContentUpdater updater;
    ContextIndex contextIndex;
    ContentIndex contentIndex;
    CTIClient ctiClient;

    @Before
    public void setup() throws Exception {
        Client client = client();
        ctiClient = mock(CTIClient.class);
        updater = new ContentUpdater(client, ctiClient);
        contextIndex = new ContextIndex(client);
        contentIndex = new ContentIndex(client);
        prepareInitialCVEInfo(client, initialOffset);
        prepareInitialConsumerInfo(client, initialOffset);
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(ContentManagerPlugin.class);
    }

    public void testFetchAndApplyUpdates_ContentChangesTypeCreate() throws InterruptedException {
        // Arrange
        Long offsetId = 1L;
        Offset createOffset = getOffset(offsetId, ContentType.CREATE);
        ContentChanges contentChanges = new ContentChanges(List.of(createOffset));
        // Mock
        when(ctiClient.getChanges(initialOffset.toString(), "1", null)).thenReturn(contentChanges);
        // Act
        boolean updated = updater.fetchAndApplyUpdates(initialOffset, offsetId);
        Thread.sleep(1000);
        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(offsetId, updatedConsumer.getLastOffset());
    }

    public void testFetchAndApplyUpdates_ContentChangesTypeUpdate() throws InterruptedException {
        // Arrange
        Long offsetId = 2L;
        Offset createOffset = getOffset(offsetId - 1, ContentType.CREATE);
        Offset updateOffset = getOffset(offsetId, ContentType.UPDATE);
        ContentChanges contentChanges = new ContentChanges(List.of(createOffset, updateOffset));
        // Mock
        when(ctiClient.getChanges(initialOffset.toString(), offsetId.toString(), null))
                .thenReturn(contentChanges);
        // Act
        boolean updated = updater.fetchAndApplyUpdates(initialOffset, offsetId);
        Thread.sleep(5000);
        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(offsetId, updatedConsumer.getLastOffset());
    }

    public void testFetchAndApplyUpdates_ContentChangesTypeDelete()
            throws InterruptedException, ExecutionException, TimeoutException {
        // Arrange
        Long offsetId = 2L;
        Offset createOffset = getOffset(offsetId - 1, ContentType.CREATE);
        Offset deleteOffset = getOffset(offsetId, ContentType.DELETE);
        ContentChanges contentChanges = new ContentChanges(List.of(createOffset, deleteOffset));
        // Mock
        when(ctiClient.getChanges(initialOffset.toString(), offsetId.toString(), null))
                .thenReturn(contentChanges);
        // Act
        boolean updated = updater.fetchAndApplyUpdates(initialOffset, offsetId);
        Thread.sleep(5000);
        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        GetResponse getContent = contentIndex.get(testResource).get(TIMEOUT, TimeUnit.SECONDS);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        assertEquals(offsetId, updatedConsumer.getLastOffset());
        assertFalse(getContent.isExists());
    }

    private Offset getOffset(Long id, ContentType type) {
        List<PatchOperation> operations = null;
        Map<String, Object> payload = null;
        if (type == ContentType.UPDATE) {
            operations = List.of(new PatchOperation("add", "/newField", null, "test"));
        } else if (type == ContentType.CREATE) {
            payload = new HashMap<>();
            payload.put("name", "Dummy Threat");
            payload.put("indicators", List.of("192.168.1.1", "example.com"));
        }
        return new Offset(CONTEXT_ID, id, testResource, type, 1L, operations, payload);
    }

    /**
     * Prepares the initial ConsumerInfo document in the test index.
     *
     * @param client The OpenSearch client.
     * @param offset The initial offset to set.
     * @throws Exception If an error occurs while preparing the document.
     */
    @SuppressWarnings("unchecked")
    public void prepareInitialConsumerInfo(Client client, Long offset) throws Exception {
        // Create a ConsumerInfo document manually in the test index
        ConsumerInfo info = new ConsumerInfo(CONSUMER_ID, CONTEXT_ID, offset, null);

        client
                .prepareIndex(ContextIndex.INDEX_NAME)
                .setId(CONTEXT_ID)
                .setSource(info.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }

    public void prepareInitialCVEInfo(Client client, Long offsetId) throws Exception {
        // Create a ConsumerInfo document manually in the test index
        Offset offset = getOffset(offsetId, ContentType.CREATE);
        client
                .prepareIndex(ContentIndex.INDEX_NAME)
                .setId(CONTEXT_ID)
                .setSource(offset.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }
}
