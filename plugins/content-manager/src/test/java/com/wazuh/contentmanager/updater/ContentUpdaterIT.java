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

import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.*;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.*;
import com.wazuh.contentmanager.updater.ContentUpdater;

import static com.wazuh.contentmanager.settings.PluginSettings.CONSUMER_ID;
import static com.wazuh.contentmanager.settings.PluginSettings.CONTEXT_ID;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterIT extends OpenSearchIntegTestCase {
    Long initialOffset = 0L;
    ContentUpdater updater;
    ContextIndex contextIndex;
    CTIClient ctiClient;

    @Before
    public void setup() throws Exception {
        Client client = client();
        ctiClient = mock(CTIClient.class);
        updater = new ContentUpdater(client, ctiClient);
        contextIndex = new ContextIndex(client);
        prepareInitialCVEInfo(client, initialOffset);
        prepareInitialConsumerInfo(client, initialOffset);
        Thread.sleep(1000);
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(ContentManagerPlugin.class);
    }

    //    public void testFetchAndApplyUpdates_appliesContentCorrectly() {
    //        // Act
    //        boolean updated = updater.fetchAndApplyUpdates(initialOffset, 10L);
    //        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
    //        // Assert
    //        assertTrue(updated);
    //        assertNotNull(updatedConsumer);
    //        assertEquals(10L, (long) updatedConsumer.getLastOffset());
    //    }

    public void testFetchAndApplyUpdates_ContentChangesTypeCreate() {
        // Arrange
        Long newOffset = 1L;
        Offset createOffset =
                new Offset(CONTEXT_ID, newOffset, "test", ContentType.CREATE, 1L, null, getDummyPayload());
        ContentChanges contentChanges = new ContentChanges(List.of(createOffset));
        // Mock
        when(ctiClient.getChanges(initialOffset.toString(), "1", null)).thenReturn(contentChanges);
        // Act
        boolean updated = updater.fetchAndApplyUpdates(initialOffset, newOffset);
        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        logger.info("Created consumer info: {}", updatedConsumer);
        assertEquals(newOffset, updatedConsumer.getLastOffset());
    }

    public void testFetchAndApplyUpdates_ContentChangesTypeUpdate() {
        // Arrange
        Long newOffset = 2L;
        ContentChanges contentChanges = getContentChanges(newOffset);
        // Mock
        when(ctiClient.getChanges(initialOffset.toString(), "2", null)).thenReturn(contentChanges);
        // Act
        boolean updated = updater.fetchAndApplyUpdates(initialOffset, newOffset);
        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
        // Assert
        assertTrue(updated);
        assertNotNull(updatedConsumer);
        logger.info("Updated consumer info: {}", updatedConsumer);
        assertEquals(newOffset, updatedConsumer.getLastOffset());
    }

    private ContentChanges getContentChanges(Long newOffset) {
        PatchOperation operation = new PatchOperation("add", "/newField", null, "test");
        // TODO: Add this offset as initial offset of wazuh-cve using prepare Index
        Offset createOffset =
                new Offset(
                        CONTEXT_ID, newOffset - 1, "test", ContentType.CREATE, 1L, null, getDummyPayload());
        Offset updateOffset =
                new Offset(CONTEXT_ID, newOffset, "test", ContentType.UPDATE, 1L, List.of(operation), null);

        return new ContentChanges(List.of(createOffset, updateOffset));
    }

    //
    //    public void testFetchAndApplyUpdates_ContentChangesTypeDelete() {
    //        // Arrange
    //        Long newOffset = 5L;
    //        ContentChanges contentChanges =
    //                new ContentChanges(
    //                        List.of(new Offset("test", newOffset, "test", ContentType.DELETE, 1L,
    // null, null)));
    //        // Act
    //        updater.fetchAndApplyUpdates(initialOffset, newOffset);
    //        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
    //        // Assert
    //        assertNotNull(updatedConsumer);
    //        assertEquals(newOffset, updatedConsumer.getLastOffset());
    //    }
    //
    //    public void testFetchAndApplyUpdates_noNewUpdates() {
    //        // Arrange
    //        Long currentOffset = 10L;
    //        Long latestOffset = 10L;
    //        // Act
    //        boolean updated = updater.fetchAndApplyUpdates(currentOffset, latestOffset);
    //        // Assert
    //        assertFalse(updated);
    //    }
    //
    //    public void testFetchAndApplyUpdates_errorFetchingChanges() {
    //        // Arrange
    //        Long currentOffset = 0L;
    //        Long latestOffset = 10L;
    //        // Act
    //        Exception exception =
    //                assertThrows(
    //                        RuntimeException.class,
    //                        () -> updater.fetchAndApplyUpdates(currentOffset, latestOffset));
    //        // Assert
    //        assertEquals("Unable to fetch changes for offsets 0 to 10", exception.getMessage());
    //    }
    //
    //    public void testFetchAndApplyUpdates_errorOnPatchContextIndex() {
    //        // Arrange
    //        Long currentOffset = 0L;
    //        Long latestOffset = 10L;
    //        // Act
    //        Exception exception =
    //                assertThrows(
    //                        RuntimeException.class,
    //                        () -> updater.fetchAndApplyUpdates(currentOffset, latestOffset));
    //        // Assert
    //        assertEquals("Unable to fetch changes for offsets 0 to 10", exception.getMessage());
    //    }
    //
    //    public void testFetchAndApplyUpdates_restartConsumerInfo() {
    //        // Arrange
    //        Long currentOffset = 0L;
    //        Long latestOffset = 10L;
    //        // Act
    //        updater.fetchAndApplyUpdates(currentOffset, latestOffset);
    //        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
    //        // Assert
    //        assertNotNull(updatedConsumer);
    //        assertEquals(0L, (long) updatedConsumer.getLastOffset());
    //    }
    //
    //    public void testFetchAndApplyUpdates_postUpdateCommand() {
    //        // Arrange
    //        Long currentOffset = 0L;
    //        Long latestOffset = 10L;
    //        // Act
    //        updater.fetchAndApplyUpdates(currentOffset, latestOffset);
    //        ConsumerInfo updatedConsumer = contextIndex.getConsumer(CONTEXT_ID, CONSUMER_ID);
    //        // Assert
    //        assertNotNull(updatedConsumer);
    //        assertEquals(10L, (long) updatedConsumer.getLastOffset());
    //    }

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
                .prepareIndex("wazuh-context")
                .setId(CONTEXT_ID)
                .setSource(info.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }

    public Map<String, Object> getDummyPayload() {
        Map<String, Object> dummyPayload = new HashMap<>();
        dummyPayload.put("name", "Dummy Threat");
        dummyPayload.put("severity", "high");
        dummyPayload.put("indicators", List.of("192.168.1.1", "example.com"));
        return dummyPayload;
    }

    public void prepareInitialCVEInfo(Client client, Long offsetId) throws Exception {
        // Create a ConsumerInfo document manually in the test index

        Offset offset =
                new Offset(CONTEXT_ID, offsetId, "test", ContentType.CREATE, 1L, null, getDummyPayload());
        client
                .prepareIndex("wazuh-cve")
                .setId(CONTEXT_ID)
                .setSource(offset.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }
}
