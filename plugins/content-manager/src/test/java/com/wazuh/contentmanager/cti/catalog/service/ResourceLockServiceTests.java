/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.service;

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.Assert;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link ResourceLockService}. */
@SuppressWarnings("unchecked")
public class ResourceLockServiceTests extends OpenSearchTestCase {

    private static VersionConflictEngineException versionConflict() {
        return new VersionConflictEngineException(
                new ShardId(Constants.INDEX_RESOURCE_LOCKS, "uuid", 0), "lock-id", "already locked");
    }

    /** Mocks the client.admin().indices().exists() chain to report the lock index already exists. */
    private static void mockLockIndexExists(Client client) {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        IndicesExistsResponse existsResponse = mock(IndicesExistsResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        ActionFuture<IndicesExistsResponse> existsFuture = mock(ActionFuture.class);
        when(existsFuture.actionGet()).thenReturn(existsResponse);
        when(indicesAdminClient.exists(any())).thenReturn(existsFuture);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(client.admin()).thenReturn(adminClient);
    }

    /** Mocks client.get() to report a lock document last acquired {@code ageMillis} ago. */
    private static void mockLockGet(Client client, long ageMillis) {
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        when(getResponse.getSourceAsMap())
                .thenReturn(Map.of("acquired_at", Instant.now().toEpochMilli() - ageMillis));
        ActionFuture<GetResponse> getFuture = mock(ActionFuture.class);
        when(getFuture.actionGet()).thenReturn(getResponse);
        when(client.get(any())).thenReturn(getFuture);
    }

    public void testAcquireSucceedsImmediatelyWhenNoLockExists() throws IOException {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenReturn(mock(IndexResponse.class));
        when(client.index(any())).thenReturn(indexFuture);

        ResourceLockService service = new ResourceLockService(client);
        String lockId = service.acquire("rule", "draft");

        Assert.assertNotNull(lockId);
        verify(client, times(1)).index(any());
        verify(client, never()).get(any());
        verify(client, never()).delete(any());
    }

    public void testAcquireRetriesAfterConflictAndSucceeds() throws IOException {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, 0); // held very recently -> not stale

        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet())
                .thenThrow(versionConflict())
                .thenReturn(mock(IndexResponse.class));
        when(client.index(any())).thenReturn(indexFuture);

        ResourceLockService service = new ResourceLockService(client);
        String lockId = service.acquire("rule", "draft");

        Assert.assertNotNull(lockId);
        verify(client, times(2)).index(any());
        verify(client, never()).delete(any());
    }

    public void testAcquireStealsStaleLock() throws IOException {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, Constants.LOCK_STALE_THRESHOLD_MILLIS + 1000); // older than the threshold

        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet())
                .thenThrow(versionConflict())
                .thenReturn(mock(IndexResponse.class));
        when(client.index(any())).thenReturn(indexFuture);

        ActionFuture<DeleteResponse> deleteFuture = mock(ActionFuture.class);
        when(deleteFuture.actionGet()).thenReturn(mock(DeleteResponse.class));
        when(client.delete(any())).thenReturn(deleteFuture);

        ResourceLockService service = new ResourceLockService(client);
        String lockId = service.acquire("rule", "draft");

        Assert.assertNotNull(lockId);
        verify(client, times(1)).delete(any());
        verify(client, times(2)).index(any());
    }

    public void testAcquireThrowsAfterExhaustingRetriesOnHeldNonStaleLock() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, 0); // always held recently -> never stolen

        ActionFuture<IndexResponse> indexFuture = mock(ActionFuture.class);
        when(indexFuture.actionGet()).thenThrow(versionConflict());
        when(client.index(any())).thenReturn(indexFuture);

        ResourceLockService service = new ResourceLockService(client);
        IOException e = expectThrows(IOException.class, () -> service.acquire("rule", "draft"));
        Assert.assertTrue(e.getMessage().contains("Timed out"));
        verify(client, never()).delete(any());
    }

    public void testReleaseSwallowsExceptions() {
        Client client = mock(Client.class);
        when(client.delete(any())).thenThrow(new RuntimeException("delete failed"));

        ResourceLockService service = new ResourceLockService(client);
        // Should not throw.
        service.release("some-lock-id");
    }
}
