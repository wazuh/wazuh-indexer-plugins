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
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.Assert;

import java.time.Instant;
import java.util.Map;

import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
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
        doAnswer(
                        invocation -> {
                            ActionListener<IndicesExistsResponse> l = invocation.getArgument(1);
                            l.onResponse(existsResponse);
                            return null;
                        })
                .when(indicesAdminClient)
                .exists(any(), any(ActionListener.class));
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(client.admin()).thenReturn(adminClient);
    }

    /** Mocks async client.get() to report a lock document last acquired {@code ageMillis} ago. */
    private static void mockLockGet(Client client, long ageMillis) {
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        when(getResponse.getSourceAsMap())
                .thenReturn(Map.of("acquired_at", Instant.now().toEpochMilli() - ageMillis));
        doAnswer(
                        invocation -> {
                            ActionListener<GetResponse> l = invocation.getArgument(1);
                            l.onResponse(getResponse);
                            return null;
                        })
                .when(client)
                .get(any(GetRequest.class), any(ActionListener.class));
    }

    /** Creates a ThreadPool mock that executes scheduled runnables immediately. */
    private static ThreadPool immediateThreadPool() {
        ThreadPool threadPool = mock(ThreadPool.class);
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(threadPool)
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
        return threadPool;
    }

    public void testAcquireSucceedsImmediatelyWhenNoLockExists() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<String> future = new PlainActionFuture<>();
        service.acquire("rule", "draft", future);

        Assert.assertNotNull(future.actionGet());
        verify(client, times(1)).index(any(IndexRequest.class), any(ActionListener.class));
        verify(client, never()).get(any(GetRequest.class), any(ActionListener.class));
        verify(client, never()).delete(any(DeleteRequest.class), any(ActionListener.class));
    }

    public void testAcquireRetriesAfterConflictAndSucceeds() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, 0);

        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<String> future = new PlainActionFuture<>();
        service.acquire("rule", "draft", future);

        Assert.assertNotNull(future.actionGet());
        verify(client, times(2)).index(any(IndexRequest.class), any(ActionListener.class));
        verify(client, never()).delete(any(DeleteRequest.class), any(ActionListener.class));
    }

    public void testAcquireStealsStaleLock() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, Constants.LOCK_STALE_THRESHOLD_MILLIS + 1000);

        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(DeleteResponse.class));
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<String> future = new PlainActionFuture<>();
        service.acquire("rule", "draft", future);

        Assert.assertNotNull(future.actionGet());
        verify(client, times(1)).delete(any(DeleteRequest.class), any(ActionListener.class));
        verify(client, times(2)).index(any(IndexRequest.class), any(ActionListener.class));
    }

    public void testAcquireFailsAfterExhaustingRetriesOnHeldNonStaleLock() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, 0);

        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<String> future = new PlainActionFuture<>();
        service.acquire("rule", "draft", future);

        Exception e = expectThrows(Exception.class, future::actionGet);
        Throwable cause = e.getCause() != null ? e.getCause() : e;
        Assert.assertTrue(cause.getMessage().contains("Timed out"));
        verify(client, never()).delete(any(DeleteRequest.class), any(ActionListener.class));
    }

    public void testReleaseSwallowsExceptions() {
        Client client = mock(Client.class);
        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> l = invocation.getArgument(1);
                            l.onFailure(new RuntimeException("delete failed"));
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        service.release("some-lock-id");
        verify(client, times(1)).delete(any(DeleteRequest.class), any(ActionListener.class));
    }
}
