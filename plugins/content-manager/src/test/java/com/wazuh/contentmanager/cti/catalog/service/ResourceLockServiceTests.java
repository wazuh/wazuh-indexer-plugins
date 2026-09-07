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

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

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

    /** Header the security plugin uses to carry the authenticated user across the transport layer. */
    private static final String SECURITY_USER_HEADER = "_opendistro_security_user_info";

    private static VersionConflictEngineException versionConflict() {
        return new VersionConflictEngineException(
                new ShardId(Constants.INDEX_RESOURCE_LOCKS, "uuid", 0), "lock-id", "already locked");
    }

    /**
     * Mocks the client.admin().indices().exists() chain to report the lock index already exists.
     *
     * @return the mocked indices admin client, so callers can assert on index creation.
     */
    private static IndicesAdminClient mockLockIndexExists(Client client) {
        return mockLockIndexExists(client, () -> {});
    }

    /**
     * Same as {@link #mockLockIndexExists(Client)}, running {@code onExists} when the existence check
     * is issued so tests can observe the thread context in effect at that moment.
     */
    private static IndicesAdminClient mockLockIndexExists(Client client, Runnable onExists) {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        IndicesExistsResponse existsResponse = mock(IndicesExistsResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        doAnswer(
                        invocation -> {
                            onExists.run();
                            ActionListener<IndicesExistsResponse> l = invocation.getArgument(1);
                            l.onResponse(existsResponse);
                            return null;
                        })
                .when(indicesAdminClient)
                .exists(any(), any(ActionListener.class));
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(client.admin()).thenReturn(adminClient);
        return indicesAdminClient;
    }

    /** Mocks async client.get() to report a lock document last acquired {@code ageMillis} ago. */
    private static void mockLockGet(Client client, long ageMillis) {
        mockLockGet(client, ageMillis, () -> {});
    }

    /**
     * Same as {@link #mockLockGet(Client, long)}, running {@code onGet} when the get is issued so
     * tests can observe the thread context in effect at that moment.
     */
    private static void mockLockGet(Client client, long ageMillis, Runnable onGet) {
        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        when(getResponse.getSourceAsMap())
                .thenReturn(Map.of("acquired_at", Instant.now().toEpochMilli() - ageMillis));
        doAnswer(
                        invocation -> {
                            onGet.run();
                            ActionListener<GetResponse> l = invocation.getArgument(1);
                            l.onResponse(getResponse);
                            return null;
                        })
                .when(client)
                .get(any(GetRequest.class), any(ActionListener.class));
    }

    /**
     * Creates a ThreadPool mock that executes scheduled runnables immediately and exposes the given
     * thread context, which the service stashes before every lock operation.
     */
    private static ThreadPool immediateThreadPool(ThreadContext threadContext) {
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(threadPool)
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
        return threadPool;
    }

    /** Creates a ThreadPool mock with an empty thread context. */
    private static ThreadPool immediateThreadPool() {
        return immediateThreadPool(new ThreadContext(Settings.EMPTY));
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

    public void testAcquireDoesNotCreateTheIndexWhenItAlreadyExists() {
        Client client = mock(Client.class);
        IndicesAdminClient indicesAdminClient = mockLockIndexExists(client);
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
        verify(indicesAdminClient, never())
                .create(any(CreateIndexRequest.class), any(ActionListener.class));
    }

    public void testLockOperationsRunWithTheCallerSecurityContextStashed() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader(SECURITY_USER_HEADER, "wazuh-demo");
        // A null entry means the caller identity was not visible when the request was issued, so the
        // operation is evaluated as the plugin instead of as the REST user.
        List<String> observedIdentities = new ArrayList<>();
        Runnable observe = () -> observedIdentities.add(threadContext.getHeader(SECURITY_USER_HEADER));

        Client client = mock(Client.class);
        mockLockIndexExists(client, observe);
        // Stale lock, so the acquire exercises index -> get -> delete -> index.
        mockLockGet(client, Constants.LOCK_STALE_THRESHOLD_MILLIS + 1000, observe);
        doAnswer(
                        invocation -> {
                            observe.run();
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .doAnswer(
                        invocation -> {
                            observe.run();
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            observe.run();
                            ActionListener<DeleteResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(DeleteResponse.class));
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any(ActionListener.class));

        ResourceLockService service =
                new ResourceLockService(client, immediateThreadPool(threadContext));
        PlainActionFuture<String> future = new PlainActionFuture<>();
        service.acquire("rule", "draft", future);
        String lockId = future.actionGet();
        service.release(lockId);

        // exists + index + get + delete (steal) + index (retry) + delete (release).
        Assert.assertEquals(6, observedIdentities.size());
        observedIdentities.forEach(Assert::assertNull);
        // The caller's context is restored once each operation has been issued.
        Assert.assertEquals("wazuh-demo", threadContext.getHeader(SECURITY_USER_HEADER));
    }

    public void testAcquireCallbackRunsWithTheCallerSecurityContext() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putHeader(SECURITY_USER_HEADER, "wazuh-demo");

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

        ResourceLockService service =
                new ResourceLockService(client, immediateThreadPool(threadContext));
        AtomicReference<String> identityInCallback = new AtomicReference<>();
        PlainActionFuture<String> future = new PlainActionFuture<>();
        service.acquire(
                "rule",
                "draft",
                ActionListener.wrap(
                        lockId -> {
                            // The resource creation continues here and must still be authorized as the
                            // REST user, not as the plugin.
                            identityInCallback.set(threadContext.getHeader(SECURITY_USER_HEADER));
                            future.onResponse(lockId);
                        },
                        future::onFailure));

        Assert.assertNotNull(future.actionGet());
        Assert.assertEquals("wazuh-demo", identityInCallback.get());
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
