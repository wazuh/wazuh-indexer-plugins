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

import org.apache.logging.log4j.Level;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.engine.DocumentMissingException;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.RemoteTransportException;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.Assert;
import org.junit.Before;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.CapturingAppender;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;

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

    /** The service reads its retry budget and stale threshold from the plugin settings. */
    @Before
    public void setUpSettings() {
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);
    }

    /** Header the security plugin uses to carry the authenticated user across the transport layer. */
    private static final String SECURITY_USER_HEADER = "_opendistro_security_user_info";

    /** Version of the lock document the mocked GET reports, which a steal must be conditional on. */
    private static final long SEEN_SEQ_NO = 5;

    private static final long SEEN_PRIMARY_TERM = 1;

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
        when(getResponse.getSeqNo()).thenReturn(SEEN_SEQ_NO);
        when(getResponse.getPrimaryTerm()).thenReturn(SEEN_PRIMARY_TERM);
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
        mockLockGet(client, PluginSettings.getInstance().getResourceLockStaleThresholdMillis() + 1000);

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
        mockLockGet(
                client, PluginSettings.getInstance().getResourceLockStaleThresholdMillis() + 1000, observe);
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

    public void testTryAcquireOnceTakesAFreeLock() {
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
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);

        Assert.assertTrue(future.actionGet());
        verify(client, times(1)).index(any(IndexRequest.class), any(ActionListener.class));
    }

    /** A lock held and renewed by someone else is reported as taken at once, with no retries. */
    public void testTryAcquireOnceReportsAHeldLockWithoutRetrying() {
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
        ThreadPool threadPool = immediateThreadPool();

        ResourceLockService service = new ResourceLockService(client, threadPool);
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);

        Assert.assertFalse(future.actionGet());
        verify(client, times(1)).index(any(IndexRequest.class), any(ActionListener.class));
        verify(client, never()).delete(any(DeleteRequest.class), any(ActionListener.class));
        verify(threadPool, never()).schedule(any(Runnable.class), any(TimeValue.class), anyString());
    }

    /** A lock whose holder stopped renewing it is stolen and taken. */
    public void testTryAcquireOnceStealsAStaleLock() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, PluginSettings.getInstance().getResourceLockStaleThresholdMillis() + 1000);
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
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);

        Assert.assertTrue(future.actionGet());
        ArgumentCaptor<DeleteRequest> delete = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(client, times(1)).delete(delete.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The steal only deletes the version read as stale",
                SEEN_SEQ_NO,
                delete.getValue().ifSeqNo());
        Assert.assertEquals(SEEN_PRIMARY_TERM, delete.getValue().ifPrimaryTerm());
        verify(client, times(2)).index(any(IndexRequest.class), any(ActionListener.class));
    }

    /** Mocks an acquire that succeeds and hands back the given version of the lock document. */
    private static void mockAcquireReturning(Client client, long seqNo, long primaryTerm) {
        IndexResponse response = mock(IndexResponse.class);
        when(response.getSeqNo()).thenReturn(seqNo);
        when(response.getPrimaryTerm()).thenReturn(primaryTerm);
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onResponse(response);
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));
    }

    /** A renewal response carrying the given version of the lock document. */
    private static UpdateResponse updateResponse(long seqNo, long primaryTerm) {
        UpdateResponse response = mock(UpdateResponse.class);
        when(response.getSeqNo()).thenReturn(seqNo);
        when(response.getPrimaryTerm()).thenReturn(primaryTerm);
        return response;
    }

    /** Mocks a renewal that succeeds and hands back the given version of the lock document. */
    private static void mockRenewReturning(Client client, long seqNo, long primaryTerm) {
        UpdateResponse response = updateResponse(seqNo, primaryTerm);
        doAnswer(
                        invocation -> {
                            ActionListener<UpdateResponse> l = invocation.getArgument(1);
                            l.onResponse(response);
                            return null;
                        })
                .when(client)
                .update(any(UpdateRequest.class), any(ActionListener.class));
    }

    /**
     * Mocks renewals that stay in flight until the test answers them.
     *
     * @return the listener of each renewal sent, in order.
     */
    private static List<ActionListener<UpdateResponse>> mockRenewalsInFlight(Client client) {
        List<ActionListener<UpdateResponse>> inFlight = new ArrayList<>();
        doAnswer(
                        invocation -> {
                            inFlight.add(invocation.getArgument(1));
                            return null;
                        })
                .when(client)
                .update(any(UpdateRequest.class), any(ActionListener.class));
        return inFlight;
    }

    /** Mocks a release whose delete succeeds. */
    private static void mockReleaseSucceeds(Client client) {
        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> l = invocation.getArgument(1);
                            l.onResponse(mock(DeleteResponse.class));
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any(ActionListener.class));
    }

    /**
     * A renewal only refreshes the document this node took. Unconditional, it would keep alive a lock
     * another node has taken over in the meantime.
     */
    public void testRenewOnlyRefreshesTheVersionThisNodeHolds() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        mockRenewReturning(client, 8, 2);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        service.renew("catalog-sync");

        ArgumentCaptor<UpdateRequest> update = ArgumentCaptor.forClass(UpdateRequest.class);
        verify(client, times(1)).update(update.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The renewal is conditioned on the version taken at acquisition",
                7,
                update.getValue().ifSeqNo());
        Assert.assertEquals(2, update.getValue().ifPrimaryTerm());
    }

    /**
     * Each renewal rewrites the document, so the token has to follow the response. Kept at the one
     * read at acquisition, the second renewal would be rejected against a lock this node still holds.
     */
    public void testRenewFollowsTheVersionOfEachSuccessfulRenewal() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        mockRenewReturning(client, 8, 2);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        service.renew("catalog-sync");
        service.renew("catalog-sync");

        ArgumentCaptor<UpdateRequest> update = ArgumentCaptor.forClass(UpdateRequest.class);
        verify(client, times(2)).update(update.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The second renewal uses the version the first one returned",
                8,
                update.getAllValues().get(1).ifSeqNo());
    }

    /**
     * A renewal rejected because the lock changed hands tells the caller, which is the only way the
     * holder finds out: nothing else reports it, and every later renewal would fail the same way.
     */
    public void testRenewReportsTheLockAsLostOnAVersionConflict() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        doAnswer(
                        invocation -> {
                            ActionListener<UpdateResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .when(client)
                .update(any(UpdateRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        AtomicReference<Boolean> lost = new AtomicReference<>(false);
        service.renew("catalog-sync", () -> lost.set(true));

        Assert.assertTrue("The holder is told it no longer holds the lock", lost.get());
    }

    /**
     * A renewal that has not landed when the next one is due is not doubled. Sent with the same
     * version, the second one would be rejected once the first lands, and the holder would give up a
     * lock it still holds as if another node had taken it over.
     */
    public void testRenewIsNotSentWhileThePreviousOneIsInFlight() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        List<ActionListener<UpdateResponse>> inFlight = mockRenewalsInFlight(client);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        AtomicReference<Boolean> lost = new AtomicReference<>(false);
        service.renew("catalog-sync", () -> lost.set(true));
        service.renew("catalog-sync", () -> lost.set(true));

        verify(client, times(1)).update(any(UpdateRequest.class), any(ActionListener.class));

        inFlight.get(0).onResponse(updateResponse(8, 2));
        service.renew("catalog-sync", () -> lost.set(true));

        ArgumentCaptor<UpdateRequest> update = ArgumentCaptor.forClass(UpdateRequest.class);
        verify(client, times(2)).update(update.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The next renewal carries the version the first one wrote",
                8,
                update.getAllValues().get(1).ifSeqNo());
        Assert.assertFalse("The lock is still this node's", lost.get());
    }

    /**
     * A renewal that fails for another reason than the lock changing hands, such as a write rejected
     * under load, does not report the lock as lost, and does not keep the next renewal from being
     * sent.
     */
    public void testFailedRenewalDoesNotReportTheLockAsLostNorBlockTheNextOne() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        List<ActionListener<UpdateResponse>> inFlight = mockRenewalsInFlight(client);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        AtomicReference<Boolean> lost = new AtomicReference<>(false);
        service.renew("catalog-sync", () -> lost.set(true));
        inFlight.get(0).onFailure(new OpenSearchRejectedExecutionException("rejected execution"));
        service.renew("catalog-sync", () -> lost.set(true));

        ArgumentCaptor<UpdateRequest> update = ArgumentCaptor.forClass(UpdateRequest.class);
        verify(client, times(2)).update(update.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The failed renewal wrote nothing, so the version is unchanged",
                7,
                update.getAllValues().get(1).ifSeqNo());
        Assert.assertFalse(lost.get());
    }

    /**
     * A renewal finding the document gone reports the lock as lost: a renewal never creates the
     * document, so no later one can succeed.
     */
    public void testRenewReportsTheLockAsLostWhenItsDocumentIsGone() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        doAnswer(
                        invocation -> {
                            ActionListener<UpdateResponse> l = invocation.getArgument(1);
                            l.onFailure(
                                    new DocumentMissingException(
                                            new ShardId(Constants.INDEX_RESOURCE_LOCKS, "uuid", 0), "catalog-sync"));
                            return null;
                        })
                .when(client)
                .update(any(UpdateRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        AtomicReference<Boolean> lost = new AtomicReference<>(false);
        service.renew("catalog-sync", () -> lost.set(true));

        Assert.assertTrue(lost.get());
    }

    /**
     * A failed renewal logs what made the write fail, not only the node it was sent to, after the
     * {@code Failed to renew lock [<id>]:} text that log monitoring matches the line by.
     */
    public void testFailedRenewalLogsItsCause() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        doAnswer(
                        invocation -> {
                            ActionListener<UpdateResponse> l = invocation.getArgument(1);
                            l.onFailure(
                                    new RemoteTransportException(
                                            "[node-2][127.0.0.1:9300][indices:data/write/update[s]]",
                                            new OpenSearchRejectedExecutionException("rejected execution")));
                            return null;
                        })
                .when(client)
                .update(any(UpdateRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        try (CapturingAppender logs = CapturingAppender.attach(ResourceLockService.class)) {
            service.renew("catalog-sync");

            Assert.assertEquals(
                    List.of("Failed to renew lock [catalog-sync]: rejected execution"),
                    logs.messages(Level.WARN));
        }
    }

    /**
     * The release that closes the pass is still conditional after a renewal reported the lock lost.
     * Dropping the version there would leave the delete unconditional, which is the one case this
     * guard exists for: the holder would remove the new holder's lock on its way out.
     */
    public void testReleaseStaysConditionalAfterARenewalReportedTheLockLost() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        doAnswer(
                        invocation -> {
                            ActionListener<UpdateResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .when(client)
                .update(any(UpdateRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());
        service.renew("catalog-sync", () -> {});

        service.release("catalog-sync");

        ArgumentCaptor<DeleteRequest> delete = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(client, times(1)).delete(delete.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The release is still conditioned on the version this node took",
                7,
                delete.getValue().ifSeqNo());
    }

    /**
     * The release only deletes the version this node holds. Unconditional, a holder that lost the
     * lock deletes the new holder's and leaves the slot free while a pass is still running.
     */
    public void testReleaseOnlyDeletesTheVersionThisNodeHolds() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        mockRenewReturning(client, 8, 2);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());
        service.renew("catalog-sync");

        service.release("catalog-sync");

        ArgumentCaptor<DeleteRequest> delete = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(client, times(1)).delete(delete.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The release uses the version the last renewal returned", 8, delete.getValue().ifSeqNo());
        Assert.assertEquals(2, delete.getValue().ifPrimaryTerm());
    }

    /**
     * A lock this node never took carries no version, so the delete stays unconditional. This is the
     * path the resource-creation locks take, and their behaviour is unchanged.
     */
    public void testReleaseOfALockThisNodeNeverTookIsUnconditional() {
        Client client = mock(Client.class);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        service.release("some-other-lock");

        ArgumentCaptor<DeleteRequest> delete = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(client, times(1)).delete(delete.capture(), any(ActionListener.class));
        Assert.assertEquals(SequenceNumbers.UNASSIGNED_SEQ_NO, delete.getValue().ifSeqNo());
    }

    /**
     * A release requested while a renewal is in flight waits for it and deletes the version it wrote.
     * Sent right away, the delete would carry the version the renewal replaces, be rejected once the
     * renewal lands, and leave the lock behind, held by nobody, until it goes stale.
     */
    public void testReleaseWaitsForTheRenewalInFlightAndDeletesTheVersionItWrote() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        List<ActionListener<UpdateResponse>> inFlight = mockRenewalsInFlight(client);
        mockReleaseSucceeds(client);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());
        service.renew("catalog-sync");

        AtomicReference<Boolean> released = new AtomicReference<>(false);
        service.release("catalog-sync", () -> released.set(true));

        verify(client, never()).delete(any(DeleteRequest.class), any(ActionListener.class));
        Assert.assertFalse(released.get());

        inFlight.get(0).onResponse(updateResponse(8, 2));

        ArgumentCaptor<DeleteRequest> delete = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(client, times(1)).delete(delete.capture(), any(ActionListener.class));
        Assert.assertEquals(
                "The release deletes the version the renewal wrote", 8, delete.getValue().ifSeqNo());
        Assert.assertTrue(released.get());
    }

    /**
     * A release waiting for a renewal is still sent when that renewal fails, conditioned on the
     * version this node last wrote. Left waiting, its caller would never learn the lock was released.
     */
    public void testReleaseWaitingForARenewalIsSentWhenTheRenewalFails() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        List<ActionListener<UpdateResponse>> inFlight = mockRenewalsInFlight(client);
        mockReleaseSucceeds(client);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());
        service.renew("catalog-sync");
        AtomicReference<Boolean> released = new AtomicReference<>(false);
        service.release("catalog-sync", () -> released.set(true));

        inFlight.get(0).onFailure(versionConflict());

        ArgumentCaptor<DeleteRequest> delete = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(client, times(1)).delete(delete.capture(), any(ActionListener.class));
        Assert.assertEquals(7, delete.getValue().ifSeqNo());
        Assert.assertTrue(released.get());
    }

    /**
     * A lock this node never took is not renewed. Its document, if any, is another node's, and an
     * unconditional update would keep that lock alive on its behalf.
     */
    public void testRenewOfALockThisNodeNeverTookIsNotSent() {
        Client client = mock(Client.class);
        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());

        service.renew("catalog-sync");

        verify(client, never()).update(any(UpdateRequest.class), any(ActionListener.class));
    }

    /**
     * A renewal that runs after the release, such as one already started when its task was cancelled
     * at the end of the pass, is not sent: landing before the delete, it would get it rejected.
     */
    public void testRenewAfterTheReleaseIsNotSent() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        mockReleaseSucceeds(client);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());
        service.release("catalog-sync");

        service.renew("catalog-sync");

        verify(client, never()).update(any(UpdateRequest.class), any(ActionListener.class));
    }

    /** Renewal updates the existing document, so it can never create a lock nobody holds. */
    public void testRenewUpdatesTheLockDocument() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockAcquireReturning(client, 7, 2);
        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);
        Assert.assertTrue(future.actionGet());

        service.renew("catalog-sync");

        verify(client, times(1)).update(any(UpdateRequest.class), any(ActionListener.class));
        // The one index request is the acquisition.
        verify(client, times(1)).index(any(IndexRequest.class), any(ActionListener.class));
    }

    /** The release callback runs even when the delete fails, so its caller is never left waiting. */
    public void testReleaseRunsCallbackWhenDeleteFails() {
        Client client = mock(Client.class);
        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> l = invocation.getArgument(1);
                            l.onFailure(new RuntimeException("delete failed"));
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any(ActionListener.class));
        AtomicReference<Boolean> released = new AtomicReference<>(false);

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        service.release("catalog-sync", () -> released.set(true));

        Assert.assertTrue(released.get());
    }

    /**
     * Two callers see the same stale lock. The second one to delete it finds a newer version, the
     * lock the first caller has just created, so its delete fails and it reports the lock as held,
     * instead of deleting that lock and taking it too.
     */
    public void testTryAcquireOnceLosingTheStealToAnotherCallerReportsTheLockAsHeld() {
        Client client = mock(Client.class);
        mockLockIndexExists(client);
        mockLockGet(client, PluginSettings.getInstance().getResourceLockStaleThresholdMillis() + 1000);
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .when(client)
                .index(any(IndexRequest.class), any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            ActionListener<DeleteResponse> l = invocation.getArgument(1);
                            l.onFailure(versionConflict());
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any(ActionListener.class));

        ResourceLockService service = new ResourceLockService(client, immediateThreadPool());
        PlainActionFuture<Boolean> future = new PlainActionFuture<>();
        service.tryAcquireOnce("catalog-sync", future);

        Assert.assertFalse(future.actionGet());
        verify(client, times(1)).index(any(IndexRequest.class), any(ActionListener.class));
    }
}
