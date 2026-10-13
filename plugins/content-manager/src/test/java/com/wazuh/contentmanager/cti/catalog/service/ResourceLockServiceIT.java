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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateAction;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.FilterClient;
import org.junit.After;
import org.junit.Before;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for the named locks of {@link ResourceLockService} against a real lock index,
 * so the version checks that renewing and releasing rely on are applied by the node, not by a mock.
 *
 * <p>Renewals go through a client that holds back their answers until the test passes them on. The
 * node has already applied the write, but the holder has not heard back yet: the window a renewal
 * stuck behind a busy write queue keeps open for longer than the renewal interval.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ResourceLockServiceIT extends OpenSearchIntegTestCase {

    private static final TimeValue TIMEOUT = TimeValue.timeValueSeconds(30);

    /** Each test takes a lock of its own, never the one the catalog sync of the cluster takes. */
    private String lockId;

    @Before
    public void setUpLock() {
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);
        this.lockId = "lock-it-" + randomAlphaOfLength(8).toLowerCase(Locale.ROOT);
    }

    @After
    public void deleteLock() {
        client()
                .prepareDelete(Constants.INDEX_RESOURCE_LOCKS, this.lockId)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }

    /**
     * A renewal due while the previous one is unanswered is not sent. Sent, it would carry the
     * version the first one replaced and be rejected by it, and the holder would give up a lock it
     * still holds as if another node had taken it over.
     */
    public void testRenewalDueWhileThePreviousOneIsUnansweredKeepsTheLock() throws Exception {
        HoldingClient client = new HoldingClient(client());
        ResourceLockService service = new ResourceLockService(client, client.threadPool());
        assertTrue(this.take(service));
        long taken = this.lockSeqNo();

        AtomicBoolean lost = new AtomicBoolean();
        service.renew(this.lockId, () -> lost.set(true));
        assertBusy(() -> assertEquals("The node applied the renewal", taken + 1, this.lockSeqNo()));
        service.renew(this.lockId, () -> lost.set(true));
        client.answerRenewals();

        assertFalse("This node's own renewal is not a takeover", lost.get());

        // The next renewal carries the version the first one wrote, and lands.
        service.renew(this.lockId, () -> lost.set(true));
        assertBusy(() -> assertEquals(taken + 2, this.lockSeqNo()));
        client.answerRenewals();
        assertFalse(lost.get());
        assertEquals(
                "The renewal due while the first was unanswered was not sent", 2, client.renewalsSent());
    }

    /**
     * A release requested while a renewal is unanswered deletes the lock once the renewal is
     * answered, with the version it wrote. Sent right away with the previous version, the delete
     * would be rejected by that renewal, and the lock would stay behind, held by nobody, until it
     * went stale.
     */
    public void testReleaseWhileARenewalIsUnansweredDeletesTheLock() throws Exception {
        HoldingClient client = new HoldingClient(client());
        ResourceLockService service = new ResourceLockService(client, client.threadPool());
        assertTrue(this.take(service));
        long taken = this.lockSeqNo();
        service.renew(this.lockId, () -> {});
        assertBusy(() -> assertEquals(taken + 1, this.lockSeqNo()));

        PlainActionFuture<Void> released = PlainActionFuture.newFuture();
        service.release(this.lockId, () -> released.onResponse(null));
        client.answerRenewals();
        released.actionGet(TIMEOUT);

        assertFalse(
                "The lock is released, not left behind",
                client().prepareGet(Constants.INDEX_RESOURCE_LOCKS, this.lockId).get().isExists());
    }

    /**
     * A lock another node took over is neither renewed nor deleted by the node that lost it: the
     * renewal is rejected and reports the loss, and the release leaves the new holder's lock alone.
     */
    public void testLockTakenOverIsNeitherRenewedNorDeleted() throws Exception {
        ResourceLockService service = new ResourceLockService(client(), client().threadPool());
        assertTrue(this.take(service));
        long newHolder =
                client()
                        .prepareIndex(Constants.INDEX_RESOURCE_LOCKS)
                        .setId(this.lockId)
                        .setSource(Map.of("acquired_at", Instant.now().toEpochMilli()))
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .get()
                        .getSeqNo();

        PlainActionFuture<Void> lost = PlainActionFuture.newFuture();
        service.renew(this.lockId, () -> lost.onResponse(null));
        lost.actionGet(TIMEOUT);
        PlainActionFuture<Void> released = PlainActionFuture.newFuture();
        service.release(this.lockId, () -> released.onResponse(null));
        released.actionGet(TIMEOUT);

        assertEquals("The new holder's lock is untouched", newHolder, this.lockSeqNo());
    }

    /** A renewal that finds the lock document gone reports the lock as lost. */
    public void testRenewalOfADeletedLockReportsItLost() throws Exception {
        ResourceLockService service = new ResourceLockService(client(), client().threadPool());
        assertTrue(this.take(service));
        client()
                .prepareDelete(Constants.INDEX_RESOURCE_LOCKS, this.lockId)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();

        PlainActionFuture<Void> lost = PlainActionFuture.newFuture();
        service.renew(this.lockId, () -> lost.onResponse(null));
        lost.actionGet(TIMEOUT);
    }

    private boolean take(ResourceLockService service) {
        PlainActionFuture<Boolean> acquired = PlainActionFuture.newFuture();
        service.tryAcquireOnce(this.lockId, acquired);
        return acquired.actionGet(TIMEOUT);
    }

    private long lockSeqNo() {
        return client().prepareGet(Constants.INDEX_RESOURCE_LOCKS, this.lockId).get().getSeqNo();
    }

    /**
     * Sends every request on, but holds back the answers to renewals until {@link #answerRenewals()}
     * passes them on.
     */
    private static final class HoldingClient extends FilterClient {
        private final AtomicInteger sent = new AtomicInteger();
        private final AtomicInteger answered = new AtomicInteger();
        private final List<Runnable> held = new ArrayList<>();

        private HoldingClient(Client in) {
            super(in);
        }

        @Override
        protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
                ActionType<Response> action, Request request, ActionListener<Response> listener) {
            if (action != UpdateAction.INSTANCE) {
                super.doExecute(action, request, listener);
                return;
            }
            this.sent.incrementAndGet();
            super.doExecute(
                    action,
                    request,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(Response response) {
                            HoldingClient.this.hold(() -> listener.onResponse(response));
                        }

                        @Override
                        public void onFailure(Exception e) {
                            HoldingClient.this.hold(() -> listener.onFailure(e));
                        }
                    });
        }

        private void hold(Runnable answer) {
            synchronized (this.held) {
                this.held.add(answer);
            }
            this.answered.incrementAndGet();
        }

        /** Waits for the node to answer every renewal sent so far, then passes the answers on. */
        private void answerRenewals() throws Exception {
            assertBusy(() -> assertEquals(this.sent.get(), this.answered.get()));
            List<Runnable> answers;
            synchronized (this.held) {
                answers = new ArrayList<>(this.held);
                this.held.clear();
            }
            answers.forEach(Runnable::run);
        }

        private int renewalsSent() {
            return this.sent.get();
        }
    }
}
