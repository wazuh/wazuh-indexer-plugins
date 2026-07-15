/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.rest.it;

import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;

import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Integration test for issue #1345 ("Immediate Recovery When a Feed Update Fails"): the {@code
 * CatalogSyncJob} concurrency guard must reject a request to start a new synchronization pass while
 * one is already running, over the real REST -> transport -> {@code CatalogSyncJob} path (no
 * mocks).
 */
public class CatalogSyncConcurrencyIT extends ContentManagerRestTestCase {

    /**
     * Two POST /update requests fired back-to-back: the first is accepted and starts a pass; the
     * second, landing while that pass is still in flight on the {@code threadPool.generic()}
     * executor, must be rejected with 409 Conflict rather than starting a second concurrent pass.
     *
     * <p>Verifies: a request that wins the guard returns 202 Accepted, and a second request fired
     * immediately after (while that pass is still in flight) returns 409 Conflict with the "already
     * in progress" message, proving the {@code CatalogSyncJob}'s real {@code Semaphore(1)} guard --
     * not a mock -- rejects concurrent runs.
     *
     * <p>The node may already be running a scheduled {@code CatalogSyncJob} pass on startup (and,
     * because the CTI feed is unreachable in the test cluster, its immediate retry), which would make
     * our first request itself land on 409. The assertion is therefore wrapped in {@code assertBusy}:
     * we retry the pair until we observe a window where <em>we</em> win the guard (202) and the
     * immediately-following request is rejected (409).
     *
     * @throws Exception On failure to communicate with OpenSearch or if the guarantee is not observed
     *     within the timeout.
     */
    public void testPostUpdate_concurrentRequests_secondIsRejected() throws Exception {
        assertBusy(
                () -> {
                    // Try to win the guard ourselves. A 409 here means a background pass currently
                    // holds it; not our window -- fail so assertBusy retries.
                    Response first;
                    try {
                        first = this.makeRequest("POST", PluginSettings.UPDATE_URI, "");
                    } catch (ResponseException e) {
                        throw new AssertionError(
                                "A sync pass is already running; retrying to win the guard.", e);
                    }
                    assertEquals(RestStatus.ACCEPTED.getStatus(), this.getStatusCode(first));

                    // We now hold the semaphore. A request fired immediately must be rejected with
                    // 409, proving the real guard (not a mock) is enforced.
                    ResponseException e =
                            expectThrows(
                                    ResponseException.class,
                                    () -> this.makeRequest("POST", PluginSettings.UPDATE_URI, ""));
                    assertEquals(
                            "A second update request landing while the first is still running must be"
                                    + " rejected with 409, proving the real semaphore guard (not a mock) is"
                                    + " enforced",
                            RestStatus.CONFLICT.getStatus(),
                            e.getResponse().getStatusLine().getStatusCode());
                },
                60,
                TimeUnit.SECONDS);
    }
}
