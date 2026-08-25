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
package com.wazuh.contentmanager.utils;

import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Assert;

import java.util.Map;

import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.InOrder;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

/** Unit tests for {@link SetupReadiness}. */
public class SetupReadinessTests extends OpenSearchTestCase {

    private Client client;
    private GetRequestBuilder getRequestBuilder;
    private GetResponse getResponse;
    private SetupReadiness setupReadiness;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.EMPTY);

        this.client = mock(Client.class);
        this.getRequestBuilder = mock(GetRequestBuilder.class);
        this.getResponse = mock(GetResponse.class);

        when(this.client.prepareGet(Constants.INDEX_SETUP_STATUS, Constants.SETUP_STATUS_DOC_ID))
                .thenReturn(this.getRequestBuilder);
        when(this.getRequestBuilder.get()).thenReturn(this.getResponse);

        this.setupReadiness = new SetupReadiness(this.client);
    }

    /**
     * A cluster without the Setup plugin has no marker coming, so there is nothing to wait for: the
     * caller's fallback runs immediately instead of after the full backoff schedule.
     */
    public void testSetupPluginAbsentReturnsFalseWithoutSleeping() throws Exception {
        SetupReadiness readiness = spy(this.setupReadiness);
        doReturn(false).when(readiness).isSetupPluginInstalled();

        Assert.assertFalse(readiness.awaitReady());
        verify(readiness, never()).sleepSeconds(anyLong());
        verify(this.getRequestBuilder, never()).get();
    }

    /** A plugin list that cannot be read is treated as "installed", so the caller still waits. */
    public void testPluginLookupFailureIsTreatedAsInstalled() {
        // The mocked client has no nodes-info stubbing, so the lookup throws.
        Assert.assertTrue(this.setupReadiness.isSetupPluginInstalled());
    }

    /**
     * A failed lookup must not be memoised, or one transient error would pin the answer for the rest
     * of the node's lifetime.
     */
    public void testPluginLookupFailureIsNotCached() {
        Assert.assertTrue(this.setupReadiness.isSetupPluginInstalled());
        Assert.assertTrue(this.setupReadiness.isSetupPluginInstalled());

        // Two calls, two attempts: nothing was cached.
        verify(this.client, times(2)).admin();
    }

    /** The marker already reports ready, so the first check returns true. */
    public void testMarkerReadyReturnsTrue() {
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsMap())
                .thenReturn(Map.of(Constants.KEY_STATUS, Constants.SETUP_STATUS_READY));

        Assert.assertTrue(this.setupReadiness.awaitReady());
    }

    /** A failed Setup boot will not fix itself, so there is nothing to wait for. */
    public void testMarkerFailedReturnsFalseWithoutSleeping() throws Exception {
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsMap())
                .thenReturn(Map.of(Constants.KEY_STATUS, Constants.SETUP_STATUS_FAILED));

        SetupReadiness readiness = spy(this.setupReadiness);
        Assert.assertFalse(readiness.awaitReady());
        verify(readiness, never()).sleepSeconds(anyLong());
    }

    /** A marker that is present but still says running is retried. */
    public void testMarkerRunningIsRetried() throws Exception {
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsMap()).thenReturn(Map.of(Constants.KEY_STATUS, "running"));

        SetupReadiness readiness = spy(this.setupReadiness);
        doNothing().when(readiness).sleepSeconds(anyLong());

        Assert.assertFalse(readiness.awaitReady());
        verify(readiness, times(PluginSettings.getInstance().getSetupWaitMaxRetries()))
                .sleepSeconds(anyLong());
    }

    /**
     * When the marker never becomes ready, the full documented backoff schedule is exhausted (20s,
     * 40s, 80s, 160s = 300s / 5 min worst case) before giving up. {@code sleepSeconds} is stubbed out
     * so the real retry loop runs without actually blocking for five minutes.
     */
    public void testSetupNeverReadyExhaustsFullBackoffScheduleThenGivesUp() throws Exception {
        when(this.getResponse.isExists()).thenReturn(false);

        SetupReadiness readiness = spy(this.setupReadiness);
        doNothing().when(readiness).sleepSeconds(anyLong());

        Assert.assertFalse(
                "Setup never became ready, so awaitReady() must give up", readiness.awaitReady());
        verify(this.getRequestBuilder, times(PluginSettings.getInstance().getSetupWaitMaxRetries() + 1))
                .get();

        InOrder inOrder = Mockito.inOrder(readiness);
        inOrder.verify(readiness).sleepSeconds(20L);
        inOrder.verify(readiness).sleepSeconds(40L);
        inOrder.verify(readiness).sleepSeconds(80L);
        inOrder.verify(readiness).sleepSeconds(160L);
    }

    /** A read failure (marker index absent, shards unassigned) is treated as "not ready yet". */
    public void testReadFailureIsTreatedAsRunning() throws Exception {
        when(this.getRequestBuilder.get()).thenThrow(new RuntimeException("no such index"));

        SetupReadiness readiness = spy(this.setupReadiness);
        doNothing().when(readiness).sleepSeconds(anyLong());

        Assert.assertFalse(readiness.awaitReady());
        verify(readiness, times(PluginSettings.getInstance().getSetupWaitMaxRetries()))
                .sleepSeconds(anyLong());
    }
}
