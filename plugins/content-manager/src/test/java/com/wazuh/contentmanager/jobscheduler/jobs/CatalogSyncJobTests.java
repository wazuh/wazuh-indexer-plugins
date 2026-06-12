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
package com.wazuh.contentmanager.jobscheduler.jobs;

import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.Map;
import java.util.concurrent.ExecutorService;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link CatalogSyncJob} class. This test suite validates the scheduled job
 * responsible for synchronizing the CTI catalog with local indices.
 *
 * <p>Tests verify job state management, job type identification, and execution lifecycle. The
 * catalog sync job is a critical component that ensures local content indices remain synchronized
 * with the remote CTI catalog by periodically fetching and applying updates.
 */
public class CatalogSyncJobTests extends OpenSearchTestCase {

    private CatalogSyncJob catalogSyncJob;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;
    @Mock private ThreadPool threadPool;
    @Mock private EngineService engineService;
    @Mock private GetRequestBuilder getRequestBuilder;
    @Mock private GetResponse getResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);

        this.catalogSyncJob =
                new CatalogSyncJob(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.threadPool,
                        this.engineService);

        when(this.client.prepareGet(Constants.INDEX_SETUP_STATUS, Constants.SETUP_STATUS_DOC_ID))
                .thenReturn(this.getRequestBuilder);
        when(this.getRequestBuilder.get()).thenReturn(this.getResponse);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Test that the {@link CatalogSyncJob#isRunning()} method returns false initially. */
    public void testIsRunningReturnsFalseInitially() {
        boolean isRunning = this.catalogSyncJob.isRunning();

        Assert.assertFalse(isRunning);
    }

    /** Test that the {@link CatalogSyncJob#JOB_TYPE} constant is correctly defined. */
    public void testJobTypeConstant() {
        Assert.assertEquals("consumer-sync-task", CatalogSyncJob.JOB_TYPE);
    }

    /** The setup status marker must be read from the dedicated .wazuh-setup-status index. */
    public void testSetupStatusIndexConstant() {
        Assert.assertEquals(".wazuh-setup-status", Constants.INDEX_SETUP_STATUS);
    }

    /** Setup marker already complete -> waitForSetup returns true on the first check. */
    public void testWaitForSetup_markerComplete_returnsTrue() {
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsMap())
                .thenReturn(Map.of(Constants.KEY_STATUS, Constants.SETUP_STATUS_COMPLETE));

        Assert.assertTrue(this.catalogSyncJob.waitForSetup());
    }

    /** When setup never completes, the synchronization pass is skipped entirely. */
    public void testTrigger_setupIncomplete_skipsSynchronization() {
        ExecutorService sameThreadExecutor = mock(ExecutorService.class);
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(sameThreadExecutor)
                .execute(any(Runnable.class));
        when(this.threadPool.generic()).thenReturn(sameThreadExecutor);

        CatalogSyncJob job = spy(this.catalogSyncJob);
        doReturn(false).when(job).waitForSetup();

        job.trigger();

        verifyNoInteractions(this.consumersIndex);
        Assert.assertFalse("Semaphore must be released after a skipped pass", job.isRunning());
    }
}
