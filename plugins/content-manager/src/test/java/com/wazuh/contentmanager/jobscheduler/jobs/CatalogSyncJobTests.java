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
package com.wazuh.contentmanager.jobscheduler.jobs;

import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

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

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);

        this.catalogSyncJob =
                new CatalogSyncJob(this.client, this.consumersIndex, this.environment, this.threadPool);
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
}
