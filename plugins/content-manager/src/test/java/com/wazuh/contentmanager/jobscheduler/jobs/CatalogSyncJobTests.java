package com.wazuh.contentmanager.jobscheduler.jobs;

import com.google.gson.JsonObject;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob.CATEGORY;

public class CatalogSyncJobTests  extends OpenSearchTestCase {

    private CatalogSyncJob job;

    @Mock
    Client client;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private ThreadPool threadpool;
    @Mock private Environment environment;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.job = new CatalogSyncJob(this.client, this.consumersIndex, this.environment, this.threadpool);
    }


    public void testGetCategoryOneWord() {
        JsonObject doc = new JsonObject();
        doc.addProperty(CATEGORY, "security");

        String category = this.job.getCategory(doc);

        Assert.assertEquals("Security", category);
    }

    public void testGetCategoryTwoWords() {
        JsonObject doc = new JsonObject();
        doc.addProperty(CATEGORY, "cloud-services");

        String category = this.job.getCategory(doc);

        Assert.assertEquals("Cloud Services", category);
    }

    public void testGetCategoryThreeWords() {
        JsonObject doc = new JsonObject();
        doc.addProperty(CATEGORY, "cloud-services-aws");

        String category = this.job.getCategory(doc);

        // Assert subcategory is removed
        Assert.assertEquals("Cloud Services", category);
    }
}
