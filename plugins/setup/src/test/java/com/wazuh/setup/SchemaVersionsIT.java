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
package com.wazuh.setup;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.setup.index.IndexStateManagement;
import com.wazuh.setup.index.SetupStatusIndex;
import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.SchemaStatus;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for the schema drift detection: on a freshly installed cluster every managed
 * index was created from the shipped templates, so every record in {@code .wazuh-setup-status} says
 * {@code up_to_date} with the installed and shipped versions equal, and the readiness marker is
 * {@code ready}.
 *
 * <p>The drift scenario (a cluster whose templates are replaced by a newer version staying {@code
 * running}) needs a node restart with a different plugin build, which this test cluster cannot do.
 * It is covered by the unit tests of {@code SchemaDriftDetector}.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SchemaVersionsIT extends OpenSearchRestTestCase {

    private static final int MAX_WAIT_SECONDS = 120;
    private static final int POLL_INTERVAL_MS = 500;

    /** Release number of 5.0.0, the schema version every template ships with. */
    private static final int RELEASE = 50000;

    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    @Override
    protected boolean preserveDataStreamsUponCompletion() {
        return true;
    }

    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    /**
     * Waits for the readiness marker, written after the detection, so the records are complete.
     *
     * @throws Exception if the marker does not reach {@code ready} within the timeout.
     */
    @Before
    public void waitForReadyMarker() throws Exception {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);
        while (System.currentTimeMillis() < deadline) {
            Map<String, Object> marker = this.getDocument(SetupStatusIndex.SETUP_STATUS_ID);
            if (marker != null
                    && SetupStatusIndex.SETUP_STATUS_READY.equals(marker.get(SetupStatusIndex.KEY_STATUS))) {
                return;
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
        fail("The setup status marker did not reach [ready] in " + MAX_WAIT_SECONDS + " seconds");
    }

    /** Every index family has an up-to-date record: state index, data stream, alias and internal. */
    public void testEveryIndexFamilyIsRecordedUpToDate() throws IOException {
        for (String index :
                new String[] {
                    "wazuh-states-sca",
                    "wazuh-events-v5-security",
                    "wazuh-findings-v5-security",
                    "wazuh-threatintel-rules",
                    ".wazuh-threatintel-vulnerabilities",
                    ".wazuh-settings",
                    SetupStatusIndex.INDEX_NAME
                }) {
            Map<String, Object> record = this.getDocument(index);
            assertNotNull("No record for " + index, record);
            assertEquals(index, record.get(IndexRecord.KEY_INDEX));
            assertEquals(index, RELEASE, ((Number) record.get(IndexRecord.KEY_INSTALLED)).intValue());
            assertEquals(index, RELEASE, ((Number) record.get(IndexRecord.KEY_SHIPPED)).intValue());
            assertEquals(index, RELEASE, ((Number) record.get(IndexRecord.KEY_COMPAT)).intValue());
            assertEquals(index, SchemaStatus.UP_TO_DATE.getValue(), record.get(IndexRecord.KEY_STATUS));
            assertFalse(index + " has a step", record.containsKey(IndexRecord.KEY_STEP));
            assertNotNull(index + " has no updated_at", record.get(IndexRecord.KEY_UPDATED_AT));
        }
    }

    /** The ISM configuration index is versioned by the ISM plugin itself and has no record. */
    public void testIsmConfigIndexHasNoRecord() throws IOException {
        assertNull(this.getDocument(IndexStateManagement.ISM_INDEX_NAME));
    }

    /** The status index carries the record fields in its mapping, and its own versions. */
    public void testStatusIndexMappingHoldsTheRecordFields() throws IOException, ParseException {
        Response response =
                client()
                        .performRequest(new Request("GET", "/" + SetupStatusIndex.INDEX_NAME + "/_mapping"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        for (String field :
                new String[] {
                    IndexRecord.KEY_INDEX,
                    IndexRecord.KEY_INSTALLED,
                    IndexRecord.KEY_SHIPPED,
                    IndexRecord.KEY_COMPAT,
                    IndexRecord.KEY_STATUS,
                    IndexRecord.KEY_STEP,
                    IndexRecord.KEY_UPDATED_AT
                }) {
            assertThat(body, containsString("\"" + field + "\""));
        }
        assertThat(body, containsString("\"schema_version\":" + RELEASE));
    }

    /**
     * Reads a document of the status index.
     *
     * @param id the document id.
     * @return its source, or null when it does not exist.
     */
    private Map<String, Object> getDocument(String id) throws IOException {
        try {
            Response response =
                    client()
                            .performRequest(
                                    new Request("GET", "/" + SetupStatusIndex.INDEX_NAME + "/_doc/" + id));
            Map<String, Object> body = entityAsMap(response);
            @SuppressWarnings("unchecked")
            Map<String, Object> source = (Map<String, Object>) body.get("_source");
            return source;
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return null;
            }
            throw e;
        }
    }
}
