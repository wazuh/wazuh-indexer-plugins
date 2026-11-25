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
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.setup.index.SetupStatusIndex;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for the OpenSearch operations the schema upgrade relies on, run against the
 * indices the plugin created: a mapping update addressed to a data stream reaches every backing
 * index without rolling it over, a dynamic settings update addressed to the alias of a state index
 * reaches the concrete index behind it while a static one is rejected, a mapping update addressed
 * to a content alias reaches the index behind it, and a rollover creates a write index at the
 * shipped version that ISM manages like the previous one.
 *
 * <p>The upgrade itself runs at boot, after the drift detection, so a cluster that starts at the
 * shipped version never runs it; {@code SchemaUpgraderTests} covers its sequence.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SchemaUpgradeIT extends OpenSearchRestTestCase {

    private static final int MAX_WAIT_SECONDS = 120;
    private static final int POLL_INTERVAL_MS = 500;

    private static final int RELEASE = 50000;
    private static final String METRICS_POLICY = "stream-metrics-policy";

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

    @Before
    public void waitForReadyMarker() throws Exception {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);
        while (System.currentTimeMillis() < deadline) {
            try {
                Response response =
                        client()
                                .performRequest(
                                        new Request(
                                                "GET",
                                                "/"
                                                        + SetupStatusIndex.INDEX_NAME
                                                        + "/_doc/"
                                                        + SetupStatusIndex.SETUP_STATUS_ID));
                @SuppressWarnings("unchecked")
                Map<String, Object> source = (Map<String, Object>) entityAsMap(response).get("_source");
                if (source != null
                        && SetupStatusIndex.SETUP_STATUS_READY.equals(
                                source.get(SetupStatusIndex.KEY_STATUS))) {
                    return;
                }
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() != 404) {
                    throw e;
                }
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
        fail("The setup status marker did not reach [ready] in " + MAX_WAIT_SECONDS + " seconds");
    }

    /**
     * A mapping update addressed to the data stream name is merged into every backing index, the ones
     * created before the update included, and the stream is not rolled over by it.
     */
    public void testMappingUpdateReachesEveryBackingIndexWithoutRollover()
            throws IOException, ParseException {
        String stream = "wazuh-metrics-normalization";
        client().performRequest(new Request("POST", "/" + stream + "/_rollover"));
        long generation = this.generation(stream);
        assertTrue("the stream has not rolled over", generation >= 2);

        Request mapping = new Request("PUT", "/" + stream + "/_mapping");
        mapping.setJsonEntity("{\"properties\": {\"upgrade_check\": {\"type\": \"keyword\"}}}");
        client().performRequest(mapping);

        List<String> backing = this.backingIndices(stream);
        assertTrue(backing.toString(), backing.size() >= 2);
        for (String index : backing) {
            String body = this.body("GET", "/" + index + "/_mapping");
            assertThat(index, body, containsString("\"upgrade_check\""));
        }
        assertEquals("the mapping update rolled the stream over", generation, this.generation(stream));
    }

    /**
     * A settings update addressed to the alias of a state index reaches the concrete index behind it,
     * and a static setting is rejected by OpenSearch, which is why the upgrade filters them out.
     */
    public void testDynamicSettingThroughTheStateAlias() throws IOException, ParseException {
        String index = "wazuh-states-sca";
        Map<String, Object> resolved =
                entityAsMap(client().performRequest(new Request("GET", "/" + index + "/_settings")));
        assertEquals(java.util.Set.of(index + "-a"), resolved.keySet());
        String before = this.setting(index, "refresh_interval");

        Request dynamic = new Request("PUT", "/" + index + "/_settings");
        dynamic.setJsonEntity("{\"index\": {\"refresh_interval\": \"7s\"}}");
        client().performRequest(dynamic);
        assertEquals("7s", this.setting(index, "refresh_interval"));

        Request fixed = new Request("PUT", "/" + index + "/_settings");
        fixed.setJsonEntity("{\"index\": {\"number_of_shards\": 2}}");
        ResponseException rejected =
                expectThrows(ResponseException.class, () -> client().performRequest(fixed));
        assertEquals(400, rejected.getResponse().getStatusLine().getStatusCode());
        assertThat(
                EntityUtils.toString(rejected.getResponse().getEntity(), StandardCharsets.UTF_8),
                containsString("non dynamic settings"));

        Request restore = new Request("PUT", "/" + index + "/_settings");
        restore.setJsonEntity("{\"index\": {\"refresh_interval\": \"" + before + "\"}}");
        client().performRequest(restore);
    }

    /** A mapping update addressed to a content alias is merged into the index behind it. */
    public void testMappingUpdateThroughTheContentAliasReachesThePhysicalIndex()
            throws IOException, ParseException {
        String alias = "wazuh-threatintel-kvdbs";

        Request mapping = new Request("PUT", "/" + alias + "/_mapping");
        mapping.setJsonEntity("{\"properties\": {\"upgrade_check\": {\"type\": \"keyword\"}}}");
        client().performRequest(mapping);

        assertThat(this.body("GET", "/" + alias + "-a/_mapping"), containsString("\"upgrade_check\""));
    }

    /**
     * A rollover creates a write index from the stored template, so it carries the shipped schema
     * version, and ISM attaches the stream's policy to it as it does to every backing index. The
     * previous write index stays managed.
     */
    public void testRolloverCreatesAManagedWriteIndexAtTheShippedVersion()
            throws IOException, ParseException, InterruptedException {
        String stream = "wazuh-metrics-comms-v4";
        List<String> before = this.backingIndices(stream);
        String previous = before.get(before.size() - 1);

        Map<String, Object> rollover =
                entityAsMap(client().performRequest(new Request("POST", "/" + stream + "/_rollover")));
        assertEquals(Boolean.TRUE, rollover.get("rolled_over"));
        String current = (String) rollover.get("new_index");

        String mapping = this.body("GET", "/" + current + "/_mapping");
        assertThat(mapping, containsString("\"schema_version\":" + RELEASE));

        assertThat(this.explain(current, METRICS_POLICY), containsString(METRICS_POLICY));
        assertThat(this.explain(previous, METRICS_POLICY), containsString(METRICS_POLICY));
    }

    private long generation(String stream) throws IOException {
        Map<String, Object> body =
                entityAsMap(client().performRequest(new Request("GET", "/_data_stream/" + stream)));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> streams = (List<Map<String, Object>>) body.get("data_streams");
        return ((Number) streams.get(0).get("generation")).longValue();
    }

    private List<String> backingIndices(String stream) throws IOException {
        Map<String, Object> body =
                entityAsMap(client().performRequest(new Request("GET", "/_data_stream/" + stream)));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> streams = (List<Map<String, Object>>) body.get("data_streams");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> indices = (List<Map<String, Object>>) streams.get(0).get("indices");
        return indices.stream().map(index -> (String) index.get("index_name")).toList();
    }

    private String setting(String index, String name) throws IOException {
        Map<String, Object> body =
                entityAsMap(client().performRequest(new Request("GET", "/" + index + "/_settings")));
        @SuppressWarnings("unchecked")
        Map<String, Object> resolved = (Map<String, Object>) body.values().iterator().next();
        @SuppressWarnings("unchecked")
        Map<String, Object> settings = (Map<String, Object>) resolved.get("settings");
        @SuppressWarnings("unchecked")
        Map<String, Object> indexSettings = (Map<String, Object>) settings.get("index");
        return (String) indexSettings.get(name);
    }

    /** Polls the ISM explain API of an index until it names the policy, or the wait runs out. */
    private String explain(String index, String policy)
            throws IOException, ParseException, InterruptedException {
        String explain = "";
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);
        while (System.currentTimeMillis() < deadline) {
            explain = this.body("GET", "/_plugins/_ism/explain/" + index);
            if (explain.contains(policy)) {
                return explain;
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
        return explain;
    }

    private String body(String method, String endpoint) throws IOException, ParseException {
        return EntityUtils.toString(
                client().performRequest(new Request(method, endpoint)).getEntity(), StandardCharsets.UTF_8);
    }
}
