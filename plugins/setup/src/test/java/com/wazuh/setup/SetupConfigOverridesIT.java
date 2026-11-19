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
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.client.Request;
import org.opensearch.client.ResponseException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Integration tests for the configuration file of the plugin. The test cluster starts with the
 * {@code setup.yml} and the policy files of {@code src/test/resources/setup-config/overrides}, which
 * override settings of the events and stateful index templates and replace two ISM policies.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SetupConfigOverridesIT extends OpenSearchRestTestCase {

    private static final String SETUP_STATUS = "/.wazuh-setup-status/_doc/setup-status";
    private static final String EVENTS_STREAM = "wazuh-events-v5-security";
    private static final String FINDINGS_STREAM = "wazuh-findings-v5-security";
    private static final String EVENTS_TEMPLATE = "templates/streams/events.json";

    private static final String ACTIVE_RESPONSES_STREAM = "wazuh-active-responses";
    private static final String ACTIVE_RESPONSES_POLICY = "stream-active-responses-policy";
    private static final String ACTIVE_RESPONSES_DESCRIPTION =
            "Integration test policy for the active responses data stream.";

    private static final String AUDIT_STREAM = "security-auditlogs";
    private static final String AUDIT_POLICY = "security-auditlogs-policy";
    private static final String AUDIT_DESCRIPTION =
            "Integration test policy for the security audit log data stream.";

    private static final String SHARDS = "index.number_of_shards";
    private static final String DURABILITY = "index.translog.durability";
    private static final String REFRESH = "index.refresh_interval";

    private static final int MAX_WAIT_SECONDS = 120;

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
     * Waits until the plugin reports that it has initialized the cluster.
     *
     * @throws Exception if the status is not ready in time.
     */
    @Before
    public void waitForPluginInitialization() throws Exception {
        OpenSearchTestCase.assertBusy(
                () -> {
                    try {
                        Assert.assertEquals(
                                "ready", SetupConfigOverridesIT.source(SetupConfigOverridesIT.get(SETUP_STATUS)).get("status"));
                    } catch (ResponseException e) {
                        throw new AssertionError("The setup status is not available yet", e);
                    }
                },
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Performs a GET request and parses the response.
     *
     * @param endpoint the endpoint.
     * @return the response body.
     * @throws IOException if the request fails.
     */
    private static Map<String, Object> get(String endpoint) throws IOException {
        return OpenSearchRestTestCase.entityAsMap(
                OpenSearchRestTestCase.client().performRequest(new Request("GET", endpoint)));
    }

    /**
     * Returns an object nested in a parsed response.
     *
     * @param map the parent object.
     * @param key key of the nested object.
     * @return the nested object.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Map<String, Object> map, String key) {
        return (Map<String, Object>) map.get(key);
    }

    /**
     * Flattens nested settings into keys such as {@code index.translog.durability}.
     *
     * @param nested the settings as the template API returns them.
     * @param prefix key of the parent object, empty at the root.
     * @param flat the map the flattened settings are added to.
     */
    @SuppressWarnings("unchecked")
    private static void flatten(Map<String, Object> nested, String prefix, Map<String, Object> flat) {
        for (Map.Entry<String, Object> entry : nested.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            if (entry.getValue() instanceof Map) {
                SetupConfigOverridesIT.flatten((Map<String, Object>) entry.getValue(), key, flat);
            } else {
                flat.put(key, entry.getValue());
            }
        }
    }

    /**
     * Returns the source of a document read with the get API.
     *
     * @param response the parsed response.
     * @return the document.
     */
    private static Map<String, Object> source(Map<String, Object> response) {
        return SetupConfigOverridesIT.object(response, "_source");
    }

    /**
     * Reads the settings of the indices behind a name, keyed by index setting.
     *
     * @param name an index, an alias or a data stream.
     * @return the settings of each index, by index name.
     * @throws IOException if the request fails.
     */
    private static Map<String, Object> settings(String name) throws IOException {
        return SetupConfigOverridesIT.get("/" + name + "/_settings?flat_settings=true");
    }

    /**
     * Reads one setting of the only index behind a name.
     *
     * @param name an index, or a data stream with one backing index.
     * @param setting the index setting.
     * @return the value, or null when the index does not set it.
     * @throws IOException if the request fails.
     */
    private static Object setting(String name, String setting) throws IOException {
        Map<String, Object> indices = SetupConfigOverridesIT.settings(name);
        Assert.assertEquals(indices.keySet().toString(), 1, indices.size());
        String index = indices.keySet().iterator().next();
        return SetupConfigOverridesIT.object(SetupConfigOverridesIT.object(indices, index), "settings")
                .get(setting);
    }

    /**
     * Reads the description of a stored ISM policy.
     *
     * @param policy id of the policy.
     * @return the description.
     * @throws IOException if the request fails.
     */
    private static Object storedDescription(String policy) throws IOException {
        return SetupConfigOverridesIT.object(
                        SetupConfigOverridesIT.get("/_plugins/_ism/policies/" + policy), "policy")
                .get("description");
    }

    /**
     * Waits until the given number of backing indices of a data stream are managed by a policy with
     * the given description. Each managed index runs its own copy of the policy, so the description
     * tells which policy it started on.
     *
     * @param stream name of the data stream.
     * @param policy id of the policy.
     * @param description description of the policy the indices must run.
     * @param backingIndices number of backing indices expected.
     * @throws Exception if the indices are not managed in time.
     */
    private static void assertManagedBy(
            String stream, String policy, String description, int backingIndices) throws Exception {
        OpenSearchTestCase.assertBusy(
                () -> {
                    Map<String, Object> explain =
                            SetupConfigOverridesIT.get(
                                    "/_plugins/_ism/explain/.ds-" + stream + "-*?show_policy=true");
                    List<String> indices =
                            explain.keySet().stream().filter(key -> key.startsWith(".ds-" + stream)).toList();
                    Assert.assertEquals(explain.toString(), backingIndices, indices.size());
                    for (String index : indices) {
                        Map<String, Object> managed = SetupConfigOverridesIT.object(explain, index);
                        Assert.assertEquals(explain.toString(), policy, managed.get("policy_id"));
                        Assert.assertNotNull(explain.toString(), managed.get("policy"));
                        Assert.assertEquals(
                                explain.toString(),
                                description,
                                SetupConfigOverridesIT.object(managed, "policy").get("description"));
                    }
                },
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * The index template of a data stream holds the overridden settings, and the mappings bundled in
     * the plugin, untouched.
     *
     * @throws IOException if a request fails or the bundled template cannot be read.
     */
    @SuppressWarnings("unchecked")
    public void testStreamTemplateSettingsAndMappings() throws IOException {
        Map<String, Object> response =
                SetupConfigOverridesIT.get("/_index_template/" + EVENTS_STREAM + "-template");
        Map<String, Object> stored =
                SetupConfigOverridesIT.object(
                        SetupConfigOverridesIT.object(
                                ((List<Map<String, Object>>) response.get("index_templates")).get(0),
                                "index_template"),
                        "template");
        Map<String, Object> bundled;
        try (InputStream is =
                SetupConfigOverridesIT.class.getClassLoader().getResourceAsStream(EVENTS_TEMPLATE)) {
            bundled =
                    SetupConfigOverridesIT.object(new ObjectMapper().readValue(is, Map.class), "template");
        }

        Map<String, Object> settings = new HashMap<>();
        SetupConfigOverridesIT.flatten(SetupConfigOverridesIT.object(stored, "settings"), "", settings);
        Assert.assertEquals("2", settings.get(SHARDS));
        Assert.assertEquals("request", settings.get(DURABILITY));
        Assert.assertEquals("2s", settings.get(REFRESH));
        Assert.assertEquals(bundled.get("mappings"), stored.get("mappings"));
    }

    /**
     * The backing indices of the events streams have the overridden settings. The streams of another
     * template keep the bundled ones.
     *
     * @throws IOException if a request fails.
     */
    public void testBackingIndexSettings() throws IOException {
        Assert.assertEquals("2", SetupConfigOverridesIT.setting(EVENTS_STREAM, SHARDS));
        Assert.assertEquals("request", SetupConfigOverridesIT.setting(EVENTS_STREAM, DURABILITY));

        Assert.assertEquals("1", SetupConfigOverridesIT.setting(FINDINGS_STREAM, SHARDS));
        Assert.assertEquals("async", SetupConfigOverridesIT.setting(FINDINGS_STREAM, DURABILITY));
    }

    /**
     * A key for a group reaches every template of the group, except the one a more specific key
     * names. The other groups are not reached.
     *
     * @throws IOException if a request fails.
     */
    public void testMostSpecificKeyWins() throws IOException {
        Assert.assertEquals("45s", SetupConfigOverridesIT.setting("wazuh-states-sca", REFRESH));
        Assert.assertEquals("30s", SetupConfigOverridesIT.setting("wazuh-states-fim-files", REFRESH));
        Assert.assertEquals(
                "30s", SetupConfigOverridesIT.setting("wazuh-states-vulnerabilities", REFRESH));
        Assert.assertEquals("2s", SetupConfigOverridesIT.setting(EVENTS_STREAM, REFRESH));
    }

    /**
     * A replaced policy is stored with the content of its file, under the id of the default policy.
     * The policies that are not replaced are the bundled ones.
     *
     * @throws IOException if a request fails.
     */
    public void testStoredPolicies() throws IOException {
        Assert.assertEquals(
                ACTIVE_RESPONSES_DESCRIPTION,
                SetupConfigOverridesIT.storedDescription(ACTIVE_RESPONSES_POLICY));
        Assert.assertEquals(AUDIT_DESCRIPTION, SetupConfigOverridesIT.storedDescription(AUDIT_POLICY));

        String events = (String) SetupConfigOverridesIT.storedDescription("stream-events-policy");
        Assert.assertTrue(events, events.startsWith("ISM policy for events data streams."));
    }

    /**
     * The first backing index of a stream the plugin creates is managed by the replaced policy, and
     * so is the backing index a rollover creates.
     *
     * @throws Exception if a request fails or the indices are not managed in time.
     */
    public void testReplacedPolicyManagesTheStreamAcrossARollover() throws Exception {
        SetupConfigOverridesIT.assertManagedBy(
                ACTIVE_RESPONSES_STREAM, ACTIVE_RESPONSES_POLICY, ACTIVE_RESPONSES_DESCRIPTION, 1);

        OpenSearchRestTestCase.client()
                .performRequest(new Request("POST", "/" + ACTIVE_RESPONSES_STREAM + "/_rollover"));

        SetupConfigOverridesIT.assertManagedBy(
                ACTIVE_RESPONSES_STREAM, ACTIVE_RESPONSES_POLICY, ACTIVE_RESPONSES_DESCRIPTION, 2);
    }

    /**
     * The audit log stream is created by the security plugin, later and from its own template. Its
     * backing indices are managed by the replaced audit log policy, also after a rollover. The test
     * cluster has no security plugin, so the test creates the template and the stream as it does.
     *
     * <p>The policy file of this test writes its {@code ism_template} as a single template instead
     * of a list, and ISM attaches every backing index of this stream through it.
     *
     * @throws Exception if a request fails or the indices are not managed in time.
     */
    public void testReplacedAuditLogPolicyManagesTheStreamAcrossARollover() throws Exception {
        Request template = new Request("PUT", "/_index_template/opensearch-security-auditlog");
        template.setJsonEntity(
                """
                {
                  "index_patterns": ["security-auditlogs"],
                  "data_stream": {"timestamp_field": {"name": "@timestamp"}},
                  "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0}}
                }
                """);
        OpenSearchRestTestCase.client().performRequest(template);
        // Index State Management finds the policies with a search, as its list API does: the policy
        // stored at startup has to be searchable before the stream is created, or the stream stays
        // unmanaged.
        OpenSearchTestCase.assertBusy(
                () ->
                        Assert.assertTrue(
                                SetupConfigOverridesIT.get("/_plugins/_ism/policies?size=50")
                                        .toString()
                                        .contains(AUDIT_DESCRIPTION)),
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);
        OpenSearchRestTestCase.client().performRequest(new Request("PUT", "/_data_stream/" + AUDIT_STREAM));

        SetupConfigOverridesIT.assertManagedBy(AUDIT_STREAM, AUDIT_POLICY, AUDIT_DESCRIPTION, 1);

        OpenSearchRestTestCase.client()
                .performRequest(new Request("POST", "/" + AUDIT_STREAM + "/_rollover"));

        SetupConfigOverridesIT.assertManagedBy(AUDIT_STREAM, AUDIT_POLICY, AUDIT_DESCRIPTION, 2);
    }
}
