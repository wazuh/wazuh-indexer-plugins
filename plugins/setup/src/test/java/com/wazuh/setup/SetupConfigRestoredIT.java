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

import org.opensearch.client.Request;
import org.opensearch.client.ResponseException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.setup.utils.JsonUtils;

/**
 * Integration test for a configuration file that goes back to the defaults. It runs on the cluster
 * of {@link SetupConfigOverridesIT}, restarted with the {@code setup.yml} of {@code
 * src/test/resources/setup-config/restored}: the template keys are gone and the policy switches are
 * back to {@code false}. The first start of the cluster stored the replaced policies and created
 * the indices that run them.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SetupConfigRestoredIT extends OpenSearchRestTestCase {

    private static final String EVENTS_TEMPLATE = "wazuh-events-v5-security-template";
    private static final String STREAM = "wazuh-active-responses";
    private static final String POLICY = "stream-active-responses-policy";
    private static final String BUNDLED_POLICY = "policies/" + POLICY + ".json";
    private static final String REPLACED_DESCRIPTION =
            "Integration test policy for the active responses data stream.";
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
     * Reads the description of the policy each backing index of the stream runs. Each managed index
     * runs its own copy of the policy, so the description tells which policy it started on.
     *
     * @return the descriptions, in the order the backing indices were created.
     * @throws IOException if the request fails.
     */
    private static List<Object> runningDescriptions() throws IOException {
        Map<String, Object> explain =
                SetupConfigRestoredIT.get("/_plugins/_ism/explain/.ds-" + STREAM + "-*?show_policy=true");
        return explain.keySet().stream()
                .filter(key -> key.startsWith(".ds-" + STREAM))
                .sorted()
                .map(
                        index -> {
                            Map<String, Object> policy =
                                    SetupConfigRestoredIT.object(
                                            SetupConfigRestoredIT.object(explain, index), "policy");
                            return policy == null ? null : policy.get("description");
                        })
                .toList();
    }

    /**
     * With the switch back to {@code false}, the initialization stores the default policy again under
     * the same id. The indices that exist keep the policy they started on, and the backing index a
     * rollover creates starts on the default one. A template whose keys were removed from the file
     * has its bundled settings again.
     *
     * @throws Exception if a request fails or the cluster does not get there in time.
     */
    public void testDefaultsAreRestored() throws Exception {
        String bundledDescription =
                (String)
                        SetupConfigRestoredIT.object(new JsonUtils().fromFile(BUNDLED_POLICY), "policy")
                                .get("description");

        // The stored policy is the default one again. Index State Management finds the policies
        // with a search, as its list API does, so the test waits for the search to see it.
        OpenSearchTestCase.assertBusy(
                () -> {
                    try {
                        Assert.assertEquals(
                                bundledDescription,
                                SetupConfigRestoredIT.object(
                                                SetupConfigRestoredIT.get("/_plugins/_ism/policies/" + POLICY), "policy")
                                        .get("description"));
                        String searchable =
                                SetupConfigRestoredIT.get("/_plugins/_ism/policies?size=50").toString();
                        Assert.assertTrue(searchable.contains(bundledDescription));
                        Assert.assertFalse(searchable.contains(REPLACED_DESCRIPTION));
                    } catch (ResponseException e) {
                        throw new AssertionError("The cluster is not initialized yet", e);
                    }
                },
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);

        // The indices created while the policy was replaced keep running the replaced policy.
        List<Object> before = SetupConfigRestoredIT.runningDescriptions();
        Assert.assertFalse(before.isEmpty());
        for (Object description : before) {
            Assert.assertEquals(before.toString(), REPLACED_DESCRIPTION, description);
        }

        OpenSearchRestTestCase.client()
                .performRequest(new Request("POST", "/" + STREAM + "/_rollover"));

        // The new backing index starts on the default policy.
        OpenSearchTestCase.assertBusy(
                () -> {
                    List<Object> after = SetupConfigRestoredIT.runningDescriptions();
                    Assert.assertEquals(after.toString(), before.size() + 1, after.size());
                    Assert.assertEquals(after.toString(), before, after.subList(0, before.size()));
                    Assert.assertEquals(after.toString(), bundledDescription, after.get(before.size()));
                },
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);

        // The events template no longer has the two shards the first phase gave it.
        String template = SetupConfigRestoredIT.get("/_index_template/" + EVENTS_TEMPLATE).toString();
        Assert.assertTrue(template, template.contains("number_of_shards=1"));
        Assert.assertFalse(template, template.contains("number_of_shards=2"));
    }
}
