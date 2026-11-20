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
import org.junit.Before;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.setup.index.IndexStateManagement;
import com.wazuh.setup.utils.JsonUtils;

/**
 * Integration test for the ISM policies of a cluster whose configuration file is the one the plugin
 * installs, with every key commented out. The copies of the policies installed next to it must not
 * be used: the policies stored are the ones bundled in the plugin.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class DefaultPoliciesIT extends OpenSearchRestTestCase {

    private static final String SETUP_STATUS = "/.wazuh-setup-status/_doc/setup-status";
    private static final String BUNDLED_POLICIES = "policies/";
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
     * Performs a GET request and returns an object of the response.
     *
     * @param endpoint the endpoint.
     * @param key key of the object in the response body.
     * @return the object.
     * @throws IOException if the request fails.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> get(String endpoint, String key) throws IOException {
        return (Map<String, Object>)
                OpenSearchRestTestCase.entityAsMap(
                                OpenSearchRestTestCase.client().performRequest(new Request("GET", endpoint)))
                        .get(key);
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
                                "ready", DefaultPoliciesIT.get(SETUP_STATUS, "_source").get("status"));
                    } catch (ResponseException e) {
                        throw new AssertionError("The setup status is not available yet", e);
                    }
                },
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);
    }

    /**
     * Every policy stored is the bundled one, not its editable copy, which has another description.
     *
     * @throws IOException if a request fails or a bundled policy cannot be read.
     */
    @SuppressWarnings("unchecked")
    public void testStoredPoliciesAreTheBundledOnes() throws IOException {
        for (String policy : IndexStateManagement.POLICIES) {
            Map<String, Object> bundled =
                    (Map<String, Object>)
                            new JsonUtils().fromFile(BUNDLED_POLICIES + policy + ".json").get("policy");
            Map<String, Object> stored =
                    DefaultPoliciesIT.get("/_plugins/_ism/policies/" + policy, "policy");

            Assert.assertEquals(policy, bundled.get("description"), stored.get("description"));
            Assert.assertEquals(
                    policy, bundled.get("last_updated_time"), stored.get("last_updated_time"));
        }
    }
}
