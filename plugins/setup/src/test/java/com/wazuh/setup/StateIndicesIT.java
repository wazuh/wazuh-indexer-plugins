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

import com.wazuh.setup.index.AliasedIndex;
import com.wazuh.setup.index.SetupStatusIndex;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests verifying that the setup plugin provisions the state indices behind an alias:
 * for every name, a concrete {@code <name>-a} index, the public alias pointing at it as its write
 * index, and an index template covering {@code <name>*}. A write through the alias lands in the
 * concrete index and is read back through the alias.
 *
 * <p>The migration of a concrete index created before this change runs at boot, so it needs a node
 * restart that this test cluster cannot do. It is covered by the unit tests of {@code StateIndex}.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class StateIndicesIT extends OpenSearchRestTestCase {

    // spotless:off
    private static final String[] INDICES = {
        "wazuh-agent-config",
        "wazuh-agent-stats",
        "wazuh-states-sca",
        "wazuh-states-fim-files",
        "wazuh-states-fim-registry-keys",
        "wazuh-states-fim-registry-values",
        "wazuh-states-inventory-browser-extensions",
        "wazuh-states-inventory-groups",
        "wazuh-states-inventory-hardware",
        "wazuh-states-inventory-hotfixes",
        "wazuh-states-inventory-interfaces",
        "wazuh-states-inventory-networks",
        "wazuh-states-inventory-packages",
        "wazuh-states-inventory-ports",
        "wazuh-states-inventory-processes",
        "wazuh-states-inventory-protocols",
        "wazuh-states-inventory-services",
        "wazuh-states-inventory-system",
        "wazuh-states-inventory-users",
        "wazuh-states-vulnerabilities"
    };
    // spotless:on

    private static final int MAX_WAIT_SECONDS = 120;
    private static final int POLL_INTERVAL_MS = 500;

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

    /** Waits for the readiness marker, written once every index is initialized. */
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

    /** Every state index exists as a concrete {@code <name>-a} index. */
    public void testConcreteIndicesCreated() throws IOException, ParseException {
        for (String name : INDICES) {
            String physical = name + AliasedIndex.SUFFIX_A;
            Response response = client().performRequest(new Request("GET", "/" + physical));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            assertThat(body, containsString("\"" + physical + "\""));
        }
    }

    /** Every public name is an alias pointing at its {@code -a} index as the write index. */
    public void testAliasesPointAtTheConcreteIndices() throws IOException, ParseException {
        for (String name : INDICES) {
            String physical = name + AliasedIndex.SUFFIX_A;
            Response response = client().performRequest(new Request("GET", "/_alias/" + name));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            assertThat(body, containsString("\"" + physical + "\""));
            assertThat(body, containsString("\"" + name + "\""));
            assertThat(body, containsString("\"is_write_index\":true"));
        }
    }

    /** The templates keep their names and cover both physical slots and the alias name. */
    public void testTemplatesCoverEverySlot() throws IOException, ParseException {
        for (String name : INDICES) {
            String template = "states-" + name.replaceFirst("^wazuh-(states-)?", "");
            Response response =
                    client().performRequest(new Request("GET", "/_index_template/" + template));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            assertThat(body, containsString("\"" + template + "\""));
            assertThat(body, containsString("\"" + name + "*\""));
        }
    }

    /** A write through the alias lands in the concrete index and is read back through the alias. */
    public void testWritesThroughTheAliasReachTheConcreteIndex() throws IOException, ParseException {
        String name = "wazuh-states-sca";
        Request index = new Request("PUT", "/" + name + "/_doc/alias-write-test?refresh=true");
        index.setJsonEntity("{\"checksum\": {\"hash\": {\"sha1\": \"alias-write-test\"}}}");
        Response written = client().performRequest(index);
        String body = EntityUtils.toString(written.getEntity(), StandardCharsets.UTF_8);
        assertThat(body, containsString("\"_index\":\"" + name + AliasedIndex.SUFFIX_A + "\""));

        Response read =
                client().performRequest(new Request("GET", "/" + name + "/_doc/alias-write-test"));
        body = EntityUtils.toString(read.getEntity(), StandardCharsets.UTF_8);
        assertThat(body, containsString("\"found\":true"));

        client()
                .performRequest(new Request("DELETE", "/" + name + "/_doc/alias-write-test?refresh=true"));
    }
}
