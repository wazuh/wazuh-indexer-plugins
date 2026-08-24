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
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.Before;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.setup.index.ContentIndex;

/**
 * Integration tests verifying that the setup plugin provisions the threat-intel content indices:
 * for every alias name, a concrete {@code <name>-a} index, an index template covering {@code
 * <name>*} and the public alias pointing at the concrete index.
 *
 * <p>The mapping assertions reproduce the diagnostic from issue #1476: when {@code
 * wazuh-threatintel-enrichments-a} is missing, the CTI writer's first write auto-creates a
 * dynamically mapped index under the alias name, {@code document.type} becomes a {@code text} field
 * and the home overview's Threat catalog widget group fails with a 400.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class ThreatIntelIndicesIT extends OpenSearchRestTestCase {

    private static final String ENRICHMENTS = "wazuh-threatintel-enrichments";

    // spotless:off
    private static final List<String> ALIASES =
            List.of(
                    ENRICHMENTS,
                    "wazuh-threatintel-filters",
                    "wazuh-threatintel-decoders",
                    "wazuh-threatintel-rules",
                    "wazuh-threatintel-kvdbs",
                    "wazuh-threatintel-integrations",
                    "wazuh-threatintel-policies",
                    ".wazuh-threatintel-vulnerabilities");
    // spotless:on

    /** Registered after the content indices in the setup plugin, so it marks them all done. */
    private static final String SETTINGS_INDEX = ".wazuh-settings";

    private static final int MAX_WAIT_SECONDS = 120;
    private static final int POLL_INTERVAL_MS = 500;

    /**
     * Preserves indices upon test completion. The setup plugin creates them once, during cluster
     * initialization, so they must survive between tests.
     *
     * @return true to preserve indices
     */
    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    /**
     * Preserves index templates upon test completion, for the same reason as the indices.
     *
     * @return true to preserve templates
     */
    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    /**
     * Waits for the setup plugin to finish initializing by polling for the settings index, which is
     * registered after the content indices.
     *
     * @throws Exception if the index is not created within {@value #MAX_WAIT_SECONDS} seconds.
     */
    @Before
    public void waitForPluginInitialization() throws Exception {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);
        while (System.currentTimeMillis() < deadline) {
            try {
                client().performRequest(new Request("GET", "/" + SETTINGS_INDEX));
                return;
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() != 404) {
                    throw e;
                }
                Thread.sleep(POLL_INTERVAL_MS);
            }
        }
        fail("Timed out waiting for [" + SETTINGS_INDEX + "] to be created");
    }

    /** Every content index exists as a concrete {@code <name>-a} index, never as {@code <name>}. */
    public void testConcreteIndicesExist() throws Exception {
        for (String alias : ALIASES) {
            String physical = alias + ContentIndex.SUFFIX_A;
            Response response = client().performRequest(new Request("GET", "/" + physical));
            assertEquals(200, response.getStatusLine().getStatusCode());
            assertTrue(
                    "expected [" + physical + "] in the response",
                    entityAsMap(response).containsKey(physical));
        }
    }

    /** Every public alias resolves to its {@code -a} index and is that index's write target. */
    public void testAliasesPointAtTheConcreteIndices() throws Exception {
        for (String alias : ALIASES) {
            String physical = alias + ContentIndex.SUFFIX_A;
            Response response = client().performRequest(new Request("GET", "/_alias/" + alias));
            Map<String, Object> body = entityAsMap(response);
            assertEquals("alias [" + alias + "] must resolve to a single index", 1, body.size());
            assertTrue("alias [" + alias + "] must point at " + physical, body.containsKey(physical));
            assertEquals(Boolean.TRUE, this.aliasProperty(body, physical, alias).get("is_write_index"));
        }
    }

    /**
     * Every content index has its template installed, with a pattern that also covers the {@code -b}
     * shadow slot the Content Manager creates during a blue/green swap.
     */
    public void testTemplatesAreInstalled() throws Exception {
        for (String alias : ALIASES) {
            String templateName = alias + "-template";
            Response response =
                    client().performRequest(new Request("GET", "/_index_template/" + templateName));
            Map<String, Object> body = entityAsMap(response);
            List<?> templates = (List<?>) body.get("index_templates");
            assertEquals("expected exactly one template named " + templateName, 1, templates.size());
            Map<?, ?> entry = (Map<?, ?>) ((Map<?, ?>) templates.get(0)).get("index_template");
            assertEquals(List.of(alias + "*"), entry.get("index_patterns"));
        }
    }

    /**
     * The check the issue prescribes: the alias must resolve to the {@code -a} index and {@code
     * document.type} must be an aggregatable keyword there.
     */
    public void testEnrichmentsDocumentTypeIsAnAggregatableKeyword() throws Exception {
        Response response =
                client()
                        .performRequest(
                                new Request("GET", "/" + ENRICHMENTS + "/_field_caps?fields=document.type"));
        Map<String, Object> body = entityAsMap(response);

        assertEquals(List.of(ENRICHMENTS + ContentIndex.SUFFIX_A), body.get("indices"));

        Map<?, ?> fields = (Map<?, ?>) body.get("fields");
        Map<?, ?> documentType = (Map<?, ?>) fields.get("document.type");
        assertNotNull("document.type must be mapped", documentType);
        assertEquals(
                "document.type must be a keyword, not a dynamically mapped text field",
                Boolean.FALSE,
                documentType.containsKey("text"));
        Map<?, ?> keyword = (Map<?, ?>) documentType.get("keyword");
        assertNotNull("document.type must be mapped as a keyword", keyword);
        assertEquals(Boolean.TRUE, keyword.get("aggregatable"));
        assertEquals(Boolean.TRUE, keyword.get("searchable"));
    }

    /**
     * The two aggregations the home overview's Threat catalog widget group issues in a single
     * request. They returned a 400 while the index was dynamically mapped.
     */
    public void testThreatCatalogAggregationsSucceed() throws Exception {
        Request request = new Request("POST", "/" + ENRICHMENTS + "/_search");
        request.setJsonEntity(
                "{\"size\":0,\"aggs\":{"
                        + "\"ioc_feed_by_type\":{\"terms\":{\"field\":\"document.type\",\"size\":10}},"
                        + "\"threat_types\":{\"terms\":{\"field\":\"document.software.type\",\"size\":10}}}}");
        Response response = client().performRequest(request);

        assertEquals(200, response.getStatusLine().getStatusCode());
        Map<?, ?> shards = (Map<?, ?>) entityAsMap(response).get("_shards");
        assertEquals(
                "no shard may fail the aggregation", 0, ((Number) shards.get("failed")).intValue());
    }

    /**
     * The enrichments mapping is {@code dynamic: strict_allow_templates} and every IoC document
     * carries an {@code offset}, so a template missing that field would reject every CTI write.
     */
    public void testAnIocDocumentIsAccepted() throws Exception {
        Request request = new Request("PUT", "/" + ENRICHMENTS + "/_doc/setup-it-ioc?refresh=true");
        request.setJsonEntity(
                "{\"offset\":42,"
                        + "\"hash\":{\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"},"
                        + "\"document\":{\"id\":\"ioc-1\",\"type\":\"domain\",\"name\":\"example.invalid\","
                        + "\"provider\":\"wazuh\",\"confidence\":85,\"tags\":[\"test\"],"
                        + "\"software\":{\"type\":\"malware\",\"name\":\"test\",\"alias\":\"test\"}}}");
        Response response = client().performRequest(request);

        assertEquals(201, response.getStatusLine().getStatusCode());

        // The write went through the alias, so it must have landed on the concrete index.
        assertEquals(ENRICHMENTS + ContentIndex.SUFFIX_A, entityAsMap(response).get("_index"));
    }

    /** Extracts the settings of a single alias from an {@code _alias} response body. */
    private Map<?, ?> aliasProperty(Map<String, Object> body, String index, String alias) {
        Map<?, ?> aliases = (Map<?, ?>) ((Map<?, ?>) body.get(index)).get("aliases");
        return (Map<?, ?>) aliases.get(alias);
    }
}
