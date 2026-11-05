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
import org.opensearch.client.RequestOptions;
import org.opensearch.client.WarningsHandler;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.setup.index.InternalIndexReplicas;

/**
 * Verifies that the setup plugin gives the Wazuh replica range to the internal indices that other
 * plugins create with a fixed replica count. On the single-node test cluster, {@code 0-1} resolves
 * to no replica, so an index created with one replica is green instead of yellow.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class InternalIndexReplicasIT extends OpenSearchRestTestCase {

    // Its backing indices match .ds-security-auditlogs-*, but it is not the stream that
    // SecurityAuditLogsIT checks ISM against, so neither test depends on the order they run in.
    private static final String AUDIT_DATA_STREAM = "security-auditlogs-replicas-test";
    private static final String AUDIT_TEMPLATE = "security-auditlogs-replicas-test";
    private static final String ISM_HISTORY_INDEX = ".opendistro-ism-managed-index-history-replicas-test";

    private static final int MAX_WAIT_SECONDS = 60;

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
     * The backing indices of an audit log data stream, created from a template that sets a fixed
     * replica count as the security plugin's does, get {@code index.auto_expand_replicas: 0-1}. The
     * template sets one replica, which would leave the single node yellow without the setting.
     *
     * @throws Exception if a request fails or the wait is interrupted
     */
    public void testAuditLogBackingIndicesAutoExpandReplicas() throws Exception {
        Request template = new Request("PUT", "/_index_template/" + AUDIT_TEMPLATE);
        template.setJsonEntity(
                """
                {
                  "index_patterns": ["%s"],
                  "data_stream": {"timestamp_field": {"name": "@timestamp"}},
                  "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 1}}
                }
                """
                        .formatted(AUDIT_DATA_STREAM));
        client().performRequest(template);
        client().performRequest(new Request("PUT", "/_data_stream/" + AUDIT_DATA_STREAM));
        try {
            this.assertAutoExpandReplicasAndGreen(".ds-" + AUDIT_DATA_STREAM + "-*");
        } finally {
            client().performRequest(new Request("DELETE", "/_data_stream/" + AUDIT_DATA_STREAM));
            client().performRequest(new Request("DELETE", "/_index_template/" + AUDIT_TEMPLATE));
        }
    }

    /**
     * An ISM history index, created with the one replica that ISM gives it by default, gets {@code
     * index.auto_expand_replicas: 0-1}, so a single node is green.
     *
     * @throws Exception if a request fails or the wait is interrupted
     */
    public void testIsmHistoryIndexAutoExpandsReplicas() throws Exception {
        Request create = new Request("PUT", "/" + ISM_HISTORY_INDEX);
        create.setJsonEntity(
                """
                {"settings": {"index.hidden": true, "number_of_shards": 1, "number_of_replicas": 1}}
                """);
        // ISM registers its history indices as system indices, and accessing one returns a warning.
        create.setOptions(permissive());
        client().performRequest(create);
        try {
            this.assertAutoExpandReplicasAndGreen(ISM_HISTORY_INDEX);
        } finally {
            Request delete = new Request("DELETE", "/" + ISM_HISTORY_INDEX);
            delete.setOptions(permissive());
            client().performRequest(delete);
        }
    }

    @SuppressWarnings("unchecked")
    private void assertAutoExpandReplicasAndGreen(String indices) throws Exception {
        assertBusy(
                () -> {
                    Request request =
                            new Request("GET", "/" + indices + "/_settings?flat_settings=true&expand_wildcards=all");
                    request.setOptions(permissive());
                    Map<String, Object> response = entityAsMap(client().performRequest(request));
                    assertFalse("no index matches " + indices, response.isEmpty());
                    response.forEach(
                            (index, body) ->
                                    assertEquals(
                                            "index.auto_expand_replicas of [" + index + "]",
                                            InternalIndexReplicas.AUTO_EXPAND_REPLICAS,
                                            ((Map<String, Object>) ((Map<String, Object>) body).get("settings"))
                                                    .get("index.auto_expand_replicas")));
                },
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);

        Request health =
                new Request(
                        "GET",
                        "/_cluster/health/"
                                + indices
                                + "?expand_wildcards=all&wait_for_status=green&timeout="
                                + MAX_WAIT_SECONDS
                                + "s");
        health.setOptions(permissive());
        assertEquals("green", entityAsMap(client().performRequest(health)).get("status"));
    }

    private static RequestOptions permissive() {
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);
        return options.build();
    }
}
