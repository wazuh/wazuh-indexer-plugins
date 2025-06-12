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
package com.wazuh.setup.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.UpdateByQueryAction;
import org.opensearch.index.reindex.UpdateByQueryRequestBuilder;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;
import org.opensearch.transport.client.Client;

import java.util.Collections;
import java.util.Locale;

import com.wazuh.setup.settings.PluginSettings;

/** The class in charge of searching and updating inactive agents in ACTIVE status. */
public class AgentStatusUpdateJob implements Runnable {
    private static final Logger log = LogManager.getLogger(AgentStatusUpdateJob.class);
    private final Client client;

    private static final String AGENT_STATUS_FIELD = "agent.status";
    private static final String LAST_LOGIN_FIELD = "agent.last_login";
    private static final String ACTIVE_STATUS = "active";
    private static final String DISCONNECTED_STATUS = "disconnected";

    /** Painless code for the updateByQuery query. */
    private static final String UPDATE_QUERY =
            String.format(
                    Locale.ROOT,
                    "if (ctx._source.agent.status == '%s') {ctx._source.agent.status = '%s';}",
                    ACTIVE_STATUS,
                    DISCONNECTED_STATUS);

    /**
     * Default constructor.
     *
     * @param client OpenSearch's client.
     */
    public AgentStatusUpdateJob(Client client) {
        this.client = client;
    }

    /**
     * Fetch every agent in ACTIVE status and whose last login time was 15 minutes before. Set their
     * status to DISCONNECTED.
     */
    @Override
    public void run() {
        log.debug("Running query to update inactive agents");
        try {
            UpdateByQueryRequestBuilder updateByQuery =
                    new UpdateByQueryRequestBuilder(this.client, UpdateByQueryAction.INSTANCE);
            updateByQuery
                    .source(PluginSettings.getAgentsIndex())
                    .filter(
                            QueryBuilders.boolQuery()
                                    .must(QueryBuilders.rangeQuery(LAST_LOGIN_FIELD).lte("now-15m/m"))
                                    .filter(QueryBuilders.termQuery(AGENT_STATUS_FIELD, ACTIVE_STATUS)))
                    .maxDocs(PluginSettings.getInstance().getMaxDocs())
                    .script(new Script(ScriptType.INLINE, "painless", UPDATE_QUERY, Collections.emptyMap()));
            BulkByScrollResponse response = updateByQuery.get();
            log.debug("Query returned {} documents", response.getUpdated());
        } catch (OpenSearchTimeoutException e) {
            log.error("Query timed out: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Generic exception running the query: {}", e.getMessage());
        }
    }
}
