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
package com.wazuh.commandmanager.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.client.Client;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.UpdateByQueryAction;
import org.opensearch.index.reindex.UpdateByQueryRequestBuilder;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;

import java.util.Collections;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.model.Status;

/**
 * The class in charge of searching and managing commands in {@link Status#PENDING} status and of
 * submitting them to the destination client.
 */
public class SearchThreadRefactor implements Runnable {
    public static final String COMMAND_STATUS_FIELD = Command.COMMAND + "." + Command.STATUS;
    private static final Logger log = LogManager.getLogger(SearchThreadRefactor.class);
    private final Client client;

    /**
     * Default constructor.
     *
     * @param client OpenSearch's client.
     */
    public SearchThreadRefactor(Client client) {
        this.client = client;
    }

    @Override
    public void run() {
        log.debug("Running scheduled job");
        try {
            // updateByQuery
            UpdateByQueryRequestBuilder updateByQuery =
                    new UpdateByQueryRequestBuilder(this.client, UpdateByQueryAction.INSTANCE);
            updateByQuery
                    .source(CommandManagerPlugin.INDEX_NAME)
                    .filter(
                            QueryBuilders.boolQuery()
                                    .must(QueryBuilders.rangeQuery("delivery_timestamp").lt("now"))
                                    .filter(
                                            QueryBuilders.termQuery(
                                                    COMMAND_STATUS_FIELD, Status.PENDING)))
                    .maxDocs(1000)
                    .script(
                            new Script(
                                    ScriptType.INLINE,
                                    "painless",
                                    "if (ctx._source.command.status == 'pending') {ctx._source.command.status = 'failure';}",
                                    Collections.emptyMap()));
            BulkByScrollResponse response = updateByQuery.get();
            log.info(response.getUpdated());
        } catch (OpenSearchTimeoutException e) {
            log.error("Query timed out: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Generic exception retrieving page: {}", e.getMessage());
        }
    }
}
