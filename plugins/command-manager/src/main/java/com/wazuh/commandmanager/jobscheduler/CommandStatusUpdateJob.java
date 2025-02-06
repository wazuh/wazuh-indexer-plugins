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
import java.util.Locale;

import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.model.Status;
import com.wazuh.commandmanager.settings.PluginSettings;

/**
 * The class in charge of searching and updating expired commands in {@link Status#PENDING} status.
 */
public class CommandStatusUpdateJob implements Runnable {
private static final Logger log = LogManager.getLogger(CommandStatusUpdateJob.class);
private final Client client;

private static final String COMMAND_STATUS_FIELD = Command.COMMAND + "." + Command.STATUS;
private static final String DELIVERY_TIMESTAMP_FIELD = "delivery_timestamp";

/** Painless code for the updateByQuery query. */
private static final String UPDATE_QUERY =
	String.format(
		Locale.ROOT,
		"if (ctx._source.command.status == '%s') {ctx._source.command.status = '%s';}",
		Status.PENDING,
		Status.FAILURE);

/**
* Default constructor.
*
* @param client OpenSearch's client.
*/
public CommandStatusUpdateJob(Client client) {
	this.client = client;
}

/**
* Fetch every command in PENDING status and whose delivery time has expired. Set their status to
* FAILURE.
*/
@Override
public void run() {
	log.debug("Running query to update expired commands");
	try {
	UpdateByQueryRequestBuilder updateByQuery =
		new UpdateByQueryRequestBuilder(this.client, UpdateByQueryAction.INSTANCE);
	updateByQuery
		.source(PluginSettings.getIndexName())
		.filter(
			QueryBuilders.boolQuery()
				.must(QueryBuilders.rangeQuery(DELIVERY_TIMESTAMP_FIELD).lt("now"))
				.filter(QueryBuilders.termQuery(COMMAND_STATUS_FIELD, Status.PENDING)))
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
