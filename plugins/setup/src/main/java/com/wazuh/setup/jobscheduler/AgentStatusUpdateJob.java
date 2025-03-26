package com.wazuh.setup.jobscheduler;

import com.wazuh.setup.model.Agent;
import com.wazuh.setup.model.AgentStatus;
import com.wazuh.setup.settings.PluginSettings;
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

public class AgentStatusUpdateJob implements Runnable {
    private static final Logger log = LogManager.getLogger(AgentStatusUpdateJob.class);
    private final Client client;

    /** Limit time to consider an agent as disconnected. */
    private static final int LIMIT_TIME_TO_DISCONECTED = 15; //Minutes

    private static final String COMMAND_STATUS_FIELD = Agent.AGENT + "." + Agent.STATUS;

    /** Painless code for the updateByQuery query. */
    private static final String UPDATE_QUERY =
        String.format(
            Locale.ROOT,
            "if (ctx._source.command.status == '%s') {ctx._source.command.status = '%s';}",
            AgentStatus.ACTIVE,
            AgentStatus.DISCONNECTED);

    /**
     * Default constructor.
     *
     * @param client OpenSearch's client.
     */
    public AgentStatusUpdateJob(Client client) {
        this.client = client;
    }

    /**
     * Fetch every agent in ACTIVE status and whose last login time was minutes before. Set their status to
     * FAILURE.
     */
    @Override
    public void run() {
        log.debug("Running query to update expired commands");
        try {
            UpdateByQueryRequestBuilder updateByQuery =
                new UpdateByQueryRequestBuilder(this.client, UpdateByQueryAction.INSTANCE);
            updateByQuery
                .source(PluginSettings.getAgentsIndex())
                .filter(
                    QueryBuilders.boolQuery()
                        .must(QueryBuilders.rangeQuery(Agent.LAST_LOGIN).lte("now"))
                        .filter(QueryBuilders.termQuery(Agent.STATUS, AgentStatus.ACTIVE)))
                //.maxDocs(PluginSettings.getInstance().getMaxDocs())
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
