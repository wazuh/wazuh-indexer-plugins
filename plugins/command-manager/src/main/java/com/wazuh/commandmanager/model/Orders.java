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
package com.wazuh.commandmanager.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.wazuh.commandmanager.settings.PluginSettings;
import com.wazuh.commandmanager.utils.Search;

/** Model that stores a list of Orders to be indexed at the commands index */
public class Orders implements ToXContentObject {
    public static final String ORDERS = "orders";
    public static final String ID = "_id";
    private final ArrayList<Order> orders;

    private static final Logger log = LogManager.getLogger(Orders.class);

    /** Default constructor. */
    public Orders() {
        this.orders = new ArrayList<>();
    }

    /**
     * Get the list of Order objects.
     *
     * @return the list of documents.
     */
    public ArrayList<Order> get() {
        return this.orders;
    }

    /**
     * Adds a document to the list of documents.
     *
     * @param order The document to add to the list.
     */
    public void add(Order order) {
        this.orders.add(order);
    }

    /**
     * Fit this object into a XContentBuilder parser, preparing it for the reply of POST /commands.
     *
     * @param builder XContentBuilder builder
     * @param params ToXContent.EMPTY_PARAMS
     * @return XContentBuilder builder with the representation of this object.
     * @throws IOException parsing error.
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startArray(ORDERS);
        for (Order order : this.orders) {
            builder.startObject();
            builder.field(ID, order.getId());
            builder.endObject();
        }
        return builder.endArray();
    }

    /**
     * Converts a list of Command objects into Orders by executing search queries.
     *
     * @param client the NodeClient used to execute search queries.
     * @param commands the list of Command objects to be converted.
     * @return an Orders object containing the generated orders.
     */
    @SuppressWarnings("unchecked")
    public static Orders fromCommands(NodeClient client, List<Command> commands) {
        Orders orders = new Orders();

        for (Command command : commands) {
            List<Agent> agentList = new ArrayList<>();
            String queryField = "";
            Target.Type targetType = command.getTarget().getType();
            String targetId = command.getTarget().getId();

            if (Objects.equals(targetType, Target.Type.GROUP)) {
                queryField = "agent.groups";
            } else if (Objects.equals(targetType, Target.Type.AGENT)) {
                queryField = "agent.id";
            }

            // Build and execute the search query
            log.info("Searching for agents using field {} with value {}", queryField, targetId);
            SearchHits hits =
                    Search.syncSearch(
                            client, PluginSettings.getAgentsIndex(), queryField, targetId);
            if (hits != null) {
                for (SearchHit hit : hits) {
                    final Map<String, Object> agentMap =
                            Search.getNestedObject(hit.getSourceAsMap(), "agent", Map.class);
                    if (agentMap != null) {
                        String agentId = (String) agentMap.get(Agent.ID);
                        List<String> agentGroups = (List<String>) agentMap.get(Agent.GROUPS);
                        Agent agent = new Agent(agentId, agentGroups);
                        agentList.add(agent);
                    }
                }
                log.info("Search retrieved {} agents.", agentList.size());
            }

            for (Agent agent : agentList) {
                Command newCommand =
                        new Command(
                                command.getSource(),
                                new Target(Target.Type.AGENT, agent.getId()),
                                command.getTimeout(),
                                command.getUser(),
                                command.getAction());
                Order order = new Order(agent, newCommand);
                orders.add(order);
            }
        }
        return orders;
    }
}
