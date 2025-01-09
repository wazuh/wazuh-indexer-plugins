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

import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;

import java.io.IOException;
import java.util.ArrayList;

/** Orders model class. */
public class Orders implements ToXContent {
    public static final String ORDERS = "orders";

    private final ArrayList<Order> orders;

    /** Default constructor. */
    public Orders() {
        this.orders = new ArrayList<>();
    }

    /**
     * Helper static method that takes the search results in SearchHits form and parses them into
     * Order objects. It then puts together a json string meant for sending over HTTP
     *
     * @param searchHits the commands search result
     * @return A json string payload with an array of orders to be processed
     */

    /**
     * Static builder method that initializes an instance of Orders from a SearchHits instance.
     *
     * @param searchHits search hits as returned from the search index query to the commands index.
     * @return instance of Orders.
     */
    public static Orders fromSearchHits(SearchHits searchHits) {
        Orders orders = new Orders();

        // Iterate over search results
        for (SearchHit hit : searchHits) {
            // Parse the hit's order
            Order order = Order.fromSearchHit(hit);
            orders.add(order);
        }

        return orders;
    }

    /**
     * Clears the current list of orders and sets the current list of orders to the input list.
     *
     * @param orders the list of orders to be set.
     */
    public void setOrders(ArrayList<Order> orders) {
        this.orders.clear();
        this.orders.addAll(orders);
    }

    /**
     * Retrieves the list of orders.
     *
     * @return the current list of Order objects.
     */
    public ArrayList<Order> getOrders() {
        return this.orders;
    }

    /**
     * Adds an order to the orders array.
     *
     * @param order order to add.
     */
    private void add(Order order) {
        this.orders.add(order);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        // Start an XContentBuilder array named "orders"
        builder.startObject();
        builder.startArray(ORDERS);
        for (Order order : this.orders) {
            order.toXContent(builder, params);
        }
        builder.endArray();
        return builder.endObject();
    }
}
