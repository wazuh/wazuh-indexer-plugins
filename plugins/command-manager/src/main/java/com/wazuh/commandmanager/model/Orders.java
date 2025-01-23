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

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;

import com.wazuh.commandmanager.CommandManagerPlugin;

/** Model that stores a list of Orders to be indexed at {@link CommandManagerPlugin#INDEX_NAME} */
public class Orders implements ToXContentObject {
    public static final String ORDERS = "_orders";
    public static final String ID = "_id";
    private final ArrayList<Order> orders;

    /** Default constructor. */
    public Orders() {
        this.orders = new ArrayList<>();
    }

    /**
     * Get the list of Order objects.
     *
     * @return the list of documents.
     */
    public ArrayList<Order> getOrders() {
        return orders;
    }

    /**
     * Adds a document to the list of documents.
     *
     * @param order The document to add to the list.
     */
    public void addOrder(Order order) {
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
}
