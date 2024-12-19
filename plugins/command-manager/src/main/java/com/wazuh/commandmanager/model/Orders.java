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
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;

import java.io.IOException;
import java.util.Objects;

public class Orders {

    private static final Logger log = LogManager.getLogger(Orders.class);

    public static String getOrders(SearchHits searchHits) {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            // Start an XContentBuilder array named "orders"
            builder.startObject();
            builder.startArray(Order.ORDERS);
            // Iterate over search results
            for (SearchHit hit : searchHits) {
                // Parse the hit's order
                Order order = Order.parseSearchHit(hit);
                // Add the current order to the XContentBuilder array
                Objects.requireNonNull(order).toXContent(builder, ToXContent.EMPTY_PARAMS);
            }
            // Close the object and prepare it for delivery
            builder.endArray();
            builder.endObject();
            return builder.toString();
        } catch (IOException e) {
            log.error("Error building payload from hit: {}", e.getMessage());
        } catch (NullPointerException e) {
            log.error(
                    "Exception found when building order payload. Null Order: {}", e.getMessage());
        }
        return null;
    }
}
