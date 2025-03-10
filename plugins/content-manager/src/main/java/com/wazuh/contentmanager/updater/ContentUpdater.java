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
package com.wazuh.contentmanager.updater;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.model.ctiapi.ContextConsumerCatalog;
import com.wazuh.contentmanager.util.Privileged;
import com.wazuh.contentmanager.util.http.QueryParameters;

public class ContentUpdater {
    private static final Integer CHUNK_MAX_SIZE = 1000;

    public void fetchContentUpdates() throws IOException {
        long currentOffset = 1234L;
        long lastOffset = getCurrentOffset(); // Example: 4567

        while (currentOffset < lastOffset) {
            long nextOffset = Math.min(currentOffset + CHUNK_MAX_SIZE, lastOffset);

            long finalCurrentOffset = currentOffset;
            SimpleHttpResponse contextChanges =
                    Privileged.doPrivilegedRequest(
                            () ->
                                    CTIClient.getInstance()
                                            .getContextChanges(
                                                    contextQueryParameters(
                                                            Long.toString(finalCurrentOffset), Long.toString(nextOffset))));

            // Process the response, update the current context with the new changes
            handleResponse(contextChanges);

            // Update the offset for the next iteration
            currentOffset = nextOffset;
        }
    }

    // We need to convert the SimpleHttpResponse to a usable value
    private void handleResponse(SimpleHttpResponse response) {}

    // This is a dummy function to mock the actual function from IndexClient until its implementation
    private static Object getContextInfo() {
        return new Object();
    }

    private Map<String, String> contextQueryParameters(String fromOffset, String toOffset) {
        Map<String, String> params = new HashMap<>();
        params.put(QueryParameters.FROM_OFFSET, fromOffset);
        params.put(QueryParameters.TO_OFFSET, toOffset);
        params.put(QueryParameters.WITH_EMPTIES, "");
        return params;
    }

    private Long getCurrentOffset() throws IOException {
        XContent xContent = XContentType.JSON.xContent();
        SimpleHttpResponse catalog =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());
        ContextConsumerCatalog parsedCatalog =
                ContextConsumerCatalog.parse(
                        xContent.createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.IGNORE_DEPRECATIONS,
                                catalog.getBodyBytes()));
        return parsedCatalog.getLastOffset();
    }

    private static Object getAllUpdates() {

        return null;
    }
}
