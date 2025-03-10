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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.model.ctiapi.ContextConsumerCatalog;
import com.wazuh.contentmanager.model.ctiapi.Offsets;
import com.wazuh.contentmanager.util.Privileged;
import com.wazuh.contentmanager.util.http.QueryParameters;

public class ContentUpdater {
    private static final Integer CHUNK_MAX_SIZE = 1000;

    private static final Logger log = LogManager.getLogger(ContentUpdater.class);

    public void fetchAndApplyUpdates() throws IOException {
        Long currentOffset = this.getCurrentContext();
        Long lastOffset = this.getCurrentOffset();

        if (lastOffset <= currentOffset) {
            log.info("On current last offset. No updates available.");
            return;
        }
        while (currentOffset < lastOffset) {
            Long nextOffset = Math.min(currentOffset + CHUNK_MAX_SIZE, lastOffset);

            Long finalCurrentOffset = currentOffset;
            Offsets offsets = this.getContextChanges(finalCurrentOffset, nextOffset);

            // Update the offset for the next iteration
            currentOffset = nextOffset;
        }
    }

    // We need to convert the SimpleHttpResponse to a usable value
    private Offsets getContextChanges(Long fromOffset, Long toOffset) throws IOException {
        XContent xContent = XContentType.JSON.xContent();
        SimpleHttpResponse response =
                Privileged.doPrivilegedRequest(
                        () ->
                                CTIClient.getInstance()
                                        .getContextChanges(
                                                contextQueryParameters(fromOffset.toString(), toOffset.toString())));

        return Offsets.parse(
                xContent.createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.IGNORE_DEPRECATIONS,
                        response.getBodyBytes()));
    }

    // This is a dummy function to mock the actual function from IndexClient until its implementation
    private Long getCurrentContext() {
        return 1234L;
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
        SimpleHttpResponse response =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());

        return ContextConsumerCatalog.parse(
                        xContent.createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.IGNORE_DEPRECATIONS,
                                response.getBodyBytes()))
                .getLastOffset();
    }
}
