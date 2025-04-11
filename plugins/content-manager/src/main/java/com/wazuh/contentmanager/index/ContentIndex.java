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
package com.wazuh.contentmanager.index;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;

import reactor.util.annotation.NonNull;

/** Class to manage the Content Manager index. */
public class ContentIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    private static final String INDEX_NAME = "wazuh-cve";
    private final int MAX_DOCUMENTS = 25;
    private static final int MAX_CONCURRENT_PETITIONS = 5;

    private final Client client;
    private final Semaphore semaphore = new Semaphore(MAX_CONCURRENT_PETITIONS);

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     */
    public ContentIndex(Client client) {
        this.client = client;
    }

    /**
     * Index an array of JSON objects using a BulkRequest
     *
     * @param documents the array of objects
     */
    private void index(List<JsonObject> documents)
            throws ExecutionException, InterruptedException, IOException {
        BulkRequest bulkRequest = new BulkRequest(INDEX_NAME);

        for (JsonObject document : documents) {
            bulkRequest.add(
                    new IndexRequest()
                            .id(document.get("name").getAsString())
                            .source(document.toString(), XContentType.JSON));
        }
        PlainActionFuture<BulkResponse> future = new PlainActionFuture<>();
        client.bulk(bulkRequest, future);
        BulkResponse bulkResponse = future.get();
        semaphore.release();
        if (bulkResponse.hasFailures()) {
            throw new IOException(
                    String.format(
                            "Snapshot indexing bulk request failed: %s", bulkResponse.buildFailureMessage()));
        } else {
            log.debug(
                    "Snapshot indexing bulk request was successful: took [{}]ms",
                    bulkResponse.getTook().millis());
        }
    }

    /**
     * Patch a document
     *
     * @param document the document to patch the existing document
     */
    public void patch(JsonObject document) {
        log.error("Unimplemented method");
    }

    /**
     * Initializes the index from a local snapshot. The snapshot file (in NDJSON format) is split in
     * chunks of {@link ContentIndex#MAX_DOCUMENTS} elements. These are bulk indexed using {@link
     * ContentIndex#index(List)}.
     *
     * @param path path to the CTI snapshot JSON file to be indexed.
     */
    public void fromSnapshot(@NonNull String path)
            throws InterruptedException, IOException, ExecutionException {
        long startTime = System.currentTimeMillis();

        String line;
        JsonObject json;
        int lineCount = 0;
        ArrayList<JsonObject> items = new ArrayList<>();

        BufferedReader reader = new BufferedReader(new FileReader(path, StandardCharsets.UTF_8));
        while ((line = reader.readLine()) != null) {
            json = JsonParser.parseString(line).getAsJsonObject();
            // Not every line in the snapshot is a CVE. We filter out the content by the "name" field of
            // the
            // current JSON object, if it starts with "CVE-". Any other case is skipped.
            String name = json.get("name").getAsString();
            if (name.startsWith("CVE-")) {
                items.add(json);
                lineCount++;
            } else {
                log.debug("Skipping non CVE element [{}]", name);
            }

            // Index items (MAX_DOCUMENTS reached)
            if (lineCount == MAX_DOCUMENTS) {
                semaphore.acquire();
                this.index(items);
                lineCount = 0;
                items.clear();
            }
        }
        // Index remaining items (> MAX_DOCUMENTS)
        if (lineCount > 0) {
            semaphore.acquire();
            this.index(items);
        }

        long estimatedTime = System.currentTimeMillis() - startTime;
        log.info("Snapshot indexing finished successfully in {} ms", estimatedTime);
    }
}
