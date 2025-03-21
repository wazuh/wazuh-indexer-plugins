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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.core.rest.RestStatus;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;


/** Class to manage the Content Manager index. */
public class ContentIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    private static final String INDEX_NAME = "wazuh-content";
    private final int MAX_DOCUMENTS = 250;

    private final Client client;


    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     */
    public ContentIndex(Client client) {
        this.client = client;
    }

    /**
     * Index an array of JSON objects.
     *
     * @param documents the array of objects
     */
    public CompletableFuture<RestStatus> index(List<JsonObject> documents) {
        throw new RuntimeException("Unimplemented method");
    }

    /**
     * Patch a document
     *
     * @param document the document to patch the existing document
     */
    public void patch(JsonObject document) {
        throw new RuntimeException("Unimplemented method");
    }

    /**
     * Divides a json document in new json documents with up to MAX_DOCUMENTS lines
     *
     * @param route The route to the file that will be divided
     */
    public void divideJson(String route){
        try (BufferedReader reader = new BufferedReader(new FileReader(route))) {
            String line;
            int lineCount = 0;
            ArrayList<JsonObject> fileContent = new ArrayList<>();

            while((line = reader.readLine()) != null){
                JsonObject json = JsonParser.parseString(line).getAsJsonObject();
                fileContent.add(json);
                lineCount++;

                if (lineCount == MAX_DOCUMENTS){
                    index(fileContent);
                    lineCount = 0;
                    fileContent.clear();
                }
            }
            if(lineCount > 0){
                index(fileContent);
            }
        }
        catch (IOException e){
            log.error("Error during the process of dividing the document due to {}", e.getMessage());
        }
    }

}
