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
package com.wazuh.commandmanager.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexTemplateMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import reactor.util.annotation.NonNull;

/** Util functions to parse and manage index templates files. */
public class IndexTemplateUtils {
    private static final Logger log = LogManager.getLogger(IndexTemplateUtils.class);

    /** Default constructor */
    public IndexTemplateUtils() {}

    /**
     * Read index template file from the resources folder and returns its JSON content as a map.
     *
     * @param filename name of the index template to read from the resources folder
     * @return the JSON index template as a map
     * @throws IOException file not found or could not be read
     */
    public static Map<String, Object> fromFile(@NonNull String filename) throws IOException {
        InputStream is = IndexTemplateUtils.class.getClassLoader().getResourceAsStream(filename);
        return IndexTemplateUtils.toMap(is);
    }

    /**
     * Convert from a JSON InputStream into a String, Object map.
     *
     * <p>Used to convert the JSON index templates to the required format.
     *
     * @param is: the JSON formatted InputStream
     * @return a map with the json string contents.
     * @throws IOException thrown by {@link JsonXContent#createParser(NamedXContentRegistry,
     *     DeprecationHandler, InputStream)}
     */
    public static Map<String, Object> toMap(InputStream is) throws IOException {
        XContentParser parser =
                JsonXContent.jsonXContent.createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        is);
        parser.nextToken();
        return parser.map();
    }

    /**
     * Cast map's element to a String, Object map.
     *
     * <p>Used to retrieve the settings and mappings from the index templates, which are a JSON
     * object themselves.
     *
     * @param map the index template as a map.
     * @param key the element's key to retrieve and cast.
     * @return a String, Object map
     */
    public static Map<String, Object> get(Map<String, Object> map, String key) {
        return (Map<String, Object>) map.get(key);
    }

    /**
     * Checks for the existence of the given index template in the cluster.
     *
     * @param clusterService The cluster service used to check the node's existence
     * @param templateName index template name within the resources folder
     * @return whether the index template exists.
     */
    public static boolean isMissingIndexTemplate(
            ClusterService clusterService, String templateName) {
        Map<String, IndexTemplateMetadata> templates =
                clusterService.state().metadata().templates();
        log.debug("Existing index templates: {} ", templates.keySet());

        return !templates.containsKey(templateName);
    }

    /**
     * Creates an index template into the cluster.
     *
     * @param client OpenSearch's client.
     * @param templateName index template name. The index template is read from the plugin's
     *     resources directory as "templateName.json", and created as "templateName".
     */
    public static void putIndexTemplate(Client client, String templateName) {
        try {
            // @throws IOException
            Map<String, Object> template = IndexTemplateUtils.fromFile(templateName + ".json");

            PutIndexTemplateRequest putIndexTemplateRequest =
                    new PutIndexTemplateRequest()
                            .mapping(IndexTemplateUtils.get(template, "mappings"))
                            .settings(IndexTemplateUtils.get(template, "settings"))
                            .name(templateName)
                            .patterns((List<String>) template.get("index_patterns"));

            AcknowledgedResponse acknowledgedResponse =
                    client.admin().indices().putTemplate(putIndexTemplateRequest).actionGet();
            if (acknowledgedResponse.isAcknowledged()) {
                log.info("Index template [{}] created successfully", templateName);
            }

        } catch (IOException e) {
            log.error("Error reading index template [{}] from filesystem", templateName);
        }
    }
}
