/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
 */
package com.wazuh.setup.utils;

import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import reactor.util.annotation.NonNull;

/** Util functions to parse and manage index templates files. */
public class IndexTemplateUtils {

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
}
