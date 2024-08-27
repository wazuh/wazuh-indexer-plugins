/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.wazuh.setup.utils;

import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

public class IndexTemplateUtils {

    public static Map<String, Object> fromFile(String filename) throws IOException {
        InputStream is = IndexTemplateUtils.class.getClassLoader().getResourceAsStream(filename);
        return IndexTemplateUtils.toMap(is);
    }

    /**
     * Convert from a JSON InputStream into a <String, Object> map
     *
     * @param template: the json formatted InputStream
     * @return a map with the json string contents.
     */
    public static Map<String, Object> toMap(InputStream template) throws IOException {
        XContentParser parser = JsonXContent.jsonXContent.createParser(
                NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                template);
        parser.nextToken();
        return parser.map();
    }

    public static Map<String, Object> get(Map<String, Object> map, String key)  {
        return (Map<String, Object>) map.get(key);
    }

}
