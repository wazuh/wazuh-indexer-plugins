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
package com.wazuh.contentmanager.model.ctiapi;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

// This model represents the JSON Patch operation format
// "operations": [
//     {
//         "op": "remove",
//         "path": "/containers/adp/0/affected/3"
//     },
//     {
//         "op": "add",
//         "path": "/containers/adp/0/affected/0/platforms/1",
//         "value": "bullseye"
//     },
//     {
//         "op": "replace",
//         "path": "/containers/adp/0/affected/0/defaultStatus",
//         "value": "unaffected"
//     },
//     {
//         "op": "add",
//         "path": "/containers/adp/3",
//         "value": {
//             "metrics": [
//                 {
//                     "other": {
//                         "type": "Unknown",
//                         "content": {
//                             "data": "{\"description\":\"unimportant\"}"
//                         }
//                     }
//                 }
//             ],
//             "affected": [
//                 {
//                     "vendor": "debian",
//                     "product": "gnuplot",
//                     "platforms": [
//                         "bookworm",
//                         "bullseye",
//                         "sid",
//                         "trixie"
//                     ],
//                     "defaultStatus": "unaffected"
//                 }
//             ],
//             "references": [
//                 {
//                     "url": "https://security-tracker.debian.org/tracker/CVE-2025-31177"
//                 }
//             ],
//             "descriptions": [
//                 {
//                     "lang": "en",
//                     "value": "not defined"
//                 }
//             ],
//             "providerMetadata": {
//                 "orgId": "79363d38-fa19-49d1-9214-5f28da3f3ac5",
//                 "shortName": "debian",
//                 "x_subShortName": "debian"
//             }
//         }
//     }
public class PatchOperation implements ToXContentObject {
    private final String op;
    private final String path;
    private final String from;
    // The value can be a JSON object, so we use String to represent it
    private final String value;

    /**
     * Constructor for the class
     *
     * @param op Operation type (add, remove, replace)
     * @param path Path to the element to be modified
     * @param from Source path for move operations
     * @param value Value to be added or replaced
     */
    public PatchOperation(String op, String path, String from, String value) {
        this.op = op;
        this.path = path;
        this.from = from;
        this.value = value;
    }

    public static PatchOperation parse(XContentParser parser)
            throws IOException, IllegalArgumentException, IOException {
        String op = null;
        String path = null;
        String from = null;
        String value = null;

        // Make sure we are at the start
        XContentParserUtils.ensureExpectedToken(
                XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        // Iterate over the object and add each Offset object to changes array
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case "op":
                    op = parser.text();
                    break;
                case "path":
                    path = parser.text();
                    break;
                case "from":
                    from = parser.text();
                    break;
                case "value":
                    value = parser.text();
                    break;
                default:
                    throw new IllegalArgumentException("Unknown field: " + fieldName);
            }
        }
        return new PatchOperation(op, path, from, value);
    }

    /**
     * Retrieve the operation type
     *
     * @return The operation type
     */
    public String getOp() {
        return this.op;
    }

    /**
     * Retrieve the path to the element to be modified
     *
     * @return The path to the element to be modified
     */
    public String getPath() {
        return this.path;
    }

    /**
     * Retrieve the source path for move operations
     *
     * @return The source path for move operations
     */
    public String getFrom() {
        return this.from;
    }

    /**
     * Retrieve the value to be added or replaced
     *
     * @return The value to be added or replaced
     */
    public String getValue() {
        return this.value;
    }

    public JsonObject getValueAsJson() {
        if (this.value == null) {
            return null;
        }
        try {
            return JsonParser.parseString(this.value).getAsJsonObject();
        } catch (JsonSyntaxException | IllegalStateException e) {
            // Not a valid JSON object, or it's not a JSON object at all
            return null;
        }
    }

    /**
     * Outputs an XContentBuilder object ready to be printed or manipulated
     *
     * @param builder the received builder object
     * @param params We don't really use this one
     * @return an XContentBuilder object ready to be printed
     * @throws IOException rethrown from Offset's toXContent
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field("op", this.op);
        builder.field("path", this.path);
        if (this.from != null) {
            builder.field("from", this.from);
        }
        if (this.value != null) {
            builder.field("value", this.value);
        }
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "PatchOperation{"
                + "op='"
                + op
                + '\''
                + ", path='"
                + path
                + '\''
                + ", from='"
                + from
                + '\''
                + ", value='"
                + value
                + '\''
                + '}';
    }
}
