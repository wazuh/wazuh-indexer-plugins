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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.ParsingException;
import org.opensearch.core.xcontent.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Changes implements ToXContentObject {

    private static final Logger log = LogManager.getLogger(Changes.class);
    private static final String DATA = "data";

    private static List<Offset> data;

    public Changes(List<Offset> data) {
        Changes.data = data;
    }

    private static Offset processOffsets(XContentParser parser) throws IOException {
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                return Offset.parse(parser);
            }
        }
        return null;
    }

    public static Changes parse(XContentParser parser)
            throws IOException, IllegalArgumentException, ParsingException {
        List<Offset> changes = new ArrayList<>();
        if (parser.nextToken() == XContentParser.Token.START_OBJECT) {
            log.info("Starting object");
            String fieldName;
            parser.nextToken();
            while ( parser.currentToken() != XContentParser.Token.END_OBJECT || parser.currentToken() != null) {
                XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, parser.currentToken(), parser);
                fieldName = parser.currentName();
                log.info("iterating {}", fieldName);
                if (Objects.equals(fieldName, DATA)
                    && parser.nextToken() == XContentParser.Token.START_ARRAY) {
                    changes.add(processOffsets(parser));
                    log.info("adding changes");
                }
            }
        }
        return new Changes(changes);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.startArray(DATA);
        data.forEach(
            (offset) ->
            {
                try {
                    offset.toXContent(builder, ToXContentObject.EMPTY_PARAMS);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        );
        builder.endArray();
        return builder.endObject();
    }

}
