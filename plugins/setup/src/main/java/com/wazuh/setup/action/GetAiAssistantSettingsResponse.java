/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.setup.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Map;

/** Response carrying the AI assistant's providers, settings and field policy, combined. */
public class GetAiAssistantSettingsResponse extends ActionResponse implements ToXContent {

    private final Map<String, Object> result;

    /**
     * Constructs a new response.
     *
     * @param result combined {@code settings}/{@code field_policy}/{@code providers} map, as
     *     assembled by {@code AiAssistantSettingsAdminIndex#get}.
     */
    public GetAiAssistantSettingsResponse(Map<String, Object> result) {
        super();
        this.result = result;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public GetAiAssistantSettingsResponse(StreamInput sin) throws IOException {
        super();
        this.result = sin.readMap();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeMap(this.result);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        for (Map.Entry<String, Object> entry : this.result.entrySet()) {
            builder.field(entry.getKey(), entry.getValue());
        }
        return builder.endObject();
    }

    public Map<String, Object> getResult() {
        return this.result;
    }
}
