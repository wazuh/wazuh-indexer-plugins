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
package com.wazuh.contentmanager.rest.model;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;

import java.io.IOException;

import com.wazuh.contentmanager.cti.catalog.model.Release;

/**
 * Response model for the version check endpoint. Produces a JSON response with the latest available
 * updates grouped by major, minor, and patch categories.
 *
 * <p>Example response:
 *
 * <pre>{@code
 * {
 *   "data": {
 *     "last_available_major": { ... },
 *     "last_available_minor": { ... },
 *     "last_available_patch": { ... }
 *   },
 *   "status": 200
 * }
 * }</pre>
 */
public class VersionCheckResponse implements ToXContent {
    private static final String DATA_KEY = "data";
    private static final String STATUS_KEY = "status";
    private static final String LAST_AVAILABLE_MAJOR_KEY = "last_available_major";
    private static final String LAST_AVAILABLE_MINOR_KEY = "last_available_minor";
    private static final String LAST_AVAILABLE_PATCH_KEY = "last_available_patch";

    private final Release lastAvailableMajor;
    private final Release lastAvailableMinor;
    private final Release lastAvailablePatch;
    private final int status;

    /**
     * Constructs a VersionCheckResponse.
     *
     * @param lastAvailableMajor the latest major version update, or null if none
     * @param lastAvailableMinor the latest minor version update, or null if none
     * @param lastAvailablePatch the latest patch version update, or null if none
     * @param status the HTTP status code
     */
    public VersionCheckResponse(
            Release lastAvailableMajor,
            Release lastAvailableMinor,
            Release lastAvailablePatch,
            int status) {
        this.lastAvailableMajor = lastAvailableMajor;
        this.lastAvailableMinor = lastAvailableMinor;
        this.lastAvailablePatch = lastAvailablePatch;
        this.status = status;
    }

    /**
     * Serializes this response into an {@link XContentBuilder} using JSON format.
     *
     * @return an {@link XContentBuilder} containing the JSON representation
     * @throws IOException if an I/O error occurs while building the content
     */
    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();

        builder.startObject(DATA_KEY);
        if (this.lastAvailableMajor != null) {
            builder.field(LAST_AVAILABLE_MAJOR_KEY);
            this.lastAvailableMajor.toXContent(builder, params);
        }
        if (this.lastAvailableMinor != null) {
            builder.field(LAST_AVAILABLE_MINOR_KEY);
            this.lastAvailableMinor.toXContent(builder, params);
        }
        if (this.lastAvailablePatch != null) {
            builder.field(LAST_AVAILABLE_PATCH_KEY);
            this.lastAvailablePatch.toXContent(builder, params);
        }
        builder.endObject();

        builder.field(STATUS_KEY, this.status);

        builder.endObject();
        return builder;
    }

    /**
     * Converts this response to a {@link BytesRestResponse}.
     *
     * @return a BytesRestResponse ready to be sent
     */
    public BytesRestResponse toBytesRestResponse() {
        try {
            return new BytesRestResponse(RestStatus.fromCode(this.status), this.toXContent());
        } catch (IOException e) {
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
}
