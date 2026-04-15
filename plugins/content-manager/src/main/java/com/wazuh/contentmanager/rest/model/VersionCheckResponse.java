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
 * Response model for the version check endpoint. Produces a JSON response following the Wazuh
 * Manager's format with {@code message} and {@code status} top-level fields.
 *
 * <p>Example response:
 *
 * <pre>{@code
 * {
 *   "message": {
 *     "uuid": "bd7f0db0-...",
 *     "last_check_date": "2026-04-14T15:28:41.347387+00:00",
 *     "current_version": "v5.0.0",
 *     "last_available_major": {},
 *     "last_available_minor": {},
 *     "last_available_patch": { "tag": "v5.0.1", ... }
 *   },
 *   "status": 200
 * }
 * }</pre>
 */
public class VersionCheckResponse implements ToXContent {
    private static final String MESSAGE_KEY = "message";
    private static final String STATUS_KEY = "status";
    private static final String UUID_KEY = "uuid";
    private static final String LAST_CHECK_DATE_KEY = "last_check_date";
    private static final String CURRENT_VERSION_KEY = "current_version";
    private static final String LAST_AVAILABLE_MAJOR_KEY = "last_available_major";
    private static final String LAST_AVAILABLE_MINOR_KEY = "last_available_minor";
    private static final String LAST_AVAILABLE_PATCH_KEY = "last_available_patch";

    private final String uuid;
    private final String lastCheckDate;
    private final String currentVersion;
    private final Release lastAvailableMajor;
    private final Release lastAvailableMinor;
    private final Release lastAvailablePatch;
    private final int status;

    /**
     * Constructs a VersionCheckResponse.
     *
     * @param uuid the cluster UUID
     * @param lastCheckDate the ISO 8601 timestamp of when the check was performed
     * @param currentVersion the current installed Wazuh version tag (e.g., "v5.0.0")
     * @param lastAvailableMajor the latest major version update, or null if none
     * @param lastAvailableMinor the latest minor version update, or null if none
     * @param lastAvailablePatch the latest patch version update, or null if none
     * @param status the HTTP status code
     */
    public VersionCheckResponse(
            String uuid,
            String lastCheckDate,
            String currentVersion,
            Release lastAvailableMajor,
            Release lastAvailableMinor,
            Release lastAvailablePatch,
            int status) {
        this.uuid = uuid;
        this.lastCheckDate = lastCheckDate;
        this.currentVersion = currentVersion;
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

        builder.startObject(MESSAGE_KEY);
        builder.field(UUID_KEY, this.uuid);
        builder.field(LAST_CHECK_DATE_KEY, this.lastCheckDate);
        builder.field(CURRENT_VERSION_KEY, this.currentVersion);

        writeReleaseOrEmpty(builder, LAST_AVAILABLE_MAJOR_KEY, this.lastAvailableMajor, params);
        writeReleaseOrEmpty(builder, LAST_AVAILABLE_MINOR_KEY, this.lastAvailableMinor, params);
        writeReleaseOrEmpty(builder, LAST_AVAILABLE_PATCH_KEY, this.lastAvailablePatch, params);

        builder.endObject();

        builder.field(STATUS_KEY, this.status);

        builder.endObject();
        return builder;
    }

    /**
     * Writes a release field as a full object if present, or as an empty object if null.
     *
     * @param builder the XContent builder
     * @param fieldName the JSON field name
     * @param release the release, or null
     * @param params serialization parameters
     * @throws IOException if an I/O error occurs
     */
    private static void writeReleaseOrEmpty(
            XContentBuilder builder, String fieldName, Release release, Params params)
            throws IOException {
        if (release != null) {
            builder.field(fieldName);
            release.toXContent(builder, params);
        } else {
            builder.startObject(fieldName).endObject();
        }
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
