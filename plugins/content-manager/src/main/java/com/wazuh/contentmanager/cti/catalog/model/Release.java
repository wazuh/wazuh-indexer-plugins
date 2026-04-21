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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Represents a single release entry returned by the CTI API's {@code /releases/:tag/updates}
 * endpoint.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Release implements ToXContentObject {
    private static final String TAG_KEY = "tag";
    private static final String TITLE_KEY = "title";
    private static final String DESCRIPTION_KEY = "description";
    private static final String PUBLISHED_DATE_KEY = "published_date";
    private static final String SEMVER_KEY = "semver";

    @JsonProperty(TAG_KEY)
    private final String tag;

    @JsonProperty(TITLE_KEY)
    private final String title;

    @JsonProperty(DESCRIPTION_KEY)
    private final String description;

    @JsonProperty(PUBLISHED_DATE_KEY)
    private final String publishedDate;

    @JsonProperty(SEMVER_KEY)
    private final Semver semver;

    /**
     * Constructs a Release instance.
     *
     * @param tag the semver release tag (e.g., "v5.1.0")
     * @param title the human-readable release title
     * @param description the release notes in markdown format
     * @param publishedDate the ISO 8601 publication timestamp
     * @param semver the parsed semantic version
     */
    @JsonCreator
    public Release(
            @JsonProperty(TAG_KEY) String tag,
            @JsonProperty(TITLE_KEY) String title,
            @JsonProperty(DESCRIPTION_KEY) String description,
            @JsonProperty(PUBLISHED_DATE_KEY) String publishedDate,
            @JsonProperty(SEMVER_KEY) Semver semver) {
        this.tag = tag;
        this.title = title;
        this.description = description;
        this.publishedDate = publishedDate;
        this.semver = semver;
    }

    /**
     * Returns the semver release tag.
     *
     * @return the tag string
     */
    public String getTag() {
        return this.tag;
    }

    /**
     * Returns the release title.
     *
     * @return the title string
     */
    public String getTitle() {
        return this.title;
    }

    /**
     * Returns the release description.
     *
     * @return the description string
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Returns the publication date.
     *
     * @return the published date string in ISO 8601 format
     */
    public String getPublishedDate() {
        return this.publishedDate;
    }

    /**
     * Returns the parsed semantic version.
     *
     * @return the Semver instance
     */
    public Semver getSemver() {
        return this.semver;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(TAG_KEY, this.tag);
        builder.field(TITLE_KEY, this.title);
        builder.field(DESCRIPTION_KEY, this.description);
        builder.field(PUBLISHED_DATE_KEY, this.publishedDate);
        if (this.semver != null) {
            builder.field(SEMVER_KEY);
            this.semver.toXContent(builder, params);
        }
        builder.endObject();
        return builder;
    }

    /** Represents the semantic version components of a release. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Semver implements ToXContentObject {
        private static final String MAJOR_KEY = "major";
        private static final String MINOR_KEY = "minor";
        private static final String PATCH_KEY = "patch";

        @JsonProperty(MAJOR_KEY)
        private final int major;

        @JsonProperty(MINOR_KEY)
        private final int minor;

        @JsonProperty(PATCH_KEY)
        private final int patch;

        /**
         * Constructs a Semver instance.
         *
         * @param major the major version number
         * @param minor the minor version number
         * @param patch the patch version number
         */
        @JsonCreator
        public Semver(
                @JsonProperty(MAJOR_KEY) int major,
                @JsonProperty(MINOR_KEY) int minor,
                @JsonProperty(PATCH_KEY) int patch) {
            this.major = major;
            this.minor = minor;
            this.patch = patch;
        }

        /**
         * @return the major version number
         */
        public int getMajor() {
            return this.major;
        }

        /**
         * @return the minor version number
         */
        public int getMinor() {
            return this.minor;
        }

        /**
         * @return the patch version number
         */
        public int getPatch() {
            return this.patch;
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field(MAJOR_KEY, this.major);
            builder.field(MINOR_KEY, this.minor);
            builder.field(PATCH_KEY, this.patch);
            builder.endObject();
            return builder;
        }
    }
}
