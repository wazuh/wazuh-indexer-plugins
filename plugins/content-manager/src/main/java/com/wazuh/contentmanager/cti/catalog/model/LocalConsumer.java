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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Data Transfer Object representing the local state of a CTI Catalog Consumer.
 *
 * <p>This class tracks the synchronization status of a specific content context. It maintains the
 * {@code localOffset} versus the {@code remoteOffset}, along with a link to the snapshot for bulk
 * updates.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LocalConsumer extends AbstractConsumer implements ToXContent {

    @JsonProperty("local_offset")
    private long localOffset;

    @JsonProperty("remote_offset")
    private long remoteOffset;

    @JsonProperty("snapshot_link")
    private String snapshotLink;

    /** Default constructor. */
    public LocalConsumer() {
        super();
    }

    /**
     * Constructs a new LocalConsumer with a basic identity.
     *
     * @param context The context identifier (e.g., "rules_development").
     * @param name The consumer name.
     */
    public LocalConsumer(String context, String name) {
        this.context = context;
        this.name = name;
        this.localOffset = 0;
        this.remoteOffset = 0;
        this.snapshotLink = "";
    }

    /**
     * Constructs a LocalConsumer with full state details.
     *
     * @param context The context identifier.
     * @param name The consumer name.
     * @param localOffset The current offset processed locally.
     * @param remoteOffset The last known offset available remotely.
     * @param snapshotUrl The URL of the snapshot associated with this state.
     */
    public LocalConsumer(
            String context, String name, long localOffset, long remoteOffset, String snapshotUrl) {
        this.context = context;
        this.name = name;
        this.localOffset = localOffset;
        this.remoteOffset = remoteOffset;
        this.snapshotLink = snapshotUrl;
    }

    /**
     * Gets the local synchronization offset.
     *
     * @return The sequence number of the last processed item.
     */
    public long getLocalOffset() {
        return this.localOffset;
    }

    /**
     * Gets the remote synchronization offset.
     *
     * @return The sequence number of the latest item available upstream.
     */
    public long getRemoteOffset() {
        return this.remoteOffset;
    }

    /**
     * Gets the snapshot download URL.
     *
     * @return A string containing the URL, or empty if not set.
     */
    public String getSnapshotLink() {
        return this.snapshotLink;
    }

    @Override
    public String toString() {
        return "LocalConsumer{"
                + "localOffset="
                + this.localOffset
                + ", remoteOffset="
                + this.remoteOffset
                + ", snapshotLink='"
                + this.snapshotLink
                + '\''
                + ", context='"
                + this.context
                + '\''
                + ", name='"
                + this.name
                + '\''
                + '}';
    }

    /**
     * Serializes the consumer object to a new XContentBuilder (JSON).
     *
     * @return The XContentBuilder containing the JSON representation.
     * @throws IOException If an I/O error occurs during building.
     */
    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    /**
     * Serializes the consumer properties into an XContentBuilder.
     *
     * @param builder The builder to write to.
     * @param params Parameters for the XContent generation (unused here).
     * @return The builder with the consumer fields appended.
     * @throws IOException If an I/O error occurs during building.
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder
                .startObject()
                .field("name", this.name)
                .field("context", this.context)
                .field("local_offset", this.localOffset)
                .field("remote_offset", this.remoteOffset)
                .field("snapshot_link", this.snapshotLink)
                .endObject();

        return builder;
    }
}
