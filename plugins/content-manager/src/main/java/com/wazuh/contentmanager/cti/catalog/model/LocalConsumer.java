/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
import com.fasterxml.jackson.annotation.JsonValue;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Data Transfer Object representing the local state of a CTI Catalog Consumer.
 *
 * <p>This class tracks the synchronization status of a specific CTI consumer. It stores
 * local/remote offsets and the consumer metadata persisted in `.wazuh-cti-consumers`.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LocalConsumer extends AbstractConsumer implements ToXContent {

    /** Represents whether the consumer is safe to query, currently syncing, or failed to sync. */
    public enum Status {
        READY("ready"),
        RUNNING("running"),
        FAILED("failed");

        private final String value;

        Status(String value) {
            this.value = value;
        }

        @JsonValue
        @Override
        public String toString() {
            return this.value;
        }

        @JsonCreator
        public static Status fromValue(String value) {
            for (Status s : Status.values()) {
                if (s.value.equalsIgnoreCase(value)) {
                    return s;
                }
            }
            throw new IllegalArgumentException("Unknown consumer status: " + value);
        }
    }

    @JsonProperty("status")
    private Status status;

    @JsonProperty("local_offset")
    private long localOffset;

    @JsonProperty("remote_offset")
    private long remoteOffset;

    @JsonProperty("type")
    private String type;

    @JsonProperty("resource")
    private String resource;

    @JsonProperty("is_public")
    private boolean isPublic;

    /** Default constructor. */
    public LocalConsumer() {
        super();
    }

    /**
     * Constructs a new LocalConsumer with a basic identity. Status defaults to {@link Status#READY}.
     *
     * @param context The context identifier (e.g., "rules_development").
     * @param name The consumer name.
     */
    public LocalConsumer(
            String context, String name, String type, String resource, boolean isPublic) {
        this.context = context;
        this.name = name;
        this.type = type;
        this.resource = resource;
        this.isPublic = isPublic;
        this.status = Status.READY;
        this.localOffset = 0;
        this.remoteOffset = 0;
    }

    /**
     * Constructs a LocalConsumer with full state details. Status defaults to {@link Status#READY}.
     *
     * @param context The context identifier.
     * @param name The consumer name.
     * @param type The consumer type identifier.
     * @param resource The full CTI consumer URL.
     * @param isPublic Whether the consumer is public.
     * @param localOffset The current offset processed locally.
     * @param remoteOffset The last known offset available remotely.
     */
    public LocalConsumer(
            String context,
            String name,
            String type,
            String resource,
            boolean isPublic,
            long localOffset,
            long remoteOffset) {
        this.context = context;
        this.name = name;
        this.type = type;
        this.resource = resource;
        this.isPublic = isPublic;
        this.status = Status.READY;
        this.localOffset = localOffset;
        this.remoteOffset = remoteOffset;
    }

    /**
     * Constructs a LocalConsumer with full state details including explicit status.
     *
     * @param context The context identifier.
     * @param name The consumer name.
     * @param type The consumer type identifier.
     * @param resource The full CTI consumer URL.
     * @param isPublic Whether the consumer is public.
     * @param status The current synchronization status.
     * @param localOffset The current offset processed locally.
     * @param remoteOffset The last known offset available remotely.
     */
    public LocalConsumer(
            String context,
            String name,
            String type,
            String resource,
            boolean isPublic,
            Status status,
            long localOffset,
            long remoteOffset) {
        this.context = context;
        this.name = name;
        this.type = type;
        this.resource = resource;
        this.isPublic = isPublic;
        this.status = status;
        this.localOffset = localOffset;
        this.remoteOffset = remoteOffset;
    }

    /**
     * Gets the current synchronization status of the consumer.
     *
     * @return The {@link Status} indicating whether the consumer is ready, running, or failed.
     */
    public Status getStatus() {
        return this.status;
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

    /** Gets the consumer type. */
    public String getType() {
        return this.type;
    }

    /** Gets the full CTI consumer URL. */
    public String getResource() {
        return this.resource;
    }

    /** Returns true if the consumer is public. */
    public boolean isPublic() {
        return this.isPublic;
    }

    @Override
    public String toString() {
        return "LocalConsumer{"
                + "status="
                + this.status
                + ", localOffset="
                + this.localOffset
                + ", remoteOffset="
                + this.remoteOffset
                + ", type='"
                + this.type
                + '\''
                + ", resource='"
                + this.resource
                + '\''
                + ", isPublic="
                + this.isPublic
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
                .field("type", this.type)
                .field("resource", this.resource)
                .field("is_public", this.isPublic)
                .field("status", this.status != null ? this.status.toString() : Status.READY.toString())
                .field("local_offset", this.localOffset)
                .field("remote_offset", this.remoteOffset)
                .endObject();

        return builder;
    }
}
