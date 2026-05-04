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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

/** CTI Consumer DTO. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RemoteConsumer extends AbstractConsumer {
    private final long offset;
    private final String snapshotLink;
    private final long snapshotOffset;
    private final String type;
    private final String resource;
    private final boolean isPublic;

    /**
     * Default constructor
     *
     * @param data The JSON node containing consumer data.
     */
    public RemoteConsumer(@JsonProperty("data") JsonNode data) {
        this.name = data.get("name").asText("");
        this.context = data.get("context").asText("");
        this.offset = data.get("last_offset").asLong(0);
        this.snapshotLink = data.get("last_snapshot_link").asText("");
        this.snapshotOffset = data.get("last_snapshot_offset").asLong(0);
        this.type = data.get("type").asText("");
        this.resource = data.get("resource").asText("");
        this.isPublic = data.get("is_public").asBoolean(false);
    }

    /**
     * Gets the last known offset of the remote consumer.
     *
     * @return The offset value.
     */
    public long getOffset() {
        return this.offset;
    }

    /**
     * Gets the link to the latest snapshot.
     *
     * @return The snapshot URL string.
     */
    public String getSnapshotLink() {
        return this.snapshotLink;
    }

    /**
     * Gets the offset associated with the latest snapshot.
     *
     * @return The snapshot offset value.
     */
    public long getSnapshotOffset() {
        return this.snapshotOffset;
    }

    /** Gets the consumer type. */
    public String getType() {
        return this.type;
    }

    /** Gets the full CTI consumer URL. */
    public String getResource() {
        return this.resource;
    }

    /** Returns true if the remote consumer is public. */
    public boolean isPublic() {
        return this.isPublic;
    }

    /**
     * Returns a string representation of the RemoteConsumer object.
     *
     * @return A string describing the internal state of the consumer.
     */
    @Override
    public String toString() {
        return "RemoteConsumer{"
                + "offset="
                + this.offset
                + ", snapshotLink='"
                + this.snapshotLink
                + '\''
                + ", snapshotOffset="
                + this.snapshotOffset
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
}
