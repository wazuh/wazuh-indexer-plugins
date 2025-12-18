package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * CTI Consumer DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RemoteConsumer extends AbstractConsumer {
    private final long offset;
    private final String snapshotLink;
    private final long snapshotOffset;

    /**
     * Default constructor
     */
    public RemoteConsumer(@JsonProperty("data") JsonNode data) {
        this.name = data.get("name").asText("");
        this.context = data.get("context").asText("");
        this.offset = data.get("last_offset").asLong(0);
        this.snapshotLink = data.get("last_snapshot_link").asText("");
        this.snapshotOffset = data.get("last_snapshot_offset").asLong(0);
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

    /**
     * Returns a string representation of the RemoteConsumer object.
     *
     * @return A string describing the internal state of the consumer.
     */
    @Override
    public String toString() {
        return "RemoteConsumer{" +
            "offset=" + this.offset +
            ", snapshotLink='" + this.snapshotLink + '\'' +
            ", snapshotOffset=" + this.snapshotOffset +
            ", context='" + this.context + '\'' +
            ", name='" + this.name + '\'' +
            '}';
    }
}
