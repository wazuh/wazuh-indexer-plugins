package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Local Consumer DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LocalConsumer extends AbstractConsumer implements ToXContent {
    @JsonProperty("local_offset")
    private long localOffset;
    @JsonProperty("remote_offset")
    private long remoteOffset;
    @JsonProperty("snapshot_link")
    private String snapshotLink;

    /**
     * Default constructor
     */
    public LocalConsumer() {
        super();
    }

    public LocalConsumer (String context, String name) {
        this.context = context;
        this.name  = name;
        this.localOffset = 0;
        this.remoteOffset = 0;
        this.snapshotLink = "";
    }

    public long getLocalOffset() {
        return localOffset;
    }

    public long getRemoteOffset() {
        return remoteOffset;
    }

    public String getSnapshotLink() {
        return snapshotLink;
    }

    @Override
    public String toString() {
        return "LocalConsumer{" +
            "localOffset=" + localOffset +
            ", remoteOffset=" + remoteOffset +
            ", snapshotLink='" + snapshotLink + '\'' +
            ", context='" + context + '\'' +
            ", name='" + name + '\'' +
            '}';
    }

    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field("name", this.name)
            .field("context", this.context)
            .field("local_offset", this.localOffset)
            .field("remote_offset", this.remoteOffset)
            .field("snapshot_link", this.snapshotLink)
            .endObject();

        return builder;
    }
}
