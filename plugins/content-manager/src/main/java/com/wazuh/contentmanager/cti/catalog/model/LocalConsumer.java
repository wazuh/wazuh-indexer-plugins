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
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Data Transfer Object representing the local state of a CTI Catalog Consumer.
 *
 * <p>This class tracks the synchronization status of a specific CTI consumer. It stores
 * local/remote offsets, the time its content was last updated and the consumer metadata persisted
 * in `.wazuh-cti-consumers`.
 *
 * <p>It also carries the nodes that failed to load the consumer's content into their Engine (only
 * the ruleset consumer has any). That state is written by the Engine content loader, not by the
 * synchronization, so it is kept apart from the synchronization phases: {@link
 * #getPendingSyncPhases()} never lists {@link #PHASE_ENGINE_LOAD}, and {@link #toXContent} adds it
 * to {@code pending_sync_phases} exactly while some node has a failure recorded.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LocalConsumer extends AbstractConsumer implements ToXContent {

    /**
     * Entry of {@code pending_sync_phases} listed while some node failed to load the consumer's
     * content into its Engine. A persisted contract read by the dashboard and the AI assistant, like
     * the synchronization phase names, so it is a constant of its own.
     */
    public static final String PHASE_ENGINE_LOAD = "engine_load";

    /** Field holding the Engine load failure shown to clients and the per-node failures. */
    static final String KEY_ENGINE_LOAD_ERROR = "engine_load_error";

    /** Sub-field of {@link #KEY_ENGINE_LOAD_ERROR} holding the failure of each node, by node id. */
    static final String KEY_NODES = "nodes";

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

    private List<String> pendingSyncPhases = Collections.emptyList();

    /** Failures to load the content into the Engine, by node id, sorted by id. */
    private Map<String, EngineLoadFailure> engineLoadFailures = Collections.emptyMap();

    @JsonProperty(Constants.KEY_UPDATED_AT)
    private String updatedAt;

    /**
     * The {@code engine_load_error} object as stored. Only its {@code nodes} are read back: the
     * fields shown to clients are derived from them on every write.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static final class StoredEngineLoadError {
        @JsonProperty(KEY_NODES)
        private Map<String, EngineLoadFailure> nodes;
    }

    /** Default constructor. */
    public LocalConsumer() {
        super();
    }

    /**
     * Constructs a new LocalConsumer with a basic identity. Status defaults to {@link
     * Status#RUNNING}: a consumer with no offsets yet has not actually synced anything, so it cannot
     * be {@link Status#READY}.
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
        this.status = Status.RUNNING;
        this.localOffset = 0;
        this.remoteOffset = 0;
    }

    /**
     * Constructs a LocalConsumer with full state details. Status defaults to {@link Status#RUNNING};
     * callers that know the sync actually completed should use the constructor that takes an explicit
     * {@link Status} instead.
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
        this.status = Status.RUNNING;
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
     * Constructs a LocalConsumer with full state details including explicit status and pending SAP
     * sync phases.
     *
     * @param context The context identifier.
     * @param name The consumer name.
     * @param type The consumer type identifier.
     * @param resource The full CTI consumer URL.
     * @param isPublic Whether the consumer is public.
     * @param status The current synchronization status.
     * @param localOffset The current offset processed locally.
     * @param remoteOffset The last known offset available remotely.
     * @param pendingSyncPhases Names of SAP sync sub-phases still owed a retry.
     */
    public LocalConsumer(
            String context,
            String name,
            String type,
            String resource,
            boolean isPublic,
            Status status,
            long localOffset,
            long remoteOffset,
            List<String> pendingSyncPhases) {
        this.context = context;
        this.name = name;
        this.type = type;
        this.resource = resource;
        this.isPublic = isPublic;
        this.status = status;
        this.localOffset = localOffset;
        this.remoteOffset = remoteOffset;
        this.pendingSyncPhases = LocalConsumer.withoutEngineLoad(pendingSyncPhases);
    }

    /**
     * Returns the synchronization phases of {@code phases}: {@link #PHASE_ENGINE_LOAD} is derived
     * from the recorded Engine load failures, never taken from a phase list.
     *
     * @param phases The phase names, or {@code null}.
     * @return The phases without {@link #PHASE_ENGINE_LOAD}, or an empty list.
     */
    private static List<String> withoutEngineLoad(List<String> phases) {
        if (phases == null || phases.isEmpty()) {
            return Collections.emptyList();
        }
        if (!phases.contains(PHASE_ENGINE_LOAD)) {
            return phases;
        }
        return phases.stream().filter(phase -> !PHASE_ENGINE_LOAD.equals(phase)).toList();
    }

    /**
     * Sets the synchronization phases read from {@code pending_sync_phases}, leaving out {@link
     * #PHASE_ENGINE_LOAD}.
     *
     * @param phases The stored phase names.
     */
    @JsonProperty("pending_sync_phases")
    private void setPendingSyncPhases(List<String> phases) {
        this.pendingSyncPhases = LocalConsumer.withoutEngineLoad(phases);
    }

    /**
     * Sets the Engine load failures read from {@code engine_load_error.nodes}.
     *
     * @param stored The stored {@code engine_load_error} object, or {@code null}.
     */
    @JsonProperty(KEY_ENGINE_LOAD_ERROR)
    private void setStoredEngineLoadError(StoredEngineLoadError stored) {
        this.engineLoadFailures = LocalConsumer.sortedFailures(stored != null ? stored.nodes : null);
    }

    /**
     * Copies a failure map into an unmodifiable map sorted by node id, dropping null entries.
     *
     * @param failures The failures by node id, or {@code null}.
     * @return The sorted copy, or an empty map.
     */
    private static Map<String, EngineLoadFailure> sortedFailures(
            Map<String, EngineLoadFailure> failures) {
        if (failures == null || failures.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, EngineLoadFailure> sorted = new TreeMap<>();
        failures.forEach(
                (nodeId, failure) -> {
                    if (nodeId != null && failure != null) {
                        sorted.put(nodeId, failure);
                    }
                });
        return Collections.unmodifiableMap(sorted);
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

    /**
     * Gets the names of SAP sync sub-phases still owed a retry.
     *
     * @return The pending phase names (e.g. "integrations", "rules", "detectors"), or an empty list
     *     if none are pending. Never {@link #PHASE_ENGINE_LOAD}, which is not a synchronization
     *     phase: see {@link #getEngineLoadFailures()}.
     */
    public List<String> getPendingSyncPhases() {
        return this.pendingSyncPhases;
    }

    /**
     * Gets the nodes that failed to load the consumer's content into their Engine and have not loaded
     * it since.
     *
     * @return The failures by node id, sorted by id; empty when every node loaded the content.
     */
    @JsonIgnore
    public Map<String, EngineLoadFailure> getEngineLoadFailures() {
        return this.engineLoadFailures;
    }

    /**
     * Gets the Engine load failure shown to clients: the most recent one among the nodes that are
     * still failing. Ties go to the lowest node id, so every writer derives the same one.
     *
     * @return The failure, or {@code null} when no node is failing.
     */
    @JsonIgnore
    public EngineLoadFailure getEngineLoadError() {
        EngineLoadFailure latest = null;
        for (EngineLoadFailure failure : this.engineLoadFailures.values()) {
            if (latest == null || failure.failedAtInstant().isAfter(latest.failedAtInstant())) {
                latest = failure;
            }
        }
        return latest;
    }

    /**
     * Returns a copy of this consumer with the given Engine load failures, in place of its own. Every
     * write of the ruleset consumer document takes them from the stored document, since only the
     * Engine content loader changes them.
     *
     * @param failures The failures by node id, or {@code null} for none.
     * @return The copy.
     */
    public LocalConsumer withEngineLoadFailures(Map<String, EngineLoadFailure> failures) {
        LocalConsumer copy = this.withUpdatedAt(this.updatedAt);
        copy.engineLoadFailures = LocalConsumer.sortedFailures(failures);
        return copy;
    }

    /**
     * Gets the time a synchronization pass last changed this consumer's content, whether the pass was
     * scheduled or requested through the API.
     *
     * @return The time as an ISO-8601 string, or {@code null} if no pass has changed the content
     *     since the field was introduced.
     */
    public String getUpdatedAt() {
        return this.updatedAt;
    }

    /**
     * Returns a copy of this consumer with the given content update time. Every write of a consumer
     * document replaces the whole document, so a write that does not change the content must carry
     * the time over from the document it read.
     *
     * @param updatedAt The time as an ISO-8601 string, or {@code null} for none.
     * @return The copy.
     */
    public LocalConsumer withUpdatedAt(String updatedAt) {
        LocalConsumer copy =
                new LocalConsumer(
                        this.context,
                        this.name,
                        this.type,
                        this.resource,
                        this.isPublic,
                        this.status,
                        this.localOffset,
                        this.remoteOffset,
                        this.pendingSyncPhases);
        copy.updatedAt = updatedAt;
        copy.engineLoadFailures = this.engineLoadFailures;
        return copy;
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
                + ", updatedAt='"
                + this.updatedAt
                + '\''
                + ", engineLoadFailures="
                + this.engineLoadFailures
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
     * <p>While some node has an Engine load failure recorded, {@code pending_sync_phases} also lists
     * {@link #PHASE_ENGINE_LOAD}, and {@code engine_load_error} holds the failure from {@link
     * #getEngineLoadError()} plus every node's failure under {@code nodes}. Both are left out
     * otherwise.
     *
     * @param builder The builder to write to.
     * @param params Parameters for the XContent generation (unused here).
     * @return The builder with the consumer fields appended.
     * @throws IOException If an I/O error occurs during building.
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        List<String> phases = this.pendingSyncPhases;
        EngineLoadFailure engineLoadError = this.getEngineLoadError();
        if (engineLoadError != null) {
            phases = new ArrayList<>(this.pendingSyncPhases);
            phases.add(PHASE_ENGINE_LOAD);
        }
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
                .field("pending_sync_phases", phases);
        if (this.updatedAt != null) {
            builder.field(Constants.KEY_UPDATED_AT, this.updatedAt);
        }
        if (engineLoadError != null) {
            builder.startObject(KEY_ENGINE_LOAD_ERROR);
            engineLoadError.writeFields(builder);
            builder.startObject(KEY_NODES);
            for (Map.Entry<String, EngineLoadFailure> entry : this.engineLoadFailures.entrySet()) {
                builder.startObject(entry.getKey());
                entry.getValue().writeFields(builder);
                builder.endObject();
            }
            builder.endObject();
            builder.endObject();
        }
        builder.endObject();

        return builder;
    }
}
