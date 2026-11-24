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

import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;

/**
 * One node's failure to load the CTI ruleset content into its Engine, as recorded in the ruleset
 * consumer document of {@code .wazuh-cti-consumers}.
 *
 * <p>The field names and the {@link #REASON_REFUSED} and {@link #REASON_UNREACHABLE} values are a
 * persisted contract read by the dashboard and the AI assistant, so they are spelled out here
 * rather than derived from other identifiers.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class EngineLoadFailure {

    /** The Engine read the payload and refused it (a 4xx answer). */
    public static final String REASON_REFUSED = "refused";

    /** The Engine could not be reached, or failed (a 5xx answer or a socket error). */
    public static final String REASON_UNREACHABLE = "unreachable";

    static final String KEY_FAILED_AT = "failed_at";
    static final String KEY_REASON = "reason";
    static final String KEY_MESSAGE = "message";
    static final String KEY_NODE = "node";

    private final String failedAt;
    private final String reason;
    private final String message;
    private final String node;

    /**
     * Constructs a failure.
     *
     * @param failedAt When the node started failing this way, as an ISO-8601 string.
     * @param reason {@link #REASON_REFUSED} or {@link #REASON_UNREACHABLE}.
     * @param message The Engine's error message.
     * @param node The name of the node that failed.
     */
    @JsonCreator
    public EngineLoadFailure(
            @JsonProperty(KEY_FAILED_AT) String failedAt,
            @JsonProperty(KEY_REASON) String reason,
            @JsonProperty(KEY_MESSAGE) String message,
            @JsonProperty(KEY_NODE) String node) {
        this.failedAt = failedAt;
        this.reason = reason;
        this.message = message;
        this.node = node;
    }

    /**
     * Gets the time the node started failing this way. Retries that fail the same way do not change
     * it.
     *
     * @return The time as an ISO-8601 string.
     */
    public String getFailedAt() {
        return this.failedAt;
    }

    /**
     * Gets the kind of failure.
     *
     * @return {@link #REASON_REFUSED} or {@link #REASON_UNREACHABLE}.
     */
    public String getReason() {
        return this.reason;
    }

    /**
     * Gets the Engine's error message.
     *
     * @return The message.
     */
    public String getMessage() {
        return this.message;
    }

    /**
     * Gets the name of the node that failed.
     *
     * @return The node name.
     */
    public String getNode() {
        return this.node;
    }

    /**
     * Returns whether {@code other} is the same failure at any time: same reason, message and node. A
     * retry that fails this way is not a change of state and is not written again.
     *
     * @param other The failure to compare with, or {@code null}.
     * @return {@code true} if both describe the same failure.
     */
    public boolean isSameFailureAs(EngineLoadFailure other) {
        return other != null
                && Objects.equals(this.reason, other.reason)
                && Objects.equals(this.message, other.message)
                && Objects.equals(this.node, other.node);
    }

    /**
     * Parses {@link #getFailedAt()}, to order the failures of several nodes.
     *
     * @return The time, or {@link Instant#EPOCH} if it is missing or not a valid instant.
     */
    Instant failedAtInstant() {
        if (this.failedAt == null) {
            return Instant.EPOCH;
        }
        try {
            return Instant.parse(this.failedAt);
        } catch (DateTimeParseException e) {
            return Instant.EPOCH;
        }
    }

    /**
     * Writes the failure's fields into the object currently open in {@code builder}.
     *
     * @param builder The builder, with an object started.
     * @throws IOException If the fields cannot be written.
     */
    void writeFields(XContentBuilder builder) throws IOException {
        builder
                .field(KEY_FAILED_AT, this.failedAt)
                .field(KEY_REASON, this.reason)
                .field(KEY_MESSAGE, this.message)
                .field(KEY_NODE, this.node);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof EngineLoadFailure other)) {
            return false;
        }
        return Objects.equals(this.failedAt, other.failedAt) && this.isSameFailureAs(other);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.failedAt, this.reason, this.message, this.node);
    }

    @Override
    public String toString() {
        return "EngineLoadFailure{"
                + "failedAt='"
                + this.failedAt
                + "', reason='"
                + this.reason
                + "', node='"
                + this.node
                + "', message='"
                + this.message
                + "'}";
    }
}
