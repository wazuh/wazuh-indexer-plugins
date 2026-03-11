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
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Model representing a CVE (Common Vulnerabilities and Exposures) resource. CVE documents contain a
 * payload with the CVE data and a hash for integrity verification. Unlike other resources, CVEs do
 * not have a space field.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Cve {

    private static final String KEY_PAYLOAD = "payload";

    @JsonProperty(KEY_PAYLOAD)
    private JsonNode payload;

    @JsonProperty(Constants.KEY_OFFSET)
    private Long offset;

    /** Default constructor. */
    public Cve() {}

    /**
     * Factory method to create a Cve instance from a raw JsonNode payload.
     *
     * <p>If the payload contains an {@code offset} field (injected by the update pipeline), it is
     * extracted to the top-level {@code offset} property and removed from the payload so it does not
     * violate the strict index mapping.
     *
     * @param payload The raw JSON object containing the CVE data.
     * @return A fully populated Cve instance.
     */
    public static Cve fromPayload(JsonNode payload) {
        Cve cve = new Cve();

        // Extract offset from the payload node before storing it, so the field stays at the
        // document root rather than inside the strict-mapped payload object.
        if (payload.has(Constants.KEY_OFFSET)) {
            cve.setOffset(payload.get(Constants.KEY_OFFSET).asLong());
            ObjectNode stripped = ((ObjectNode) payload).deepCopy();
            stripped.remove(Constants.KEY_OFFSET);
            payload = stripped;
        }

        cve.setPayload(payload);

        return cve;
    }

    /**
     * Gets the payload.
     *
     * @return The CVE payload.
     */
    public JsonNode getPayload() {
        return this.payload;
    }

    /**
     * Sets the payload.
     *
     * @param payload The CVE payload.
     */
    public void setPayload(JsonNode payload) {
        this.payload = payload;
    }

    /**
     * Gets the CTI offset.
     *
     * @return The CTI offset value.
     */
    public Long getOffset() {
        return this.offset;
    }

    /**
     * Sets the CTI offset.
     *
     * @param offset The CTI offset value.
     */
    public void setOffset(Long offset) {
        this.offset = offset;
    }

}
