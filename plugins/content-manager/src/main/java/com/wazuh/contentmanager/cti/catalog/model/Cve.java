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
 * Model representing a CVE (Common Vulnerabilities and Exposures) resource.
 *
 * <p>CVE content is indexed under the {@code document} field, and may include a top-level {@code
 * offset}. Unlike most content resources, CVEs do not have a space field.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Cve {

    private static final String KEY_PAYLOAD = "payload";
    private static final String KEY_DOCUMENT = Constants.KEY_DOCUMENT;

    @JsonProperty(KEY_DOCUMENT)
    private JsonNode document;

    @JsonProperty(Constants.KEY_OFFSET)
    private Long offset;

    /** Default constructor. */
    public Cve() {}

    /**
     * Factory method to create a Cve instance from a raw JsonNode payload.
     *
     * <p>If the input contains an {@code offset} field (injected by update/snapshot pipelines), it is
     * extracted to the top-level {@code offset} property.
     *
     * <p>The input can be either a raw CVE JSON document, a {@code document}-wrapped payload, or a
     * legacy {@code payload}-wrapped payload.
     *
     * @param payload The raw JSON object containing the CVE data.
     * @return A fully populated Cve instance.
     */
    public static Cve fromPayload(JsonNode payload) {
        Cve cve = new Cve();

        if (payload == null || payload.isNull()) {
            return cve;
        }

        JsonNode normalized = payload;

        // Extract offset from the incoming node so it is always indexed at document root.
        if (normalized.isObject() && normalized.has(Constants.KEY_OFFSET)) {
            cve.setOffset(normalized.get(Constants.KEY_OFFSET).asLong());
            ObjectNode stripped = (ObjectNode) normalized.deepCopy();
            stripped.remove(Constants.KEY_OFFSET);
            normalized = stripped;
        }

        if (normalized.isObject()) {
            // Accept both new and legacy wrappers while always serializing to `document`.
            if (normalized.has(KEY_DOCUMENT)) {
                cve.setDocument(normalized.get(KEY_DOCUMENT));
                return cve;
            }
            if (normalized.has(KEY_PAYLOAD)) {
                cve.setDocument(normalized.get(KEY_PAYLOAD));
                return cve;
            }
        }

        // Raw CVE payload (no wrapper).
        cve.setDocument(normalized);
        return cve;
    }

    /**
     * Gets the document.
     *
     * @return The CVE document.
     */
    public JsonNode getDocument() {
        return this.document;
    }

    /**
     * Sets the document.
     *
     * @param document The CVE document.
     */
    public void setDocument(JsonNode document) {
        this.document = document;
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
