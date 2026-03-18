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

import java.util.Arrays;
import java.util.Locale;

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

    @JsonProperty(Constants.KEY_DOCUMENT)
    private JsonNode document;

    @JsonProperty(Constants.KEY_OFFSET)
    private Long offset;

    @JsonProperty(Constants.KEY_TYPE)
    private String type;

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
        return fromPayload(payload, null);
    }

    /**
     * Factory method to create a Cve instance from a raw JsonNode payload and resource name.
     *
     * <p>When provided, {@code resourceName} is used to derive the indexed {@code type} using {@link
     * #deriveType(String)}.
     *
     * @param payload The raw JSON object containing the CVE data.
     * @param resourceName The CTI resource name/id.
     * @return A fully populated Cve instance.
     */
    public static Cve fromPayload(JsonNode payload, String resourceName) {
        Cve cve = new Cve();

        if (payload == null || payload.isNull()) {
            return cve;
        }

        JsonNode normalized = payload;

        // Extract offset from the incoming node so it is always indexed at document root.
        if (normalized.isObject() && normalized.has(Constants.KEY_OFFSET)) {
            cve.setOffset(normalized.get(Constants.KEY_OFFSET).asLong());
            ObjectNode stripped = normalized.deepCopy();
            stripped.remove(Constants.KEY_OFFSET);
            normalized = stripped;
        }

        String explicitType = null;
        if (normalized.isObject() && normalized.hasNonNull(Constants.KEY_TYPE)) {
            explicitType = normalized.get(Constants.KEY_TYPE).asText();
            CveContentType mappedType = CveContentType.fromValue(explicitType);
            if (mappedType != null) {
                cve.setType(mappedType.getValue());
            }
        }

        if (normalized.isObject()) {
            // Accept both new and legacy wrappers while always serializing to `document`.
            if (normalized.has(Constants.KEY_DOCUMENT)) {
                cve.setDocument(normalized.get(Constants.KEY_DOCUMENT));
                if (cve.getType() == null) {
                    cve.setType(deriveType(resourceName));
                }
                if (cve.getType() == null && explicitType != null) {
                    cve.setType(explicitType);
                }
                return cve;
            }
            if (normalized.has(Constants.KEY_PAYLOAD)) {
                cve.setDocument(normalized.get(Constants.KEY_PAYLOAD));
                if (cve.getType() == null) {
                    cve.setType(deriveType(resourceName));
                }
                if (cve.getType() == null && explicitType != null) {
                    cve.setType(explicitType);
                }
                return cve;
            }

            // `type` at payload root is catalog metadata, not part of the CVE document body.
            if (normalized.has(Constants.KEY_TYPE)) {
                ((ObjectNode) normalized).remove(Constants.KEY_TYPE);
            }
        }

        // Raw CVE payload (no wrapper).
        cve.setDocument(normalized);
        if (cve.getType() == null) {
            cve.setType(deriveType(resourceName));
        }
        if (cve.getType() == null && explicitType != null) {
            cve.setType(explicitType);
        }
        return cve;
    }

    /**
     * Derives CTI CVE type from the resource name/id.
     *
     * @param resourceName The CTI resource name (e.g. CVE-2026-0001, TID-001).
     * @return The canonical CVE type value, or null when the pattern is unknown.
     */
    public static String deriveType(String resourceName) {
        CveContentType type = CveContentType.fromResourceName(resourceName);
        return type != null ? type.getValue() : null;
    }

    private enum CveContentType {
        CNA_MAPPING_GLOBAL("CNA-MAPPING-GLOBAL"),
        CVE("CVE"),
        FEED_GLOBAL("FEED-GLOBAL"),
        OSCPE_GLOBAL("OSCPE-GLOBAL"),
        TCPE("TCPE"),
        TID("TID"),
        TVENDORS("TVENDORS");

        private final String value;

        CveContentType(String value) {
            this.value = value;
        }

        private String getValue() {
            return this.value;
        }

        private static CveContentType fromValue(String value) {
            if (value == null) {
                return null;
            }
            return Arrays.stream(values())
                    .filter(type -> type.value.equalsIgnoreCase(value))
                    .findFirst()
                    .orElse(null);
        }

        private static CveContentType fromResourceName(String resourceName) {
            if (resourceName == null || resourceName.isBlank()) {
                return null;
            }

            String normalized = resourceName.trim().toUpperCase(Locale.ROOT);

            if (normalized.startsWith("CVE-")) {
                return CVE;
            }
            if (normalized.startsWith("TID-")) {
                return TID;
            }
            return switch (normalized) {
                case "CNA-MAPPING-GLOBAL" -> CNA_MAPPING_GLOBAL;
                case "FEED-GLOBAL" -> FEED_GLOBAL;
                case "OSCPE-GLOBAL" -> OSCPE_GLOBAL;
                case "TCPE" -> TCPE;
                case "TVENDORS" -> TVENDORS;
                default -> null;
            };
        }
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

    /**
     * Gets the CTI Content type.
     *
     * @return The CTI Content value.
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the CTI Content type.
     *
     * @param type The CTI content value.
     */
    public void setType(String type) {
        this.type = type;
    }
}
