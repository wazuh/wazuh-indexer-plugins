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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * Model representing an IoC (Indicator of Compromise) resource. Structured to match the {@code
 * subset.yml} and {@code ioc.json} template schema, with typed fields instead of generic maps.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Ioc extends Resource {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String DOCUMENT_KEY = "document";

    @JsonProperty(DOCUMENT_KEY)
    private IocDocument document;

    /** Default constructor. */
    public Ioc() {}

    /**
     * Factory method to create an Ioc instance from a raw JsonNode payload.
     *
     * @param payload The raw JSON object containing the IoC data.
     * @return A fully populated Ioc instance.
     */
    public static Ioc fromPayload(JsonNode payload) {
        return MAPPER.convertValue(payload, Ioc.class);
    }

    /**
     * Gets the document.
     *
     * @return The IoC document.
     */
    public IocDocument getDocument() {
        return this.document;
    }

    /**
     * Sets the document.
     *
     * @param document The IoC document.
     */
    public void setDocument(IocDocument document) {
        this.document = document;
    }

    /**
     * Represents the {@code document} object within an IoC. Uses flat dot-notation keys (e.g. {@code
     * "feed.name"}, {@code "software.type"}) matching the CTI payload structure.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class IocDocument {

        private static final String CONFIDENCE_KEY = "confidence";
        private static final String FEED_NAME_KEY = "feed.name";
        private static final String FIRST_SEEN_KEY = "first_seen";
        private static final String ID_KEY = "id";
        private static final String LAST_SEEN_KEY = "last_seen";
        private static final String NAME_KEY = "name";
        private static final String PROVIDER_KEY = "provider";
        private static final String REFERENCE_KEY = "reference";
        private static final String TYPE_KEY = "type";
        private static final String SOFTWARE_ALIAS_KEY = "software.alias";
        private static final String SOFTWARE_NAME_KEY = "software.name";
        private static final String SOFTWARE_TYPE_KEY = "software.type";
        private static final String TAGS_KEY = "tags";

        @JsonProperty(CONFIDENCE_KEY)
        private Long confidence;

        @JsonProperty(FEED_NAME_KEY)
        private String feedName;

        @JsonProperty(FIRST_SEEN_KEY)
        private String firstSeen;

        @JsonProperty(ID_KEY)
        private String id;

        @JsonProperty(LAST_SEEN_KEY)
        private String lastSeen;

        @JsonProperty(NAME_KEY)
        private String name;

        @JsonProperty(PROVIDER_KEY)
        private String provider;

        @JsonProperty(REFERENCE_KEY)
        private String reference;

        @JsonProperty(TYPE_KEY)
        private String type;

        @JsonProperty(SOFTWARE_ALIAS_KEY)
        private List<String> softwareAlias;

        @JsonProperty(SOFTWARE_NAME_KEY)
        private String softwareName;

        @JsonProperty(SOFTWARE_TYPE_KEY)
        private String softwareType;

        @JsonProperty(TAGS_KEY)
        private List<String> tags;

        /** Default constructor. */
        public IocDocument() {}

        /**
         * Gets the confidence score.
         *
         * @return The confidence score.
         */
        public Long getConfidence() {
            return this.confidence;
        }

        /**
         * Sets the confidence score.
         *
         * @param confidence The confidence score.
         */
        public void setConfidence(Long confidence) {
            this.confidence = confidence;
        }

        /**
         * Gets the feed name.
         *
         * @return The feed name.
         */
        public String getFeedName() {
            return this.feedName;
        }

        /**
         * Sets the feed name.
         *
         * @param feedName The feed name.
         */
        public void setFeedName(String feedName) {
            this.feedName = feedName;
        }

        /**
         * Gets the first seen date.
         *
         * @return The first seen date.
         */
        public String getFirstSeen() {
            return this.firstSeen;
        }

        /**
         * Sets the first seen date.
         *
         * @param firstSeen The first seen date.
         */
        public void setFirstSeen(String firstSeen) {
            this.firstSeen = firstSeen;
        }

        /**
         * Gets the IoC identifier.
         *
         * @return The id.
         */
        public String getId() {
            return this.id;
        }

        /**
         * Sets the IoC identifier.
         *
         * @param id The id.
         */
        public void setId(String id) {
            this.id = id;
        }

        /**
         * Gets the last seen date.
         *
         * @return The last seen date.
         */
        public String getLastSeen() {
            return this.lastSeen;
        }

        /**
         * Sets the last seen date.
         *
         * @param lastSeen The last seen date.
         */
        public void setLastSeen(String lastSeen) {
            this.lastSeen = lastSeen;
        }

        /**
         * Gets the name.
         *
         * @return The name.
         */
        public String getName() {
            return this.name;
        }

        /**
         * Sets the name.
         *
         * @param name The name.
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * Gets the provider.
         *
         * @return The provider.
         */
        public String getProvider() {
            return this.provider;
        }

        /**
         * Sets the provider.
         *
         * @param provider The provider.
         */
        public void setProvider(String provider) {
            this.provider = provider;
        }

        /**
         * Gets the reference.
         *
         * @return The reference.
         */
        public String getReference() {
            return this.reference;
        }

        /**
         * Sets the reference.
         *
         * @param reference The reference.
         */
        public void setReference(String reference) {
            this.reference = reference;
        }

        /**
         * Gets the type.
         *
         * @return The type.
         */
        public String getType() {
            return this.type;
        }

        /**
         * Sets the type.
         *
         * @param type The type.
         */
        public void setType(String type) {
            this.type = type;
        }

        /**
         * Gets the software aliases.
         *
         * @return The list of software aliases.
         */
        public List<String> getSoftwareAlias() {
            return this.softwareAlias;
        }

        /**
         * Sets the software aliases.
         *
         * @param softwareAlias The list of software aliases.
         */
        public void setSoftwareAlias(List<String> softwareAlias) {
            this.softwareAlias = softwareAlias;
        }

        /**
         * Gets the software name.
         *
         * @return The software name.
         */
        public String getSoftwareName() {
            return this.softwareName;
        }

        /**
         * Sets the software name.
         *
         * @param softwareName The software name.
         */
        public void setSoftwareName(String softwareName) {
            this.softwareName = softwareName;
        }

        /**
         * Gets the software type.
         *
         * @return The software type.
         */
        public String getSoftwareType() {
            return this.softwareType;
        }

        /**
         * Sets the software type.
         *
         * @param softwareType The software type.
         */
        public void setSoftwareType(String softwareType) {
            this.softwareType = softwareType;
        }

        /**
         * Gets the tags.
         *
         * @return The list of tags.
         */
        public List<String> getTags() {
            return this.tags;
        }

        /**
         * Sets the tags.
         *
         * @param tags The list of tags.
         */
        public void setTags(List<String> tags) {
            this.tags = tags;
        }
    }
}
