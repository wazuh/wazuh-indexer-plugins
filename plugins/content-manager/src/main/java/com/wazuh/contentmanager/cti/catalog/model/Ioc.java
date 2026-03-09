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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Model representing an IoC (Indicator of Compromise) resource. Structured to match the {@code
 * subset.yml} and {@code ioc.json} template schema, with typed fields instead of generic maps.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public class Ioc {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @JsonProperty(Constants.KEY_DOCUMENT)
    private IocDocument document;

    @JsonProperty(Constants.KEY_HASH)
    private IocHash hash;

    @JsonProperty(Constants.KEY_OFFSET)
    private Long offset;

    /** Default constructor. */
    public Ioc() {}

    /**
     * Factory method to create an Ioc instance from a raw JsonNode payload.
     *
     * @param payload The raw JSON object containing the IoC data.
     * @return A fully populated Ioc instance.
     */
    public static Ioc fromPayload(JsonNode payload) {
        // Extract offset before conversion so it stays at root level
        Long offsetValue = null;
        if (payload.has(Constants.KEY_OFFSET)) {
            offsetValue = payload.get(Constants.KEY_OFFSET).asLong();
            if (payload.isObject()) {
                ((com.fasterxml.jackson.databind.node.ObjectNode) payload).remove(Constants.KEY_OFFSET);
            }
        }

        Ioc ioc = Ioc.MAPPER.convertValue(payload, Ioc.class);
        ioc.setOffset(offsetValue);
        if (payload.has(Constants.KEY_DOCUMENT)) {
            String sha256 = Resource.computeSha256(payload.get(Constants.KEY_DOCUMENT).toString());
      // TODO: check the commented code (current code)
      //  // Strip the routing 'type' field before deserialization
      //  ObjectNode sanitizedPayload = payload.deepCopy();
      //  sanitizedPayload.remove(Constants.KEY_TYPE);

      //  Ioc ioc = Ioc.MAPPER.convertValue(sanitizedPayload, Ioc.class);
      //  if (sanitizedPayload.has(Constants.KEY_DOCUMENT)) {
      //      String sha256 =
      //              Resource.computeSha256(sanitizedPayload.get(Constants.KEY_DOCUMENT).toString());
            ioc.setHash(new IocHash(sha256));
        }
        return ioc;
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
     * Gets the hash.
     *
     * @return The IoC hash.
     */
    public IocHash getHash() {
        return this.hash;
    }

    /**
     * Sets the hash.
     *
     * @param hash The IoC hash.
     */
    public void setHash(IocHash hash) {
        this.hash = hash;
    }

    /**
     * Gets the CTI offset.
     *
     * @return The CTI offset value, or null if not set.
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
     * Represents the {@code document} object within an IoC. Uses proper nested classes to handle
     * structures like "feed" and "software".
     */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class IocDocument {

        private static final String CONFIDENCE_KEY = "confidence";
        private static final String FIRST_SEEN_KEY = "first_seen";
        private static final String ID_KEY = "id";
        private static final String LAST_SEEN_KEY = "last_seen";
        private static final String NAME_KEY = "name";
        private static final String PROVIDER_KEY = "provider";
        private static final String REFERENCE_KEY = "reference";
        private static final String TYPE_KEY = "type";
        private static final String TAGS_KEY = "tags";
        private static final String FEED_KEY = "feed";
        private static final String SOFTWARE_KEY = "software";

        @JsonProperty(IocDocument.CONFIDENCE_KEY)
        private Long confidence;

        @JsonProperty(IocDocument.FIRST_SEEN_KEY)
        private String firstSeen;

        @JsonProperty(IocDocument.ID_KEY)
        private String id;

        @JsonProperty(IocDocument.LAST_SEEN_KEY)
        private String lastSeen;

        @JsonProperty(IocDocument.NAME_KEY)
        private String name;

        @JsonProperty(IocDocument.PROVIDER_KEY)
        private String provider;

        @JsonProperty(IocDocument.REFERENCE_KEY)
        private String reference;

        @JsonProperty(IocDocument.TYPE_KEY)
        private String type;

        @JsonProperty(IocDocument.TAGS_KEY)
        private List<String> tags;

        @JsonProperty(IocDocument.FEED_KEY)
        private Feed feed;

        @JsonProperty(IocDocument.SOFTWARE_KEY)
        private Software software;

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

        /**
         * Gets the feed object.
         *
         * @return The feed object.
         */
        public Feed getFeed() {
            return this.feed;
        }

        /**
         * Sets the feed object.
         *
         * @param feed The feed object.
         */
        public void setFeed(Feed feed) {
            this.feed = feed;
        }

        /**
         * Gets the software object.
         *
         * @return The software object.
         */
        public Software getSoftware() {
            return this.software;
        }

        /**
         * Sets the software object.
         *
         * @param software The feed object.
         */
        public void setSoftware(Software software) {
            this.software = software;
        }

        /** Represents the {@code feed} object within an IoC document. */
        @JsonInclude(JsonInclude.Include.ALWAYS)
        public static class Feed {
            @JsonProperty("name")
            private String name;

            public Feed() {}

            /**
             * Gets the feed.name field.
             *
             * @return The feed.name object.
             */
            public String getName() {
                return this.name;
            }

            /**
             * Sets the feed.name field.
             *
             * @param name The feed.name object.
             */
            public void setName(String name) {
                this.name = name;
            }
        }

        /** Represents the {@code software} object within an IoC document. */
        @JsonInclude(JsonInclude.Include.ALWAYS)
        public static class Software {
            @JsonProperty("alias")
            private List<String> alias;

            @JsonProperty("name")
            private String name;

            @JsonProperty("type")
            private String type;

            public Software() {}

            /**
             * Gets the software.alias field.
             *
             * @return The software.alias list.
             */
            public List<String> getAlias() {
                return this.alias;
            }

            /**
             * Sets the software.alias field.
             *
             * @param alias The software.alias list.
             */
            public void setAlias(List<String> alias) {
                this.alias = alias;
            }

            /**
             * Gets the software.name field.
             *
             * @return The software.name object.
             */
            public String getName() {
                return this.name;
            }

            /**
             * Sets the software.name field.
             *
             * @param name The software.name list.
             */
            public void setName(String name) {
                this.name = name;
            }

            /**
             * Gets the software.type field.
             *
             * @return The software.type object.
             */
            public String getType() {
                return this.type;
            }

            /**
             * Sets the software.type field.
             *
             * @param type The software.type list.
             */
            public void setType(String type) {
                this.type = type;
            }
        }
    }

    /** Represents the {@code hash} object within an IoC, containing a SHA-256 checksum. */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class IocHash {

        private static final String SHA256_KEY = "sha256";

        @JsonProperty(SHA256_KEY)
        private String sha256;

        /** Default constructor. */
        public IocHash() {}

        /**
         * Creates an IocHash with the given SHA-256 value.
         *
         * @param sha256 The SHA-256 hash string.
         */
        public IocHash(String sha256) {
            this.sha256 = sha256;
        }

        /**
         * Gets the SHA-256 hash.
         *
         * @return The SHA-256 hash string.
         */
        public String getSha256() {
            return this.sha256;
        }

        /**
         * Sets the SHA-256 hash.
         *
         * @param sha256 The SHA-256 hash string.
         */
        public void setSha256(String sha256) {
            this.sha256 = sha256;
        }
    }
}
