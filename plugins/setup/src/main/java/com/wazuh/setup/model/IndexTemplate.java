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
package com.wazuh.setup.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;

import java.util.List;
import java.util.Map;

/**
 * Index Template Data Transfer Object.
 *
 * <p>Fill-in values automatically using Jackson Databind.
 */
public class IndexTemplate {

    /** Default constructor */
    public IndexTemplate() {}

    /** Key of the mapping metadata object holding the schema versions. */
    public static final String META_KEY = "_meta";

    /** Key of the release that last changed the template. */
    public static final String SCHEMA_VERSION_KEY = "schema_version";

    /** Key of the oldest schema version whose indices can be upgraded in place. */
    public static final String COMPAT_VERSION_KEY = "compat_version";

    @JsonProperty("index_patterns")
    private List<String> indexPatterns;

    private long priority;

    @JsonProperty("version")
    private Long version;

    private Map<String, Object> settings;
    private Map<String, Object> mappings;

    @JsonProperty("data_stream")
    private Map<String, Object> dataStream;

    @SuppressWarnings("unchecked")
    @JsonProperty("template")
    private void unpackNested(Map<String, Object> template) {
        this.settings = (Map<String, Object>) template.get("settings");
        this.mappings = (Map<String, Object>) template.get("mappings");
    }

    /**
     * Index pattern getter.
     *
     * @return returns the list of index patters this index template applies to, or null.
     */
    public List<String> getIndexPatterns() {
        return this.indexPatterns;
    }

    /**
     * Index pattern setter.
     *
     * @param indexPatterns the list of index patterns to apply.
     */
    public void setIndexPatterns(List<String> indexPatterns) {
        this.indexPatterns = indexPatterns;
    }

    /**
     * Index template priority getter.
     *
     * @return returns the priority of the index template, or null.
     */
    public long getPriority() {
        return this.priority;
    }

    /**
     * Index template version getter. It is the release that last changed the template, as a
     * five-digit release number (5.0.0 is 50000, 5.2.1 is 50201).
     *
     * @return returns the version of the index template, or null when the file declares none.
     */
    public Long getVersion() {
        return this.version;
    }

    /**
     * Returns the schema versions declared in the mapping metadata ({@code mappings._meta}), or null
     * when the template declares none.
     *
     * @return map with the {@value #SCHEMA_VERSION_KEY} and {@value #COMPAT_VERSION_KEY} entries.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getSchemaVersions() {
        if (this.mappings == null || !(this.mappings.get(META_KEY) instanceof Map)) {
            return null;
        }
        return (Map<String, Object>) this.mappings.get(META_KEY);
    }

    /**
     * Checks that the template declares its schema versions: the native {@code version} field, and
     * {@code schema_version} and {@code compat_version} under {@code mappings._meta}, both positive
     * integers, with {@code compat_version} not greater than {@code schema_version} and {@code
     * version} equal to {@code schema_version}. Every index created from the template inherits the
     * mapping metadata, which is how the plugin tells on a later boot whether the index needs an
     * upgrade.
     *
     * @param templateName name of the template, used in the error message.
     * @throws IllegalArgumentException if any of the fields is missing or inconsistent.
     */
    public void validateSchemaVersions(String templateName) {
        if (this.version == null) {
            throw new IllegalArgumentException(
                    "Index template [" + templateName + "] declares no version");
        }
        Map<String, Object> versions = this.getSchemaVersions();
        if (versions == null) {
            throw new IllegalArgumentException(
                    "Index template [" + templateName + "] declares no mappings." + META_KEY + " object");
        }
        long schemaVersion = positiveInteger(versions, SCHEMA_VERSION_KEY, templateName);
        long compatVersion = positiveInteger(versions, COMPAT_VERSION_KEY, templateName);
        if (compatVersion > schemaVersion) {
            throw new IllegalArgumentException(
                    "Index template ["
                            + templateName
                            + "] declares a "
                            + COMPAT_VERSION_KEY
                            + " ("
                            + compatVersion
                            + ") greater than its "
                            + SCHEMA_VERSION_KEY
                            + " ("
                            + schemaVersion
                            + ")");
        }
        if (this.version != schemaVersion) {
            throw new IllegalArgumentException(
                    "Index template ["
                            + templateName
                            + "] declares a version ("
                            + this.version
                            + ") different from its "
                            + SCHEMA_VERSION_KEY
                            + " ("
                            + schemaVersion
                            + ")");
        }
    }

    /**
     * Reads a positive integer entry of the schema versions map.
     *
     * @param versions the schema versions map.
     * @param key entry to read.
     * @param templateName name of the template, used in the error message.
     * @return the value as a long.
     * @throws IllegalArgumentException if the entry is missing, not an integer or not positive.
     */
    private static long positiveInteger(
            Map<String, Object> versions, String key, String templateName) {
        Object value = versions.get(key);
        if (!(value instanceof Integer || value instanceof Long) || ((Number) value).longValue() <= 0) {
            throw new IllegalArgumentException(
                    "Index template ["
                            + templateName
                            + "] declares no positive integer "
                            + key
                            + " under mappings."
                            + META_KEY);
        }
        return ((Number) value).longValue();
    }

    /**
     * Index settings getter.
     *
     * @return returns the index settings to apply to indices matching the index pattern, or null.
     */
    public Map<String, Object> getSettings() {
        return this.settings;
    }

    /**
     * Index mappings getter.
     *
     * @return returns the index mappings for the indices matching the index pattern, or null.
     */
    public Map<String, Object> getMappings() {
        return this.mappings;
    }

    /**
     * Data Stream getter.
     *
     * @return returns the "data_stream" property of the index template, or null.
     */
    public Map<String, Object> getDataStream() {
        return this.dataStream;
    }

    /**
     * Builds up a ComposableIndexTemplate resulting from the properties of the index template.
     *
     * @param settings index template settings as a string.
     * @param compressedMapping index template mappings a CompressedXContent instance.
     * @return instance of ComposableIndexTemplate.
     */
    public ComposableIndexTemplate getComposableIndexTemplate(
            Settings settings, CompressedXContent compressedMapping) {
        ComposableIndexTemplate.DataStreamTemplate dataStreamTemplate =
                this.getDataStream() != null ? new ComposableIndexTemplate.DataStreamTemplate() : null;

        // Create the composable template
        return new ComposableIndexTemplate(
                this.getIndexPatterns(),
                new Template(settings, compressedMapping, null),
                null,
                this.getPriority(),
                this.getVersion(),
                null,
                dataStreamTemplate);
    }
}
