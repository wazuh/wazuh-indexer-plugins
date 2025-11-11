/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.setup.utils;

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
 * <p>Fill-in values automatically using Jackson Databind. TODO consider use the Tree Model instead
 * of direct binding. Better for highly nested structures.
 */
public class IndexTemplate {

    @JsonProperty("index_patterns")
    private List<String> indexPatterns;

    private long priority;
    private Map<String, Object> template;
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

    public List<String> getIndexPatterns() {
        return this.indexPatterns;
    }

    public long getPriority() {
        return this.priority;
    }

    public Map<String, Object> getSettings() {
        return this.settings;
    }

    public Map<String, Object> getMappings() {
        return this.mappings;
    }

    public Map<String, Object> getDataStream() {
        return this.dataStream;
    }

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
                null,
                null,
                dataStreamTemplate);
    }
}
