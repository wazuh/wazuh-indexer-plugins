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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/** Tests for the schema versions an {@link IndexTemplate} must declare. */
public class IndexTemplateTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A minimal template that declares its versions consistently. */
    private static final String VALID =
            "{"
                    + "\"index_patterns\": [\"test*\"],"
                    + "\"priority\": 1,"
                    + "\"version\": 50100,"
                    + "\"template\": {"
                    + "  \"settings\": {\"index\": {\"number_of_shards\": \"1\"}},"
                    + "  \"mappings\": {"
                    + "    \"dynamic\": \"strict\","
                    + "    \"properties\": {\"name\": {\"type\": \"keyword\"}},"
                    + "    \"_meta\": {\"schema_version\": 50100, \"compat_version\": 50000}"
                    + "  }"
                    + "}}";

    private static IndexTemplate parse(String json) throws IOException {
        return MAPPER.readValue(json, IndexTemplate.class);
    }

    /** Verifies that the version and the mapping metadata are read from the file. */
    public void testParsesSchemaVersions() throws IOException {
        IndexTemplate template = parse(VALID);

        assertEquals(Long.valueOf(50100), template.getVersion());
        assertEquals(50100, template.getSchemaVersions().get(IndexTemplate.SCHEMA_VERSION_KEY));
        assertEquals(50000, template.getSchemaVersions().get(IndexTemplate.COMPAT_VERSION_KEY));
        template.validateSchemaVersions("test");
    }

    /** Verifies that the native version reaches the composable template. */
    public void testComposableTemplateCarriesTheVersion() throws IOException {
        IndexTemplate template = parse(VALID);
        Settings settings = Settings.builder().loadFromMap(template.getSettings()).build();
        CompressedXContent mappings =
                new CompressedXContent(MAPPER.writeValueAsString(template.getMappings()));

        ComposableIndexTemplate composable = template.getComposableIndexTemplate(settings, mappings);

        assertEquals(Long.valueOf(50100), composable.version());
    }

    /** A template without the native version field is rejected. */
    public void testRejectsMissingVersion() throws IOException {
        IndexTemplate template = parse(VALID.replace("\"version\": 50100,", ""));

        IllegalArgumentException e =
                expectThrows(IllegalArgumentException.class, () -> template.validateSchemaVersions("test"));
        assertTrue(e.getMessage(), e.getMessage().contains("[test] declares no version"));
    }

    /** A template without the mapping metadata is rejected. */
    public void testRejectsMissingMeta() throws IOException {
        IndexTemplate template =
                parse(
                        VALID.replace(
                                ",    \"_meta\": {\"schema_version\": 50100, \"compat_version\": 50000}", ""));

        IllegalArgumentException e =
                expectThrows(IllegalArgumentException.class, () -> template.validateSchemaVersions("test"));
        assertTrue(e.getMessage(), e.getMessage().contains("mappings._meta"));
    }

    /** A schema version that is not a positive integer is rejected. */
    public void testRejectsNonIntegerSchemaVersion() throws IOException {
        IndexTemplate template =
                parse(VALID.replace("\"schema_version\": 50100", "\"schema_version\": \"5.1.0\""));

        IllegalArgumentException e =
                expectThrows(IllegalArgumentException.class, () -> template.validateSchemaVersions("test"));
        assertTrue(e.getMessage(), e.getMessage().contains("positive integer schema_version"));
    }

    /** A compatibility version greater than the schema version is rejected. */
    public void testRejectsCompatGreaterThanSchema() throws IOException {
        IndexTemplate template =
                parse(VALID.replace("\"compat_version\": 50000", "\"compat_version\": 50200"));

        IllegalArgumentException e =
                expectThrows(IllegalArgumentException.class, () -> template.validateSchemaVersions("test"));
        assertTrue(e.getMessage(), e.getMessage().contains("compat_version (50200) greater than"));
    }

    /** A native version different from the schema version is rejected. */
    public void testRejectsVersionDifferentFromSchemaVersion() throws IOException {
        IndexTemplate template = parse(VALID.replace("\"version\": 50100,", "\"version\": 50000,"));

        IllegalArgumentException e =
                expectThrows(IllegalArgumentException.class, () -> template.validateSchemaVersions("test"));
        assertTrue(e.getMessage(), e.getMessage().contains("version (50000) different"));
    }

    /**
     * Verifies that every index template shipped with the plugin declares its schema versions. The
     * Setup plugin refuses to start on a template without them, so a template added to the resources
     * without going through the schema generator would take the node down.
     *
     * @throws Exception if the templates directory cannot be listed or a template cannot be read.
     */
    public void testShippedTemplatesDeclareSchemaVersions() throws Exception {
        URL marker = IndexTemplate.class.getClassLoader().getResource("templates/setup-status.json");
        assertNotNull("templates/setup-status.json is not on the classpath", marker);
        Path templates = PathUtils.get(marker.toURI()).getParent();

        List<Path> files;
        try (Stream<Path> walk = Files.walk(templates)) {
            files = walk.filter(path -> path.toString().endsWith(".json")).sorted().toList();
        }
        assertFalse("no templates found under " + templates, files.isEmpty());

        for (Path file : files) {
            String name = templates.relativize(file).toString();
            try (InputStream is = Files.newInputStream(file)) {
                IndexTemplate template = MAPPER.readValue(is, IndexTemplate.class);
                template.validateSchemaVersions(name);
            }
        }
    }
}
