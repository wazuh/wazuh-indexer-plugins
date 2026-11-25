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
package com.wazuh.setup.index;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.Level;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.Version;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Assert;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.wazuh.setup.config.SetupConfig;
import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.utils.CapturingAppender;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for the settings {@link Index} stores in the index templates when the configuration
 * file of the plugin overrides some of them. They use the index templates bundled in the plugin.
 */
public class TemplateSettingsTests extends OpenSearchTestCase {

    private static final String EVENTS_TEMPLATE = "templates/streams/events";
    private static final String SCA_TEMPLATE = "templates/states/sca";
    private static final String RULES_TEMPLATE = "templates/content/rules";
    private static final List<String> TEMPLATES =
            List.of(EVENTS_TEMPLATE, SCA_TEMPLATE, RULES_TEMPLATE);

    private static final String EVENTS_STREAM = "wazuh-events-v5-security";
    private static final String SCA_INDEX = "wazuh-states-sca";
    private static final String RULES_ALIAS = "wazuh-threatintel-rules";

    private static final String SHARDS = "index.number_of_shards";
    private static final String REPLICAS = "index.number_of_replicas";
    private static final String AUTO_EXPAND = "index.auto_expand_replicas";
    private static final String REFRESH = "index.refresh_interval";

    private Client client;
    private ClusterService clusterService;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.clusterService = mock(ClusterService.class);
        doReturn(Settings.EMPTY).when(this.clusterService).getSettings();
        doReturn(mock(ActionFuture.class))
                .when(this.client)
                .execute(eq(PutComposableIndexTemplateAction.INSTANCE), any());
        this.setClusterState();
    }

    /**
     * Makes the cluster hold the given indices and data streams.
     *
     * @param indices the indices of the cluster. One named as a backing index makes its data stream.
     */
    private void setClusterState(IndexMetadata... indices) {
        Metadata.Builder metadata = Metadata.builder();
        for (IndexMetadata index : indices) {
            metadata.put(index, false);
            String name = index.getIndex().getName();
            if (name.startsWith(DataStream.BACKING_INDEX_PREFIX)) {
                metadata.put(
                        new DataStream(
                                EVENTS_STREAM,
                                new DataStream.TimestampField("@timestamp"),
                                List.of(index.getIndex())));
            }
        }
        doReturn(ClusterState.builder(ClusterName.DEFAULT).metadata(metadata).build())
                .when(this.clusterService)
                .state();
    }

    /**
     * Builds the metadata of an existing index.
     *
     * @param name name of the index.
     * @param settings settings of the index, on top of one shard and no replicas.
     * @return the metadata.
     */
    private static IndexMetadata.Builder existing(String name, Settings settings) {
        return IndexMetadata.builder(name)
                .settings(
                        Settings.builder()
                                .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                                .put(SHARDS, 1)
                                .put(REPLICAS, 0)
                                .put(settings));
    }

    /**
     * Gives an index its dependencies and the configuration read from a file with the given content.
     *
     * @param index the index.
     * @param yaml content of the configuration file, or null for no file.
     * @param <T> type of the index.
     * @return the index.
     * @throws IOException if the file cannot be written.
     */
    private <T extends Index> T configure(T index, String yaml) throws IOException {
        index.setClient(this.client);
        index.setClusterService(this.clusterService);
        if (yaml != null) {
            Path directory = LuceneTestCase.createTempDir();
            Files.writeString(directory.resolve(SetupConfig.FILE), yaml, StandardCharsets.UTF_8);
            index.setConfig(
                    SetupConfig.load(directory, TEMPLATES, List.of(), NamedXContentRegistry.EMPTY));
        }
        return index;
    }

    /**
     * Reads an index template bundled in the plugin.
     *
     * @param template resource path of the template.
     * @return the template.
     * @throws IOException if the resource cannot be read.
     */
    private static IndexTemplate bundled(String template) throws IOException {
        try (InputStream is =
                TemplateSettingsTests.class.getClassLoader().getResourceAsStream(template + ".json")) {
            return new ObjectMapper().readValue(is, IndexTemplate.class);
        }
    }

    /**
     * Creates the index template of an index and returns what was sent to the cluster.
     *
     * @param index the index.
     * @return the index template of the request.
     */
    private ComposableIndexTemplate createTemplate(Index index) {
        index.createTemplate(index.getTemplate());
        ArgumentCaptor<PutComposableIndexTemplateAction.Request> captor =
                ArgumentCaptor.forClass(PutComposableIndexTemplateAction.Request.class);
        verify(this.client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), captor.capture());
        clearInvocations(this.client);
        return captor.getValue().indexTemplate();
    }

    /**
     * Asserts that an override changes the settings of the stored index template and nothing else.
     *
     * @param plain the index without a configuration file.
     * @param overridden the same index, with three shards in its configuration file.
     */
    private void assertOnlyTheSettingsChange(Index plain, Index overridden) {
        ComposableIndexTemplate before = this.createTemplate(plain);
        ComposableIndexTemplate after = this.createTemplate(overridden);

        Assert.assertEquals("1", before.template().settings().get(SHARDS));
        Assert.assertEquals("3", after.template().settings().get(SHARDS));
        Assert.assertEquals(
                before.template().settings().filter(key -> !SHARDS.equals(key)),
                after.template().settings().filter(key -> !SHARDS.equals(key)));
        Assert.assertEquals(before.template().mappings(), after.template().mappings());
        Assert.assertEquals(before.indexPatterns(), after.indexPatterns());
        Assert.assertEquals(before.priority(), after.priority());
        Assert.assertEquals(before.getDataStreamTemplate(), after.getDataStreamTemplate());
    }

    /**
     * Without overrides, the settings are the bundled ones and the cluster state is not read.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testNoOverrides() throws IOException {
        Index index = this.configure(new StreamIndex(EVENTS_STREAM), "# No keys\n");
        IndexTemplate template = TemplateSettingsTests.bundled(EVENTS_TEMPLATE);

        Settings settings = index.templateSettings(EVENTS_TEMPLATE, "events-template", template);

        Assert.assertEquals(Settings.builder().loadFromMap(template.getSettings()).build(), settings);
        verify(this.clusterService, never()).state();
    }

    /**
     * An override replaces the bundled value of its setting, and adds a setting the template does not
     * have. The other bundled settings stay.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testOverridesGoOnTopOfTheBundledSettings() throws IOException {
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.refresh_interval: 30s\n"
                                + "templates.states.*.settings.index.translog.durability: async\n");
        IndexTemplate template = TemplateSettingsTests.bundled(SCA_TEMPLATE);
        Settings bundled = Settings.builder().loadFromMap(template.getSettings()).build();

        Settings settings = index.templateSettings(SCA_TEMPLATE, "sca-template", template);

        Assert.assertEquals("5s", bundled.get(REFRESH));
        Assert.assertEquals("30s", settings.get(REFRESH));
        Assert.assertNull(bundled.get("index.translog.durability"));
        Assert.assertEquals("async", settings.get("index.translog.durability"));
        Assert.assertEquals(bundled.size() + 1, settings.size());
        Assert.assertEquals(bundled.get("index.codec"), settings.get("index.codec"));
    }

    /**
     * The template of a data stream keeps its mappings, index patterns, priority and data stream
     * definition when a setting is overridden.
     *
     * @throws IOException if the configuration file cannot be written.
     */
    public void testStreamTemplateKeepsEverythingButTheSettings() throws IOException {
        this.assertOnlyTheSettingsChange(
                this.configure(new StreamIndex(EVENTS_STREAM), null),
                this.configure(
                        new StreamIndex(EVENTS_STREAM),
                        "templates.streams.events.settings.index.number_of_shards: 3\n"));
    }

    /**
     * The template of a stateful index keeps everything but the overridden setting.
     *
     * @throws IOException if the configuration file cannot be written.
     */
    public void testStateTemplateKeepsEverythingButTheSettings() throws IOException {
        this.assertOnlyTheSettingsChange(
                this.configure(new StateIndex(SCA_INDEX, SCA_TEMPLATE), null),
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.*.settings.index.number_of_shards: 3\n"));
    }

    /**
     * The template of a content index keeps everything but the overridden setting.
     *
     * @throws IOException if the configuration file cannot be written.
     */
    public void testContentTemplateKeepsEverythingButTheSettings() throws IOException {
        this.assertOnlyTheSettingsChange(
                this.configure(new ContentIndex(RULES_ALIAS, RULES_TEMPLATE), null),
                this.configure(
                        new ContentIndex(RULES_ALIAS, RULES_TEMPLATE),
                        "templates.*.*.settings.index.number_of_shards: 3\n"));
    }

    /**
     * A replica count overridden while the template still auto-expands its replicas is reported: the
     * override has no effect.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testReplicaOverrideUnderAutoExpand() throws IOException {
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.number_of_replicas: 2\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(1, warnings.size());
            Assert.assertTrue(warnings.get(0), warnings.get(0).contains("[sca-template]"));
            Assert.assertTrue(
                    warnings.get(0), warnings.get(0).contains("[" + AUTO_EXPAND + "] is [0-1]"));
        }
    }

    /**
     * The warning about a replica count under auto-expand shows the range as it is written: {@code
     * 0-all}, not the number OpenSearch reads it as.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testReplicaOverrideUnderAutoExpandToAllNodes() throws IOException {
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.number_of_replicas: 2\n"
                                + "templates.states.sca.settings.index.auto_expand_replicas: \"0-all\"\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(warnings.toString(), 1, warnings.size());
            Assert.assertTrue(
                    warnings.get(0), warnings.get(0).contains("[" + AUTO_EXPAND + "] is [0-all]"));
        }
    }

    /**
     * A replica count overridden together with auto-expand set to false takes effect, so nothing is
     * reported.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testReplicaOverrideWithAutoExpandOff() throws IOException {
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.number_of_replicas: 2\n"
                                + "templates.states.sca.settings.index.auto_expand_replicas: false\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            Settings settings =
                    index.templateSettings(
                            SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            Assert.assertEquals("2", settings.get(REPLICAS));
            Assert.assertEquals("false", settings.get(AUTO_EXPAND));
            Assert.assertTrue(appender.messages(Level.WARN).isEmpty());
        }
    }

    /**
     * An index that exists with another value for an overridden setting is reported, once per
     * setting, with the name of the index. A setting it already has is not.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testExistingIndexWithOtherValues() throws IOException {
        this.setClusterState(
                TemplateSettingsTests.existing(SCA_INDEX, Settings.builder().put(REFRESH, "5s").build())
                        .build());
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.refresh_interval: 30s\n"
                                + "templates.states.sca.settings.index.number_of_shards: 3\n"
                                + "templates.states.sca.settings.index.translog.durability: request\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(warnings.toString(), 2, warnings.size());
            Assert.assertTrue(
                    warnings.toString(),
                    warnings.stream()
                            .anyMatch(
                                    w ->
                                            w.contains("[" + SCA_INDEX + "]")
                                                    && w.contains("[" + REFRESH + "] = [5s]")
                                                    && w.contains("[30s]")));
            Assert.assertTrue(
                    warnings.toString(),
                    warnings.stream().anyMatch(w -> w.contains("[" + SHARDS + "] = [1]")));
        }
    }

    /**
     * An index that already has the overridden values is not reported. The values are compared, not
     * the way they are written.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testExistingIndexWithTheSameValues() throws IOException {
        this.setClusterState(
                TemplateSettingsTests.existing(
                                SCA_INDEX, Settings.builder().put(REFRESH, "30000ms").put(SHARDS, 3).build())
                        .build());
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.refresh_interval: 30s\n"
                                + "templates.states.sca.settings.index.number_of_shards: 3\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            Assert.assertTrue(appender.messages(Level.WARN).isEmpty());
        }
    }

    /**
     * For a data stream, the index compared is its write index.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testExistingDataStream() throws IOException {
        String backingIndex = DataStream.getDefaultBackingIndexName(EVENTS_STREAM, 1);
        this.setClusterState(TemplateSettingsTests.existing(backingIndex, Settings.EMPTY).build());
        Index index =
                this.configure(
                        new StreamIndex(EVENTS_STREAM),
                        "templates.streams.events.settings.index.number_of_shards: 3\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    EVENTS_TEMPLATE, "events-template", TemplateSettingsTests.bundled(EVENTS_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(1, warnings.size());
            Assert.assertTrue(warnings.get(0), warnings.get(0).contains("[" + backingIndex + "]"));
        }
    }

    /**
     * For a content index, the index compared is the one behind the alias, whichever slot it is.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testExistingAliasTarget() throws IOException {
        this.setClusterState(
                TemplateSettingsTests.existing(RULES_ALIAS + "-b", Settings.EMPTY)
                        .putAlias(AliasMetadata.builder(RULES_ALIAS).writeIndex(true))
                        .build());
        Index index =
                this.configure(
                        new ContentIndex(RULES_ALIAS, RULES_TEMPLATE),
                        "templates.content.rules.settings.index.number_of_shards: 3\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    RULES_TEMPLATE, "rules-template", TemplateSettingsTests.bundled(RULES_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(1, warnings.size());
            Assert.assertTrue(warnings.get(0), warnings.get(0).contains("[" + RULES_ALIAS + "-b]"));
        }
    }

    /**
     * While an index auto-expands its replicas, its replica count is the one OpenSearch computed, so
     * it is not compared with the override. The auto-expand range is.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testReplicaCountOfAnAutoExpandedIndex() throws IOException {
        this.setClusterState(
                TemplateSettingsTests.existing(
                                SCA_INDEX, Settings.builder().put(AUTO_EXPAND, "0-1").put(REPLICAS, 1).build())
                        .build());
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.number_of_replicas: 2\n"
                                + "templates.states.sca.settings.index.auto_expand_replicas: false\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(warnings.toString(), 1, warnings.size());
            Assert.assertTrue(warnings.get(0), warnings.get(0).contains("[" + AUTO_EXPAND + "] = [0-1]"));
        }
    }

    /**
     * An existing index is reported with its value as it holds it: an auto-expand range of {@code
     * 0-all}, not the number OpenSearch reads it as.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testExistingIndexAutoExpandingToAllNodes() throws IOException {
        this.setClusterState(
                TemplateSettingsTests.existing(
                                SCA_INDEX, Settings.builder().put(AUTO_EXPAND, "0-all").build())
                        .build());
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.auto_expand_replicas: \"0-2\"\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(warnings.toString(), 1, warnings.size());
            Assert.assertTrue(
                    warnings.get(0), warnings.get(0).contains("[" + AUTO_EXPAND + "] = [0-all]"));
        }
    }

    /**
     * An index can hold a value the configuration file does not accept, set by hand. It is reported
     * as different, and does not break the initialization.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testExistingIndexWithAValueTheFileDoesNotAccept() throws IOException {
        this.setClusterState(
                TemplateSettingsTests.existing(
                                SCA_INDEX, Settings.builder().put("index.codec", "lz4").build())
                        .build());
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.codec: best_compression\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            index.templateSettings(
                    SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(1, warnings.size());
            Assert.assertTrue(warnings.get(0), warnings.get(0).contains("[index.codec] = [lz4]"));
        }
    }

    /**
     * A codec name in another case is another codec. An index that holds {@code ZSTD} is reported as
     * different from an override of {@code zstd}.
     *
     * @throws IOException if the template cannot be read.
     */
    public void testExistingIndexWithTheCodecInAnotherCase() throws IOException {
        this.setClusterState(
                TemplateSettingsTests.existing(
                                SCA_INDEX, Settings.builder().put("index.codec", "ZSTD").build())
                        .build());
        Index index =
                this.configure(
                        new StateIndex(SCA_INDEX, SCA_TEMPLATE),
                        "templates.states.sca.settings.index.codec: zstd\n");

        try (CapturingAppender appender = CapturingAppender.attach(Index.class)) {
            Settings settings =
                    index.templateSettings(
                            SCA_TEMPLATE, "sca-template", TemplateSettingsTests.bundled(SCA_TEMPLATE));

            Assert.assertEquals("zstd", settings.get("index.codec"));
            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(warnings.toString(), 1, warnings.size());
            Assert.assertTrue(warnings.get(0), warnings.get(0).contains("[index.codec] = [ZSTD]"));
        }
    }
}
