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
package com.wazuh.setup;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.TestEnvironment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.Assert;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.wazuh.setup.config.SetupConfig;
import com.wazuh.setup.config.SetupConfigException;
import com.wazuh.setup.config.SupportedSetting;
import com.wazuh.setup.index.Index;
import com.wazuh.setup.index.IndexStateManagement;
import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.utils.JsonUtils;

import static org.mockito.Mockito.mock;

/**
 * Checks the files the build generates for the configuration directory of the plugin ({@code
 * setup.yml} and the copies of the ISM policies) against the plugin itself: the index templates it
 * registers, the policies it bundles, and its own reader of the file. A default that changes in a
 * template, a new template or a new policy cannot leave these files behind.
 */
public class SetupConfigFilesTests extends OpenSearchTestCase {

    /** Classpath folder the build generates the files into. */
    private static final String GENERATED = SetupConfig.DIRECTORY + "/";

    /** Classpath folder of the ISM policies bundled in the plugin. */
    private static final String BUNDLED_POLICIES = "policies/";

    /** Heading of the section of setup.yml that holds the examples. */
    private static final String EXAMPLES_HEADING = "\n# Examples\n";

    /** Heading of the section of setup.yml that lists every key with its default. */
    private static final String KEYS_HEADING = "\n# Every key, with its default\n";

    /**
     * A commented key naming one template, with its default and, after it, a comment with the valid
     * values: group 1 is the key, group 2 the value.
     */
    private static final Pattern TEMPLATE_DEFAULT =
            Pattern.compile(
                    "(?m)^#(templates\\.[a-z]+\\.[a-z0-9-]+\\.settings\\.[^:\\n]+): ([^#\\s]\\S*)\\s+# .+$");

    /** A commented key covering several templates, with the default they all share. */
    private static final Pattern WILDCARD_DEFAULT =
            Pattern.compile(
                    "(?m)^#(templates\\.[a-z*]+\\.\\*\\.settings\\.[^:\\n]+): ([^#\\s]\\S*)\\s+# .+$");

    /**
     * A commented key covering templates with different defaults: it has no value, only a comment.
     */
    private static final Pattern WILDCARD_WITHOUT_DEFAULT =
            Pattern.compile("(?m)^#(templates\\.[a-z*]+\\.\\*\\.settings\\.[^:\\n]+):\\s+# .+$");

    /** A commented policy switch: group 1 is the key. */
    private static final Pattern POLICY_SWITCH =
            Pattern.compile("(?m)^#(policies\\.[a-z-]+\\.custom): false\\s+# .+$");

    /** Any commented key: group 1 is the line without the "#" in front. */
    private static final Pattern COMMENTED_KEY =
            Pattern.compile("(?m)^#((?:templates|policies)\\.\\S+: \\S.*)$");

    private Path directory;
    private String setupYml;
    private String examples;
    private String keys;
    private List<String> templates;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        // The index templates of the plugin are the ones of the indices it registers.
        SetupPlugin plugin = new SetupPlugin();
        Environment environment =
                TestEnvironment.newEnvironment(
                        Settings.builder()
                                .put(Environment.PATH_HOME_SETTING.getKey(), LuceneTestCase.createTempDir())
                                .build());
        plugin.createComponents(
                mock(Client.class),
                mock(ClusterService.class),
                mock(ThreadPool.class),
                null,
                null,
                null,
                environment,
                null,
                null,
                null,
                null);
        this.templates = plugin.indices.stream().map(Index::getTemplate).distinct().toList();

        // The test JVM only reads the classpath, so the generated files are copied out of it.
        this.directory = LuceneTestCase.createTempDir();
        this.setupYml = SetupConfigFilesTests.generated(SetupConfig.FILE);
        // The examples repeat keys of the list of every key, so each section is uncommented apart.
        int examplesStart = this.setupYml.indexOf(EXAMPLES_HEADING);
        int keysStart = this.setupYml.indexOf(KEYS_HEADING);
        Assert.assertTrue("setup.yml has no examples section", examplesStart > 0);
        Assert.assertTrue("setup.yml has no list of every key", keysStart > examplesStart);
        this.examples = this.setupYml.substring(examplesStart, keysStart);
        this.keys = this.setupYml.substring(keysStart);
        for (String policy : IndexStateManagement.POLICIES) {
            Files.writeString(
                    this.directory.resolve(policy + ".json"),
                    SetupConfigFilesTests.generated(policy + ".json"),
                    StandardCharsets.UTF_8);
        }
    }

    /**
     * Reads a generated file.
     *
     * @param name name of the file.
     * @return its content.
     * @throws IOException if the file cannot be read.
     */
    private static String generated(String name) throws IOException {
        try (InputStream is =
                SetupConfigFilesTests.class.getClassLoader().getResourceAsStream(GENERATED + name)) {
            Assert.assertNotNull("The build did not generate [" + name + "]", is);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Writes the configuration file and reads it as the plugin does.
     *
     * @param yaml content of the file.
     * @return the configuration.
     * @throws IOException if the file cannot be written.
     */
    private SetupConfig load(String yaml) throws IOException {
        Files.writeString(this.directory.resolve(SetupConfig.FILE), yaml, StandardCharsets.UTF_8);
        return SetupConfig.load(
                this.directory, this.templates, IndexStateManagement.POLICIES, NamedXContentRegistry.EMPTY);
    }

    /**
     * Reads the settings an index template bundled in the plugin has.
     *
     * @param template resource path of the template.
     * @return the settings.
     * @throws IOException if the resource cannot be read.
     */
    private static Settings bundledSettings(String template) throws IOException {
        try (InputStream is =
                SetupConfigFilesTests.class.getClassLoader().getResourceAsStream(template + ".json")) {
            IndexTemplate indexTemplate = new ObjectMapper().readValue(is, IndexTemplate.class);
            return Settings.builder().loadFromMap(indexTemplate.getSettings()).build();
        }
    }

    /**
     * Asserts that a configuration leaves the settings of every index template as they are bundled.
     *
     * @param config the configuration.
     * @throws IOException if a template cannot be read.
     */
    private void assertNoEffectiveChange(SetupConfig config) throws IOException {
        for (String template : this.templates) {
            Settings bundled = SetupConfigFilesTests.bundledSettings(template);
            Settings overridden =
                    Settings.builder().put(bundled).put(config.templateOverrides(template)).build();
            for (SupportedSetting setting : SupportedSetting.values()) {
                Assert.assertEquals(
                        "Default of [" + setting.key() + "] for [" + template + "]",
                        setting.read(bundled),
                        setting.read(overridden));
            }
        }
    }

    /**
     * The file as installed, with every key commented out, overrides nothing and replaces no policy.
     *
     * @throws IOException if a file cannot be read or written.
     */
    public void testInstalledFileChangesNothing() throws IOException {
        SetupConfig config = this.load(this.setupYml);

        for (String template : this.templates) {
            Assert.assertTrue(template, config.templateOverrides(template).isEmpty());
        }
        for (String policy : IndexStateManagement.POLICIES) {
            Assert.assertNull(policy, config.customPolicy(policy));
        }
    }

    /**
     * Every template of the three groups has a commented key for each supported setting, and the
     * value it shows is the one the template has: uncommenting them all changes no setting. A
     * template that sets nothing for a key must show the OpenSearch default.
     *
     * <p>Loading the file also proves the other direction: a key naming a template that the plugin
     * does not register, or holding a value the plugin rejects, fails the load.
     *
     * @throws IOException if a file cannot be read or written.
     */
    public void testCommentedDefaultsOfEachTemplate() throws IOException {
        SetupConfig config = this.load(TEMPLATE_DEFAULT.matcher(this.keys).replaceAll("$1: $2"));

        int overridable = 0;
        for (String template : this.templates) {
            // Internal templates sit outside the groups and have no keys.
            if (template.split("/").length != 3) {
                Assert.assertTrue(template, config.templateOverrides(template).isEmpty());
                continue;
            }
            overridable++;
            Assert.assertEquals(
                    "Keys of [" + template + "]",
                    SupportedSetting.values().length,
                    config.templateOverrides(template).size());
        }
        Assert.assertTrue("No template can be overridden", overridable > 0);
        this.assertNoEffectiveChange(config);
    }

    /**
     * A commented key that covers several templates shows a value only when all of them share it, so
     * uncommenting those keys changes no setting either.
     *
     * @throws IOException if a file cannot be read or written.
     */
    public void testCommentedDefaultsOfTheWildcardKeys() throws IOException {
        Assert.assertTrue(WILDCARD_DEFAULT.matcher(this.keys).find());

        this.assertNoEffectiveChange(
                this.load(WILDCARD_DEFAULT.matcher(this.keys).replaceAll("$1: $2")));
    }

    /**
     * A key that covers templates with different defaults has no value to show. Uncommented as it is,
     * it is rejected instead of silently overriding nothing.
     *
     * @throws IOException if a file cannot be read or written.
     */
    public void testWildcardKeyWithoutDefault() throws IOException {
        Matcher matcher = WILDCARD_WITHOUT_DEFAULT.matcher(this.keys);
        Assert.assertTrue(matcher.find());
        String key = matcher.group(1);

        SetupConfigException e =
                LuceneTestCase.expectThrows(
                        SetupConfigException.class,
                        () -> this.load(this.keys.replace("#" + key + ":", key + ":")));
        Assert.assertTrue(e.getMessage(), e.getMessage().contains("[" + key + "]"));
    }

    /**
     * Every default policy has its switch and its editable copy. A copy is the default policy with
     * another description, and the plugin accepts it as it is installed.
     *
     * @throws IOException if a file cannot be read or written.
     */
    @SuppressWarnings("unchecked")
    public void testPolicyCopies() throws IOException {
        SetupConfig config = this.load(POLICY_SWITCH.matcher(this.keys).replaceAll("$1: true"));

        for (String policy : IndexStateManagement.POLICIES) {
            Assert.assertNotNull("Switch or copy of [" + policy + "]", config.customPolicy(policy));
            Map<String, Object> copy =
                    new HashMap<>((Map<String, Object>) config.customPolicy(policy).get("policy"));
            Map<String, Object> bundled =
                    new HashMap<>(
                            (Map<String, Object>)
                                    new JsonUtils().fromFile(BUNDLED_POLICIES + policy + ".json").get("policy"));

            String description = (String) copy.remove("description");
            Assert.assertNotEquals(policy, bundled.remove("description"), description);
            Assert.assertTrue(description, description.contains("policies." + policy + ".custom"));
            Assert.assertEquals(policy, bundled, copy);
        }
    }

    /**
     * The examples of the file work as they are written: with the "#" in front of their keys removed,
     * the file loads, and the keys do what their comments say. An example naming a template or a
     * policy that no longer exists, or holding a value the plugin rejects, fails the load.
     *
     * @throws IOException if a file cannot be read or written.
     */
    public void testExamples() throws IOException {
        Assert.assertTrue(COMMENTED_KEY.matcher(this.examples).find());

        SetupConfig config = this.load(COMMENTED_KEY.matcher(this.examples).replaceAll("$1"));

        // Three data nodes.
        Settings events = config.templateOverrides("templates/streams/events");
        Assert.assertEquals("3", events.get("index.number_of_shards"));
        Assert.assertEquals("0-2", events.get("index.auto_expand_replicas"));
        // A fixed number of replicas for every index: the key of the events example is more specific.
        Settings rules = config.templateOverrides("templates/content/rules");
        Assert.assertEquals("false", rules.get("index.auto_expand_replicas"));
        Assert.assertEquals("1", rules.get("index.number_of_replicas"));
        // A stateful index that refreshes less often, and only that one.
        Assert.assertEquals(
                "30s",
                config
                        .templateOverrides("templates/states/inventory-services")
                        .get("index.refresh_interval"));
        Assert.assertNull(
                config.templateOverrides("templates/states/sca").get("index.refresh_interval"));
        // Stream indices that sync every write.
        Assert.assertEquals("request", events.get("index.translog.durability"));
        Assert.assertNull(rules.get("index.translog.durability"));
        // Your own retention for the events.
        Assert.assertNotNull(config.customPolicy("stream-events-policy"));
        Assert.assertNull(config.customPolicy("stream-findings-policy"));
    }

    /**
     * A commented key is used by removing the "#" in front of it: the valid values that follow the
     * default on the line stay there as a comment, which the file reader ignores.
     *
     * @throws IOException if a file cannot be read or written.
     */
    public void testKeyLinesWorkWithTheirTrailingComment() throws IOException {
        Matcher line =
                Pattern.compile("(?m)^#(templates\\.streams\\.events\\.settings\\.\\S+: .+)$")
                        .matcher(this.keys);
        StringBuilder uncommented = new StringBuilder();
        while (line.find()) {
            Assert.assertTrue(line.group(1), line.group(1).contains(" # "));
            uncommented.append(line.group(1)).append('\n');
        }

        SetupConfig config = this.load(uncommented.toString());

        Assert.assertEquals(
                SupportedSetting.values().length,
                config.templateOverrides("templates/streams/events").size());
    }
}
