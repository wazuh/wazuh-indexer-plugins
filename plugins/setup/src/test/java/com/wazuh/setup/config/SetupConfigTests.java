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
package com.wazuh.setup.config;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.common.hash.MessageDigests;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.wazuh.setup.utils.CapturingAppender;

/** Unit tests for the {@link SetupConfig} class. */
public class SetupConfigTests extends OpenSearchTestCase {

    private static final String EVENTS = "templates/streams/events";
    private static final String FINDINGS = "templates/streams/findings";
    private static final String SCA = "templates/states/sca";
    private static final String STATE_VULNERABILITIES = "templates/states/vulnerabilities";
    private static final String CONTENT_VULNERABILITIES = "templates/content/vulnerabilities";
    private static final String SETUP_STATUS = "templates/setup-status";

    /** Templates the plugin under test registers: three groups, and one outside them. */
    private static final List<String> TEMPLATES =
            List.of(EVENTS, FINDINGS, SCA, STATE_VULNERABILITIES, CONTENT_VULNERABILITIES, SETUP_STATUS);

    private static final String EVENTS_POLICY = "stream-events-policy";
    private static final String FINDINGS_POLICY = "stream-findings-policy";
    private static final List<String> POLICIES = List.of(EVENTS_POLICY, FINDINGS_POLICY);

    private static final String SHARDS = "index.number_of_shards";
    private static final String REPLICAS = "index.number_of_replicas";
    private static final String REFRESH = "index.refresh_interval";

    private Path directory;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.directory = LuceneTestCase.createTempDir();
    }

    /**
     * Writes the configuration file and reads it.
     *
     * @param yaml content of the file.
     * @return the configuration.
     * @throws IOException if the file cannot be written.
     */
    private SetupConfig load(String yaml) throws IOException {
        Files.writeString(this.directory.resolve(SetupConfig.FILE), yaml, StandardCharsets.UTF_8);
        return SetupConfig.load(this.directory, TEMPLATES, POLICIES, NamedXContentRegistry.EMPTY);
    }

    /**
     * Asserts that a configuration file is rejected, and that the error names what is wrong.
     *
     * @param yaml content of the file.
     * @param expected texts the error message must hold.
     * @throws IOException if the file cannot be written.
     */
    private void assertInvalid(String yaml, String... expected) throws IOException {
        SetupConfigException e =
                LuceneTestCase.expectThrows(SetupConfigException.class, () -> this.load(yaml));
        for (String text : expected) {
            Assert.assertTrue(
                    "[" + e.getMessage() + "] does not hold [" + text + "]", e.getMessage().contains(text));
        }
    }

    /**
     * Writes a policy file for a default policy.
     *
     * @param policy id of the default policy, which names the file.
     * @param json content of the file.
     * @throws IOException if the file cannot be written.
     */
    private void writePolicy(String policy, String json) throws IOException {
        Files.writeString(this.directory.resolve(policy + ".json"), json, StandardCharsets.UTF_8);
    }

    /**
     * Builds a policy document as the policy files hold it.
     *
     * @param id value of the {@code policy_id} field.
     * @return the document.
     */
    private static String policy(String id) {
        return "{\"policy\": {\"policy_id\": \""
                + id
                + "\", \"description\": \"Edited copy\", \"last_updated_time\": 1700000000000,"
                + " \"default_state\": \"hot\", \"states\": [{\"name\": \"hot\"}],"
                + " \"ism_template\": [{\"index_patterns\": [\"wazuh-events-v5*\"], \"priority\": 0}]}}";
    }

    /**
     * Reads a default policy as the plugin bundles it, which is also what its editable copy holds.
     *
     * @param id id of the default policy.
     * @return the policy document.
     * @throws IOException if the policy cannot be read.
     */
    private static String defaultPolicy(String id) throws IOException {
        try (InputStream is =
                SetupConfigTests.class.getClassLoader().getResourceAsStream("policies/" + id + ".json")) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Replaces a text of a policy document, and fails if the document does not hold it once.
     *
     * @param document the policy document.
     * @param text the text to replace.
     * @param replacement its replacement.
     * @return the edited document.
     */
    private static String edit(String document, String text, String replacement) {
        Assert.assertEquals(
                "[" + text + "] in the policy", 2, document.split(Pattern.quote(text), -1).length);
        return document.replace(text, replacement);
    }

    /** Without the file there are no overrides and every policy is the default one. */
    public void testAbsentFile() {
        SetupConfig config =
                SetupConfig.load(this.directory, TEMPLATES, POLICIES, NamedXContentRegistry.EMPTY);

        Assert.assertTrue(config.templateOverrides(EVENTS).isEmpty());
        Assert.assertNull(config.customPolicy(EVENTS_POLICY));
    }

    /**
     * A path that exists and is not a file is an error, not an absent file: a configuration was
     * meant, and the defaults must not replace it silently. A link to a file is read as the file.
     *
     * @throws IOException if a file cannot be written.
     */
    public void testPathThatIsNotAFile() throws IOException {
        Path file = this.directory.resolve(SetupConfig.FILE);

        Files.createDirectory(file);
        this.assertNotAFile(file);
        Files.delete(file);

        Files.createSymbolicLink(file, this.directory.resolve("absent.yml"));
        this.assertNotAFile(file);
        Files.delete(file);

        Path target = this.directory.resolve("linked.yml");
        Files.writeString(
                target,
                "templates.streams.events.settings.index.number_of_shards: 3\n",
                StandardCharsets.UTF_8);
        Files.createSymbolicLink(file, target);
        SetupConfig config =
                SetupConfig.load(this.directory, TEMPLATES, POLICIES, NamedXContentRegistry.EMPTY);
        Assert.assertEquals("3", config.templateOverrides(EVENTS).get("index.number_of_shards"));
    }

    /**
     * Asserts that the configuration is rejected because its path is not a regular file.
     *
     * @param file path of the configuration file.
     */
    private void assertNotAFile(Path file) {
        SetupConfigException e =
                LuceneTestCase.expectThrows(
                        SetupConfigException.class,
                        () ->
                                SetupConfig.load(this.directory, TEMPLATES, POLICIES, NamedXContentRegistry.EMPTY));
        Assert.assertEquals("[" + file + "] exists but is not a regular file", e.getMessage());
    }

    /**
     * A file where every key is commented out, as installed, has no overrides.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testFileWithOnlyComments() throws IOException {
        SetupConfig config =
                this.load("# A comment\n#templates.streams.events.settings.index.number_of_shards: 3\n");

        Assert.assertTrue(config.templateOverrides(EVENTS).isEmpty());
        Assert.assertNull(config.customPolicy(EVENTS_POLICY));
    }

    /**
     * A key can be written flat or as nested YAML.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testFlatAndNestedKeys() throws IOException {
        Settings flat =
                this.load("templates.streams.events.settings.index.number_of_shards: 3\n")
                        .templateOverrides(EVENTS);
        Settings nested =
                this.load(
                                "templates:\n  streams:\n    events:\n      settings:\n        index:\n"
                                        + "          number_of_shards: 3\n")
                        .templateOverrides(EVENTS);

        Assert.assertEquals("3", flat.get(SHARDS));
        Assert.assertEquals(flat, nested);
    }

    /**
     * The key naming the template wins over the key of its group, which wins over the key for every
     * template. Settings that only a less specific key sets are still applied.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testMostSpecificKeyWins() throws IOException {
        SetupConfig config =
                this.load(
                        "templates.*.*.settings.index.refresh_interval: 10s\n"
                                + "templates.*.*.settings.index.number_of_replicas: 2\n"
                                + "templates.streams.*.settings.index.refresh_interval: 20s\n"
                                + "templates.streams.events.settings.index.refresh_interval: 30s\n");

        Assert.assertEquals("30s", config.templateOverrides(EVENTS).get(REFRESH));
        Assert.assertEquals("20s", config.templateOverrides(FINDINGS).get(REFRESH));
        Assert.assertEquals("10s", config.templateOverrides(SCA).get(REFRESH));
        Assert.assertEquals("2", config.templateOverrides(EVENTS).get(REPLICAS));
        Assert.assertEquals(2, config.templateOverrides(EVENTS).size());
    }

    /**
     * A template outside the three groups, such as an internal one, is not reached by any key.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testTemplateOutsideTheGroups() throws IOException {
        SetupConfig config = this.load("templates.*.*.settings.index.number_of_replicas: 2\n");

        Assert.assertTrue(config.templateOverrides(SETUP_STATUS).isEmpty());
        Assert.assertEquals("2", config.templateOverrides(SCA).get(REPLICAS));
    }

    /**
     * Two groups can hold a template of the same name. Each one has its own key.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testSameNameInTwoGroups() throws IOException {
        SetupConfig config =
                this.load(
                        "templates.states.vulnerabilities.settings.index.number_of_shards: 2\n"
                                + "templates.content.vulnerabilities.settings.index.number_of_shards: 4\n");

        Assert.assertEquals("2", config.templateOverrides(STATE_VULNERABILITIES).get(SHARDS));
        Assert.assertEquals("4", config.templateOverrides(CONTENT_VULNERABILITIES).get(SHARDS));
    }

    /**
     * Every supported setting accepts the values an index accepts.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testValidValues() throws IOException {
        Settings overrides =
                this.load(
                                "templates.streams.events.settings.index.number_of_shards: 3\n"
                                        + "templates.streams.events.settings.index.number_of_replicas: 2\n"
                                        + "templates.streams.events.settings.index.auto_expand_replicas: false\n"
                                        + "templates.streams.events.settings.index.refresh_interval: -1\n"
                                        + "templates.streams.events.settings.index.codec: best_compression\n"
                                        + "templates.streams.events.settings.index.translog.durability: request\n"
                                        + "templates.streams.findings.settings.index.auto_expand_replicas: \"0-all\"\n")
                        .templateOverrides(EVENTS);

        Assert.assertEquals(SupportedSetting.values().length, overrides.size());
        Assert.assertEquals("false", overrides.get("index.auto_expand_replicas"));
        Assert.assertEquals("-1", overrides.get(REFRESH));
    }

    /**
     * A file that is not valid YAML is rejected, and the error names the file.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testInvalidYaml() throws IOException {
        this.assertInvalid(
                "templates:\n  streams: [unclosed\n", this.directory.resolve(SetupConfig.FILE).toString());
    }

    /**
     * A key written twice is rejected.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testDuplicateKey() throws IOException {
        this.assertInvalid(
                "templates.streams.events.settings.index.number_of_shards: 3\n"
                        + "templates.streams.events.settings.index.number_of_shards: 4\n",
                "templates.streams.events.settings.index.number_of_shards");
    }

    /**
     * A key uncommented without a value is rejected, and the error names the key.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testKeyWithoutValue() throws IOException {
        this.assertInvalid(
                "templates.streams.*.settings.index.refresh_interval:\n",
                "templates.streams.*.settings.index.refresh_interval");
    }

    /**
     * Any key the plugin does not support is rejected, and the error names it.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testUnknownKeys() throws IOException {
        this.assertInvalid("cluster.name: example\n", "[cluster.name]", "unknown key");
        this.assertInvalid(
                "templates.internal.settings.settings.index.codec: zstd\n",
                "[templates.internal.settings.settings.index.codec]",
                "unknown template group [internal]");
        this.assertInvalid(
                "templates.streams.alerts.settings.index.codec: zstd\n",
                "[templates.streams.alerts.settings.index.codec]",
                "unknown template [streams.alerts]");
        this.assertInvalid(
                "templates.streams.events.settings.index.hidden: true\n",
                "[templates.streams.events.settings.index.hidden]",
                "unsupported setting [index.hidden]");
        this.assertInvalid(
                "templates.streams.events.mappings.dynamic: true\n",
                "[templates.streams.events.mappings.dynamic]",
                "unknown key");
        this.assertInvalid(
                "templates.streams.events.settings.number_of_shards: 3\n",
                "[templates.streams.events.settings.number_of_shards]",
                "unsupported setting [number_of_shards], did you mean [index.number_of_shards]?");
        this.assertInvalid(
                "templates.*.vulnerabilities.settings.index.codec: zstd\n",
                "[templates.*.vulnerabilities.settings.index.codec]",
                "needs its group");
        this.assertInvalid(
                "policies.stream-alerts-policy.custom: true\n",
                "[policies.stream-alerts-policy.custom]",
                "unknown policy [stream-alerts-policy]");
        this.assertInvalid(
                "policies.stream-events-policy.enabled: true\n",
                "[policies.stream-events-policy.enabled]",
                "unknown key");
        this.assertInvalid("policies.custom: true\n", "[policies.custom]", "unknown key");
    }

    /**
     * A value of the wrong type or out of range is rejected, and the error names the key.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testInvalidValues() throws IOException {
        String events = "templates.streams.events.settings.";
        for (String line :
                List.of(
                        "index.number_of_shards: \"three\"",
                        "index.number_of_shards: 0",
                        "index.number_of_shards: [1, 2]",
                        "index.number_of_replicas: -1",
                        "index.auto_expand_replicas: \"2-1\"",
                        "index.auto_expand_replicas: some",
                        "index.refresh_interval: soon",
                        "index.codec: lz5",
                        "index.translog.durability: sync")) {
            String key = events + line.substring(0, line.indexOf(':'));
            this.assertInvalid(events + line + "\n", "[" + key + "]", "invalid value");
        }
        this.assertInvalid(
                "policies.stream-events-policy.custom: \"yes\"\n",
                "[policies.stream-events-policy.custom]",
                "must be true or false");
    }

    /**
     * A codec or a translog durability must be written exactly as listed. The value reaches the index
     * template as it is written, and OpenSearch takes {@code ZSTD} for an old codec that cannot
     * write.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testListedValuesAreCaseSensitive() throws IOException {
        String events = "templates.streams.events.settings.";
        for (String line :
                List.of(
                        "index.codec: ZSTD",
                        "index.codec: Best_Compression",
                        "index.translog.durability: ASYNC")) {
            int colon = line.indexOf(':');
            this.assertInvalid(
                    events + line + "\n",
                    "[" + events + line.substring(0, colon) + "]",
                    "invalid value: unknown value [" + line.substring(colon + 2) + "]",
                    "must be one of");
        }
    }

    /**
     * With the switch off, the default policy is used and the policy file is not even read.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testPolicySwitchOff() throws IOException {
        this.writePolicy(EVENTS_POLICY, "not a policy");
        SetupConfig config = this.load("policies.stream-events-policy.custom: false\n");

        Assert.assertNull(config.customPolicy(EVENTS_POLICY));
    }

    /**
     * With the switch on, the policy of the file replaces the default one. The other policies stay
     * the default ones.
     *
     * @throws IOException if a file cannot be written.
     */
    @SuppressWarnings("unchecked")
    public void testPolicySwitchOn() throws IOException {
        this.writePolicy(EVENTS_POLICY, SetupConfigTests.policy(EVENTS_POLICY));
        SetupConfig config = this.load("policies.stream-events-policy.custom: true\n");

        Map<String, Object> policy =
                (Map<String, Object>) config.customPolicy(EVENTS_POLICY).get("policy");
        Assert.assertEquals("Edited copy", policy.get("description"));
        Assert.assertNull(config.customPolicy(FINDINGS_POLICY));

        // Each call returns a new copy: a change made by the caller does not reach the next one.
        policy.put("description", "Changed by the caller");
        Assert.assertEquals(
                "Edited copy",
                ((Map<String, Object>) config.customPolicy(EVENTS_POLICY).get("policy"))
                        .get("description"));
    }

    /**
     * A policy file that is missing or that is not a policy of the same id is rejected, and the error
     * names the file.
     *
     * @throws IOException if a file cannot be written.
     */
    public void testInvalidPolicyFiles() throws IOException {
        String enabled = "policies.stream-events-policy.custom: true\n";
        String file = this.directory.resolve(EVENTS_POLICY + ".json").toString();

        this.assertInvalid(enabled, file, "not found");

        this.writePolicy(EVENTS_POLICY, "{\"policy\": ");
        this.assertInvalid(enabled, file, "cannot be read as JSON");

        this.writePolicy(EVENTS_POLICY, "{\"description\": \"Edited copy\"}");
        this.assertInvalid(enabled, file, "has no [policy] object");

        this.writePolicy(EVENTS_POLICY, SetupConfigTests.policy(FINDINGS_POLICY));
        this.assertInvalid(enabled, file, "expected [" + EVENTS_POLICY + "]");

        this.writePolicy(
                EVENTS_POLICY,
                "{\"policy\": {\"policy_id\": \"" + EVENTS_POLICY + "\", \"default_state\": \"hot\"}}");
        this.assertInvalid(enabled, file, "[policy.last_updated_time]");
    }

    /**
     * A policy file must be a policy that Index State Management (ISM) can read. The plugin stores it
     * without the ISM API, and one stored policy that ISM cannot parse stops ISM from attaching any
     * policy to new indices. Each case is a mistake that an edit of the default policy can make, and
     * the error carries what the ISM parser says about it.
     *
     * @throws IOException if a file cannot be read or written.
     */
    public void testPolicyFileThatIndexStateManagementCannotRead() throws IOException {
        String enabled = "policies.stream-events-policy.custom: true\n";
        String file = this.directory.resolve(EVENTS_POLICY + ".json").toString();
        String shipped = SetupConfigTests.defaultPolicy(EVENTS_POLICY);

        // The default policy is accepted as it ships, and with a valid age.
        this.writePolicy(EVENTS_POLICY, shipped);
        Assert.assertNotNull(this.load(enabled).customPolicy(EVENTS_POLICY));
        this.writePolicy(EVENTS_POLICY, SetupConfigTests.edit(shipped, "\"1d\"", "\"7d\""));
        Assert.assertNotNull(this.load(enabled).customPolicy(EVENTS_POLICY));

        String[][] mistakes = {
            {
                "\"min_rollover_age\": \"1d\"", "\"min_rollover_age\": \"7days\"", "failed to parse [7days]"
            },
            {"\"state_name\": \"delete\"", "\"state_name\": \"remove\"", "nonexistent state=remove"},
            {"\"default_state\": \"hot\"", "\"default_state\": \"warm\"", "valid default state"},
            {"\"delete\": {}", "\"delet\": {}", "Invalid field: [delet]"},
            {"\"min_doc_count\"", "\"min_doc_cont\"", "Invalid field: [min_doc_cont]"},
        };
        for (String[] mistake : mistakes) {
            this.writePolicy(EVENTS_POLICY, SetupConfigTests.edit(shipped, mistake[0], mistake[1]));
            this.assertInvalid(enabled, file, "Index State Management can read", mistake[2]);
        }
    }

    /**
     * A policy file can only hold the fields the ISM configuration index maps, where the plugin
     * stores the policy. Anything else would fail when the policy is stored, after other indices were
     * created, so it is rejected first, and the error names the file and the fields.
     *
     * @throws IOException if a file cannot be written.
     */
    public void testPolicyFileWithUnknownFields() throws IOException {
        String enabled = "policies.stream-events-policy.custom: true\n";
        String file = this.directory.resolve(EVENTS_POLICY + ".json").toString();
        String policy = SetupConfigTests.policy(EVENTS_POLICY);

        // A copy of a GET response of the ISM API.
        this.writePolicy(
                EVENTS_POLICY,
                "{\"_id\": \"" + EVENTS_POLICY + "\", \"_seq_no\": 7, " + policy.substring(1));
        this.assertInvalid(
                enabled, file, "unknown field(s) [_id, _seq_no]", "holds only the [policy] object");

        // A typo in a field of the policy.
        this.writePolicy(EVENTS_POLICY, policy.replace("\"states\"", "\"stats\""));
        this.assertInvalid(enabled, file, "unknown field(s) [stats] in [policy]", "default_state");
    }

    /**
     * A policy file must keep an ISM template, empty or not. ISM attaches the policy to the backing
     * index that a rollover creates through it, so without one that index gets no policy and is never
     * deleted. The error names the file and the field.
     *
     * @throws IOException if a file cannot be written.
     */
    public void testPolicyFileWithoutIsmTemplate() throws IOException {
        String enabled = "policies.stream-events-policy.custom: true\n";
        String file = this.directory.resolve(EVENTS_POLICY + ".json").toString();
        String policy = SetupConfigTests.policy(EVENTS_POLICY);
        String template =
                ", \"ism_template\": [{\"index_patterns\": [\"wazuh-events-v5*\"], \"priority\": 0}]";

        this.writePolicy(EVENTS_POLICY, SetupConfigTests.edit(policy, template, ""));
        this.assertInvalid(enabled, file, "has no [policy.ism_template]");

        this.writePolicy(
                EVENTS_POLICY, SetupConfigTests.edit(policy, template, ", \"ism_template\": []"));
        this.assertInvalid(enabled, file, "has no [policy.ism_template]");
    }

    /**
     * A time in the future in a policy file is rejected, and the error names the file and the field:
     * ISM would not attach the policy to the indices created until then. A time in microseconds is
     * the likely mistake.
     *
     * @throws IOException if a file cannot be written.
     */
    public void testPolicyTimeInTheFuture() throws IOException {
        String enabled = "policies.stream-events-policy.custom: true\n";
        String file = this.directory.resolve(EVENTS_POLICY + ".json").toString();
        String policy = SetupConfigTests.policy(EVENTS_POLICY);
        String microseconds = "1700000000000000";

        this.writePolicy(EVENTS_POLICY, policy.replace("1700000000000", microseconds));
        this.assertInvalid(
                enabled, file, "[policy.last_updated_time] is [" + microseconds + "]", "future");

        this.writePolicy(
                EVENTS_POLICY,
                policy.replace(
                        "\"priority\": 0}", "\"priority\": 0, \"last_updated_time\": " + microseconds + "}"));
        this.assertInvalid(enabled, file, "[policy.ism_template[0].last_updated_time]", "future");

        // ISM also takes a single template instead of a list.
        this.writePolicy(
                EVENTS_POLICY,
                policy.replace(
                        "[{\"index_patterns\": [\"wazuh-events-v5*\"], \"priority\": 0}]",
                        "{\"index_patterns\": [\"wazuh-events-v5*\"], \"last_updated_time\": "
                                + microseconds
                                + "}"));
        this.assertInvalid(enabled, file, "[policy.ism_template[0].last_updated_time]", "future");
    }

    /**
     * The log holds the hash of the file, one line per override and one per replaced policy, with the
     * hash of its file and a warning that the policy no longer follows the default one.
     *
     * @throws IOException if a file cannot be written.
     */
    public void testLog() throws IOException {
        String yaml =
                "templates.streams.events.settings.index.number_of_shards: 3\n"
                        + "templates.states.*.settings.index.refresh_interval: 30s\n"
                        + "policies.stream-events-policy.custom: true\n";
        this.writePolicy(EVENTS_POLICY, SetupConfigTests.policy(EVENTS_POLICY));
        SetupConfig config = this.load(yaml);
        String hash =
                MessageDigests.toHexString(
                        MessageDigests.sha256().digest(yaml.getBytes(StandardCharsets.UTF_8)));
        String policyHash =
                MessageDigests.toHexString(
                        MessageDigests.sha256()
                                .digest(SetupConfigTests.policy(EVENTS_POLICY).getBytes(StandardCharsets.UTF_8)));

        try (CapturingAppender appender = CapturingAppender.attach(SetupConfigTests.class)) {
            config.log(LogManager.getLogger(SetupConfigTests.class));

            List<String> info = appender.messages(Level.INFO);
            Assert.assertEquals(4, info.size());
            Assert.assertTrue(info.get(0), info.get(0).contains("sha256 [" + hash + "]"));
            Assert.assertTrue(info.get(0), info.get(0).contains("2 index template setting override(s)"));
            Assert.assertTrue(
                    info.get(1),
                    info.get(1).contains("[templates.states.*.settings.index.refresh_interval] = [30s]"));
            Assert.assertTrue(
                    info.get(2),
                    info.get(2).contains("[templates.streams.events.settings.index.number_of_shards] = [3]"));
            Assert.assertTrue(info.get(3), info.get(3).contains(EVENTS_POLICY + ".json"));
            Assert.assertTrue(info.get(3), info.get(3).contains("sha256 [" + policyHash + "]"));

            List<String> warnings = appender.messages(Level.WARN);
            Assert.assertEquals(1, warnings.size());
            Assert.assertTrue(warnings.get(0), warnings.get(0).contains("[" + EVENTS_POLICY + "]"));
            Assert.assertTrue(
                    warnings.get(0), warnings.get(0).contains("no longer follows the default policy"));
        }
    }

    /** Without the file, the log says that the defaults are used. */
    public void testLogWithoutFile() {
        SetupConfig config =
                SetupConfig.load(this.directory, TEMPLATES, POLICIES, NamedXContentRegistry.EMPTY);

        try (CapturingAppender appender = CapturingAppender.attach(SetupConfigTests.class)) {
            config.log(LogManager.getLogger(SetupConfigTests.class));

            List<String> info = appender.messages(Level.INFO);
            Assert.assertEquals(1, info.size());
            Assert.assertTrue(info.get(0), info.get(0).contains("not found"));
        }
    }
}
