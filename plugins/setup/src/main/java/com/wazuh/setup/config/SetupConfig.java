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

import org.apache.logging.log4j.Logger;
import org.opensearch.common.hash.MessageDigests;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.indexmanagement.indexstatemanagement.model.Policy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Configuration of the plugin, read from {@value #FILE} in the {@value #DIRECTORY} directory of the
 * node configuration. It holds the index template settings the operator overrides, and the ISM
 * policies the operator replaces with the policy files of the same directory.
 *
 * <p>An instance is the result of one read. The file is read again at every initialization, and
 * nothing of a previous read is kept, so the file is the only source of the overrides.
 */
public final class SetupConfig {

    /** Directory of the plugin configuration, under the configuration directory of the node. */
    public static final String DIRECTORY = "wazuh-indexer-setup";

    /** Name of the configuration file. */
    public static final String FILE = "setup.yml";

    /** Configuration without overrides: the plugin behaves as if the file did not exist. */
    public static final SetupConfig EMPTY = new SetupConfig(null, null, Settings.EMPTY, Map.of());

    private static final String TEMPLATES = "templates.";
    private static final String POLICIES = "policies.";
    private static final String SETTINGS = "settings.";
    private static final String CUSTOM = ".custom";
    private static final String ANY = "*";
    private static final String TEMPLATES_PATH = "templates/";
    private static final String INDEX_PREFIX = "index.";
    private static final String POLICY_FIELD = "policy";
    private static final String POLICY_ID_FIELD = "policy_id";
    private static final String LAST_UPDATED_TIME_FIELD = "last_updated_time";
    private static final String ISM_TEMPLATE_FIELD = "ism_template";

    /**
     * Index template of the ISM configuration index. A policy is stored in that index, whose mapping
     * is strict, so its mapping lists the fields a policy can have.
     */
    private static final String ISM_CONFIG_TEMPLATE = "templates/ism-config.json";

    private final Path file;
    private final String hash;
    private final Settings settings;
    private final Map<String, PolicyFile> policies;

    /**
     * A policy file that replaces a default ISM policy.
     *
     * @param file path of the file.
     * @param content content of the file, as read.
     * @param hash SHA-256 of the content.
     */
    private record PolicyFile(Path file, byte[] content, String hash) {}

    private SetupConfig(Path file, String hash, Settings settings, Map<String, PolicyFile> policies) {
        this.file = file;
        this.hash = hash;
        this.settings = settings;
        this.policies = policies;
    }

    /**
     * Reads and validates the configuration. A missing file is not an error: the result has no
     * overrides.
     *
     * @param directory directory holding {@value #FILE} and the policy files.
     * @param templates resource paths of the index templates of the plugin, for example {@code
     *     templates/streams/events}. Only those under a group folder can be overridden.
     * @param policies ids of the default ISM policies.
     * @param xContentRegistry registry of the node, which Index State Management reads a policy with.
     * @return the configuration.
     * @throws SetupConfigException if the path is not a regular file, is not valid YAML, holds an
     *     unknown key or an invalid value, or a policy file it selects is missing or invalid. The
     *     message names the key or the file.
     */
    public static SetupConfig load(
            Path directory,
            Collection<String> templates,
            Collection<String> policies,
            NamedXContentRegistry xContentRegistry) {
        Path file = directory.resolve(FILE);
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            return new SetupConfig(file, null, Settings.EMPTY, Map.of());
        }
        // Something is there, so a configuration was meant. A directory or a link to nothing is an
        // error, not an absent file: the defaults must not be applied silently in its place.
        if (!Files.isRegularFile(file)) {
            throw new SetupConfigException("[" + file + "] exists but is not a regular file");
        }

        byte[] content;
        try {
            content = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new SetupConfigException("[" + file + "] cannot be read: " + e, e);
        }
        Settings settings;
        try {
            settings =
                    Settings.builder().loadFromStream(FILE, new ByteArrayInputStream(content), false).build();
        } catch (Exception e) {
            throw new SetupConfigException(
                    "[" + file + "] is not a valid YAML settings file: " + SetupConfig.describe(e), e);
        }

        Set<String> overridable = SetupConfig.overridable(templates);
        long now = System.currentTimeMillis();
        Map<String, PolicyFile> customPolicies = new HashMap<>();
        for (String key : settings.keySet()) {
            // A SetupConfigException, which names a policy file, is not an IllegalArgumentException
            // and goes through as it is.
            try {
                if (key.startsWith(TEMPLATES)) {
                    SetupConfig.validateTemplateKey(key, settings, overridable);
                } else if (key.startsWith(POLICIES)) {
                    String rest = key.substring(POLICIES.length());
                    if (!rest.endsWith(CUSTOM) || rest.length() == CUSTOM.length()) {
                        throw new IllegalArgumentException(
                                "unknown key, expected [policies.<policy-id>.custom]");
                    }
                    String policy = rest.substring(0, rest.length() - CUSTOM.length());
                    if (!policies.contains(policy)) {
                        throw new IllegalArgumentException("unknown policy [" + policy + "]");
                    }
                    if (SetupConfig.parseSwitch(settings.get(key))) {
                        customPolicies.put(
                                policy, SetupConfig.loadPolicy(directory, policy, now, xContentRegistry));
                    }
                } else {
                    throw new IllegalArgumentException("unknown key");
                }
            } catch (IllegalArgumentException e) {
                throw new SetupConfigException("[" + key + "] in [" + file + "]: " + e.getMessage(), e);
            }
        }
        return new SetupConfig(file, SetupConfig.sha256(content), settings, Map.copyOf(customPolicies));
    }

    /**
     * Returns the settings to put on top of the bundled settings of an index template. A setting can
     * come from three keys: the one naming the template, the one naming its group, and the one for
     * all templates. The most specific one wins.
     *
     * @param template resource path of the template, for example {@code templates/streams/events}.
     * @return the overrides, keyed by index setting. Empty for a template outside the groups.
     */
    public Settings templateOverrides(String template) {
        String id = SetupConfig.templateId(template);
        if (id == null || this.settings.isEmpty()) {
            return Settings.EMPTY;
        }
        String group = id.substring(0, id.indexOf('.'));
        return Settings.builder()
                .put(this.settings.getByPrefix(TEMPLATES + ANY + "." + ANY + "." + SETTINGS))
                .put(this.settings.getByPrefix(TEMPLATES + group + "." + ANY + "." + SETTINGS))
                .put(this.settings.getByPrefix(TEMPLATES + id + "." + SETTINGS))
                .build();
    }

    /**
     * Describes the overrides in effect for an index template, to complete the error of an index that
     * could not be initialized. The file accepts values that the cluster can still refuse, such as a
     * number of shards that goes over the shard limit of the cluster, and that error names no key.
     *
     * @param template resource path of the template, for example {@code templates/streams/events}.
     * @return the description, or an empty text when the file overrides nothing for the template.
     */
    public String describeOverrides(String template) {
        Settings overrides = this.templateOverrides(template);
        if (overrides.isEmpty()) {
            return "";
        }
        List<String> values =
                new TreeSet<>(overrides.keySet())
                        .stream().map(key -> key + " = " + overrides.get(key)).toList();
        return "Overrides of [" + this.file + "] in effect for this index: " + values;
    }

    /**
     * Returns the policy that replaces a default ISM policy.
     *
     * @param policy id of the default policy.
     * @return the content of the policy file, or null when the default policy is to be used. Each
     *     call returns a new copy, which the caller can change.
     */
    public Map<String, Object> customPolicy(String policy) {
        PolicyFile policyFile = this.policies.get(policy);
        return policyFile == null
                ? null
                : SetupConfig.parsePolicy(policyFile.file(), policyFile.content());
    }

    /**
     * Logs what this configuration changes: the file and its hash, one line per template setting
     * override, and one line per replaced policy, with the hash of its file and a warning about what
     * replacing it implies. The hashes let an operator check that the nodes hold the same files.
     *
     * @param log logger to write to.
     */
    public void log(Logger log) {
        if (this.hash == null) {
            log.info("Setup configuration file [{}] not found. Using the bundled defaults.", this.file);
            return;
        }
        Set<String> overrides = new TreeSet<>();
        for (String key : this.settings.keySet()) {
            if (key.startsWith(TEMPLATES)) {
                overrides.add(key);
            }
        }
        log.info(
                "Setup configuration file [{}], sha256 [{}]: {} index template setting override(s), {} replaced ISM policy(ies).",
                this.file,
                this.hash,
                overrides.size(),
                this.policies.size());
        for (String key : overrides) {
            log.info("Index template setting override: [{}] = [{}]", key, this.settings.get(key));
        }
        for (String policy : new TreeSet<>(this.policies.keySet())) {
            PolicyFile policyFile = this.policies.get(policy);
            log.info(
                    "ISM policy [{}] is replaced by the policy in [{}], sha256 [{}].",
                    policy,
                    policyFile.file(),
                    policyFile.hash());
            log.warn(
                    "ISM policy [{}] no longer follows the default policy: changes a new version makes to the default one do not reach [{}].",
                    policy,
                    policyFile.file());
        }
    }

    /**
     * Checks a {@code templates.<group>.<name>.settings.<setting>} key and its value.
     *
     * @param key the key.
     * @param settings the settings read from the file.
     * @param overridable templates that can be overridden, as {@code <group>.<name>}.
     */
    private static void validateTemplateKey(String key, Settings settings, Set<String> overridable) {
        String[] parts = key.substring(TEMPLATES.length()).split("\\.", 3);
        if (parts.length < 3 || !parts[2].startsWith(SETTINGS)) {
            throw new IllegalArgumentException(
                    "unknown key, expected [templates.<group>.<name>.settings.<setting>]");
        }
        String group = parts[0];
        String name = parts[1];
        String setting = parts[2].substring(SETTINGS.length());
        if (ANY.equals(group)) {
            if (!ANY.equals(name)) {
                throw new IllegalArgumentException(
                        "unknown key, a template name needs its group: use [templates.<group>."
                                + name
                                + "] or [templates.*.*]");
            }
        } else if (overridable.stream().noneMatch(id -> id.startsWith(group + "."))) {
            throw new IllegalArgumentException("unknown template group [" + group + "]");
        } else if (!ANY.equals(name) && !overridable.contains(group + "." + name)) {
            throw new IllegalArgumentException("unknown template [" + group + "." + name + "]");
        }
        SupportedSetting supported = SupportedSetting.fromKey(setting);
        if (supported == null) {
            // OpenSearch takes index settings without their prefix too; this file does not.
            SupportedSetting prefixed = SupportedSetting.fromKey(INDEX_PREFIX + setting);
            throw new IllegalArgumentException(
                    "unsupported setting ["
                            + setting
                            + "]"
                            + (prefixed == null ? "" : ", did you mean [" + prefixed.key() + "]?"));
        }
        String prefix = key.substring(0, key.length() - setting.length());
        try {
            supported.read(settings.getByPrefix(prefix));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid value: " + e.getMessage(), e);
        }
    }

    /**
     * Parses the value of a {@code policies.<policy-id>.custom} key.
     *
     * @param value the value read from the file.
     * @return the switch.
     */
    private static boolean parseSwitch(String value) {
        if ("true".equals(value)) {
            return true;
        }
        if ("false".equals(value)) {
            return false;
        }
        throw new IllegalArgumentException("invalid value [" + value + "], must be true or false");
    }

    /**
     * Reads the policy file that replaces a default ISM policy, and checks it.
     *
     * @param directory directory of the policy files.
     * @param policy id of the default policy.
     * @param now current time, in epoch milliseconds.
     * @param xContentRegistry registry of the node.
     * @return the policy file.
     */
    private static PolicyFile loadPolicy(
            Path directory, String policy, long now, NamedXContentRegistry xContentRegistry) {
        Path file = directory.resolve(policy + ".json");
        if (!Files.isRegularFile(file)) {
            throw new SetupConfigException(
                    "policy file [" + file + "] not found, and [" + POLICIES + policy + CUSTOM + "] is true");
        }
        byte[] content;
        try {
            content = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new SetupConfigException("policy file [" + file + "] cannot be read: " + e, e);
        }
        SetupConfig.validatePolicy(file, policy, SetupConfig.parsePolicy(file, content), now);
        SetupConfig.parseAsIndexStateManagement(file, policy, content, xContentRegistry);
        return new PolicyFile(file, content, SetupConfig.sha256(content));
    }

    /**
     * Parses a policy file with the parser of Index State Management (ISM), the one that reads the
     * policy once it is stored. It checks what {@link #validatePolicy} does not: the states, their
     * actions and transitions, and the values.
     *
     * <p>The plugin stores the policy without the ISM API, so ISM checks nothing at that point. To
     * attach the policies to new indices, ISM reads all of them in one go. A stored policy it cannot
     * parse makes that read fail, and from then on no new index gets a policy, whichever policy it
     * should get. So a policy that ISM cannot parse must never be stored.
     *
     * @param file path of the file, for the error message.
     * @param policy id of the default policy.
     * @param content content of the file, already checked to hold only the {@code policy} object.
     * @param xContentRegistry registry of the node.
     */
    private static void parseAsIndexStateManagement(
            Path file, String policy, byte[] content, NamedXContentRegistry xContentRegistry) {
        try (XContentParser parser =
                JsonXContent.jsonXContent.createParser(
                        xContentRegistry,
                        LoggingDeprecationHandler.INSTANCE,
                        new ByteArrayInputStream(content))) {
            // The ISM parser takes the content of the [policy] object: skip "{", "policy" and "{".
            parser.nextToken();
            parser.nextToken();
            parser.nextToken();
            Policy.parse(
                    parser,
                    policy,
                    SequenceNumbers.UNASSIGNED_SEQ_NO,
                    SequenceNumbers.UNASSIGNED_PRIMARY_TERM);
        } catch (Exception e) {
            throw new SetupConfigException(
                    "policy file ["
                            + file
                            + "] is not a policy Index State Management can read: "
                            + SetupConfig.describe(e),
                    e);
        }
    }

    /**
     * Parses the content of a policy file.
     *
     * @param file path of the file, for the error message.
     * @param content content of the file.
     * @return the parsed content.
     */
    private static Map<String, Object> parsePolicy(Path file, byte[] content) {
        try (XContentParser parser =
                JsonXContent.jsonXContent.createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        new ByteArrayInputStream(content))) {
            return parser.map();
        } catch (Exception e) {
            throw new SetupConfigException(
                    "policy file [" + file + "] cannot be read as JSON: " + SetupConfig.describe(e), e);
        }
    }

    /**
     * Checks that the content of a policy file is a policy of the given id that the plugin can store
     * and that Index State Management can apply.
     *
     * <p>The plugin stores the policy without the ISM API, so ISM checks nothing. The fields are
     * checked against the mapping of the ISM configuration index, which rejects any other field. The
     * states and their actions are checked next, by {@link #parseAsIndexStateManagement}.
     *
     * @param file path of the file, for the error messages.
     * @param policy id of the default policy.
     * @param content parsed content of the file.
     * @param now current time, in epoch milliseconds.
     */
    @SuppressWarnings("unchecked")
    private static void validatePolicy(
            Path file, String policy, Map<String, Object> content, long now) {
        if (!(content.get(POLICY_FIELD) instanceof Map)) {
            throw new SetupConfigException("policy file [" + file + "] has no [policy] object");
        }
        Set<String> unknown = new TreeSet<>(content.keySet());
        unknown.remove(POLICY_FIELD);
        if (!unknown.isEmpty()) {
            throw new SetupConfigException(
                    "policy file ["
                            + file
                            + "] has unknown field(s) "
                            + unknown
                            + ": the file holds only the [policy] object");
        }
        Map<String, Object> definition = (Map<String, Object>) content.get(POLICY_FIELD);
        Set<String> known = SetupConfig.policyFields();
        unknown = new TreeSet<>(definition.keySet());
        unknown.removeAll(known);
        if (!unknown.isEmpty()) {
            throw new SetupConfigException(
                    "policy file ["
                            + file
                            + "] has unknown field(s) "
                            + unknown
                            + " in [policy], which can only hold "
                            + new TreeSet<>(known));
        }
        if (!policy.equals(definition.get(POLICY_ID_FIELD))) {
            throw new SetupConfigException(
                    "policy file ["
                            + file
                            + "] must keep the id of the default policy: [policy.policy_id] is ["
                            + definition.get(POLICY_ID_FIELD)
                            + "], expected ["
                            + policy
                            + "]");
        }
        // Index State Management applies a policy to the indices created after this time. Without
        // it, the time is the moment the policy is read, and the policy never applies to any index.
        if (!(definition.get(LAST_UPDATED_TIME_FIELD) instanceof Number)) {
            throw new SetupConfigException(
                    "policy file [" + file + "] has no [policy.last_updated_time] in epoch milliseconds");
        }
        SetupConfig.checkNotInTheFuture(
                file, "policy.last_updated_time", definition.get(LAST_UPDATED_TIME_FIELD), now);
        // ISM takes one template or a list of them. An entry without a time takes the policy's.
        Object ismTemplate = definition.get(ISM_TEMPLATE_FIELD);
        List<Object> entries =
                ismTemplate instanceof List
                        ? (List<Object>) ismTemplate
                        : ismTemplate == null ? List.of() : List.of(ismTemplate);
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i) instanceof Map
                    && ((Map<String, Object>) entries.get(i)).containsKey(LAST_UPDATED_TIME_FIELD)) {
                SetupConfig.checkNotInTheFuture(
                        file,
                        "policy.ism_template[" + i + "].last_updated_time",
                        ((Map<String, Object>) entries.get(i)).get(LAST_UPDATED_TIME_FIELD),
                        now);
            }
        }
    }

    /**
     * Checks a time of a policy file. Index State Management attaches the policy only to the indices
     * created after it, so with a time in the future the backing indices that a rollover creates
     * until then get no policy, and are never deleted.
     *
     * @param file path of the file, for the error message.
     * @param field name of the field, for the error message.
     * @param value value of the field.
     * @param now current time, in epoch milliseconds.
     */
    private static void checkNotInTheFuture(Path file, String field, Object value, long now) {
        if (!(value instanceof Number)) {
            throw new SetupConfigException(
                    "policy file [" + file + "] has no [" + field + "] in epoch milliseconds");
        }
        long time = ((Number) value).longValue();
        if (time > now) {
            throw new SetupConfigException(
                    "policy file ["
                            + file
                            + "]: ["
                            + field
                            + "] is ["
                            + time
                            + "] ("
                            + Instant.ofEpochMilli(time)
                            + "), a time in the future. The policy would not apply to the indices created"
                            + " until then. Set it to the time of the edit in milliseconds (date +%s%3N).");
        }
    }

    /**
     * Returns the fields a policy can have: those of the {@code policy} object in the mapping of the
     * ISM configuration index.
     *
     * @return the field names.
     */
    @SuppressWarnings("unchecked")
    private static Set<String> policyFields() {
        try (InputStream is =
                        SetupConfig.class.getClassLoader().getResourceAsStream(ISM_CONFIG_TEMPLATE);
                XContentParser parser =
                        JsonXContent.jsonXContent.createParser(
                                NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, is)) {
            Map<String, Object> mapping = parser.map();
            for (String field :
                    List.of("template", "mappings", "properties", POLICY_FIELD, "properties")) {
                mapping = (Map<String, Object>) mapping.get(field);
            }
            return mapping.keySet();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "The fields of a policy cannot be read from the mapping in [" + ISM_CONFIG_TEMPLATE + "]",
                    e);
        }
    }

    /**
     * Computes the SHA-256 of a file content.
     *
     * @param content the content.
     * @return the hash, in hexadecimal.
     */
    private static String sha256(byte[] content) {
        return MessageDigests.toHexString(MessageDigests.sha256().digest(content));
    }

    /**
     * Returns the templates that can be overridden: those under a group folder.
     *
     * @param templates resource paths of the index templates of the plugin.
     * @return the templates as {@code <group>.<name>}.
     */
    private static Set<String> overridable(Collection<String> templates) {
        Set<String> ids = new TreeSet<>();
        for (String template : templates) {
            String id = SetupConfig.templateId(template);
            if (id != null) {
                ids.add(id);
            }
        }
        return ids;
    }

    /**
     * Turns the resource path of a template into the {@code <group>.<name>} form the keys use.
     *
     * @param template resource path, for example {@code templates/streams/events}.
     * @return {@code streams.events} for that example, or null for a template outside a group folder.
     */
    private static String templateId(String template) {
        if (template == null || !template.startsWith(TEMPLATES_PATH)) {
            return null;
        }
        String[] parts = template.substring(TEMPLATES_PATH.length()).split("/");
        return parts.length == 2 ? parts[0] + "." + parts[1] : null;
    }

    /**
     * Joins the messages of an error and its causes. The parser wraps the reason, which names the
     * line or the key, one or two levels down.
     *
     * @param error the error.
     * @return the messages, outermost first.
     */
    private static String describe(Throwable error) {
        StringBuilder message = new StringBuilder();
        // The set stops the walk on a cause seen before, if the chain loops.
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable t = error; t != null && seen.add(t); t = t.getCause()) {
            if (t.getMessage() == null || message.indexOf(t.getMessage()) >= 0) {
                continue;
            }
            if (message.length() > 0) {
                message.append(": ");
            }
            message.append(t.getMessage());
        }
        return message.length() > 0 ? message.toString() : error.toString();
    }
}
