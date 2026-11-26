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
package com.wazuh.contentmanager.cti.catalog.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Applies Sigma filters to a rule, the way pySigma does: each filter's selections are added to the
 * rule's detection under a prefix, and its condition is appended as {@code (<rule condition>) and
 * (<filter condition>)}. The filter author writes the negation ({@code not selection}).
 *
 * <p>The prefix is {@code _filt_} and the first ten hexadecimal digits of the filter id, so the
 * composed rule is the same every time and each composed selection can be traced to its filter. A
 * leading underscore keeps the composed selections out of the rule's own selectors ({@code all of
 * them}, {@code 1 of sel*}), as the Sigma specification prescribes and Security Analytics applies.
 *
 * <p>The rule document is never modified: composition returns a copy.
 */
public final class SigmaFilterComposer {

    private static final Logger log = LogManager.getLogger(SigmaFilterComposer.class);

    /** Prefix of the identifiers a filter adds to a rule. */
    public static final String PREFIX = "_filt_";

    /** Hexadecimal digits of the filter id the prefix takes. */
    private static final int PREFIX_ID_LENGTH = 10;

    private static final String KEY_DETECTION = "detection";
    private static final String KEY_CONDITION = "condition";
    private static final String KEY_TIMEFRAME = "timeframe";
    private static final String KEY_FILTER = "filter";
    private static final String KEY_RULES = "rules";
    private static final String KEY_LOGSOURCE = "logsource";
    private static final String KEY_ID = "id";
    private static final String KEY_ENABLED = "enabled";
    private static final String NOT = "not";
    private static final String THEM = "them";

    /** The logsource keys a filter is matched on, as pySigma does. */
    private static final List<String> LOGSOURCE_KEYS = List.of("category", "product", "service");

    private static final Set<String> OPERATORS = Set.of("and", "or", NOT);

    /** The tokens of Security Analytics' condition grammar ({@code Condition.g4}). */
    private static final Pattern TOKEN =
            Pattern.compile(
                    "(?<selector>(?<quantifier>1|any|all) of (?<pattern>[A-Za-z_0-9*]+))"
                            + "|(?<identifier>[a-zA-Z_][a-zA-Z_0-9]*)"
                            + "|(?<paren>[()])"
                            + "|(?<space>[ \\r\\n\\t]+)");

    private static final Pattern IDENTIFIER = Pattern.compile("[a-zA-Z_][a-zA-Z_0-9]*");

    private static final Pattern RULE_SELECTOR = Pattern.compile("(?:1|any|all) of ([A-Za-z_0-9*]+)");

    private SigmaFilterComposer() {}

    /** A filter that cannot be applied to a rule. The message is safe to return to the user. */
    public static class ComposeException extends Exception {
        /**
         * Creates the exception.
         *
         * @param message why the filter cannot be applied.
         */
        public ComposeException(String message) {
            super(message);
        }
    }

    /** A token of a condition: its kind and its text. */
    private record Token(String kind, String text, String quantifier, String pattern) {}

    /**
     * Returns the prefix of the identifiers a filter adds to a rule.
     *
     * @param filterId the filter id.
     * @return {@code _filt_} followed by the first ten hexadecimal digits of the id and {@code _}.
     */
    public static String prefix(String filterId) {
        String digits = filterId.replaceAll("[^0-9A-Fa-f]", "").toLowerCase(Locale.ROOT);
        return PREFIX + digits.substring(0, Math.min(PREFIX_ID_LENGTH, digits.length())) + "_";
    }

    /**
     * Checks a filter on its own: its structure and its condition, which must be a single top-level
     * negation over its selections.
     *
     * @param filter the filter document ({@code logsource}, {@code filter}).
     * @return the names of the filter's selections.
     * @throws ComposeException if the filter is malformed or follows the other convention.
     */
    public static List<String> validateFilter(JsonNode filter) throws ComposeException {
        if (!filter.path(KEY_LOGSOURCE).isObject()) {
            throw new ComposeException(Constants.E_400_SIGMA_FILTER_MISSING_LOGSOURCE);
        }
        JsonNode body = filter.path(KEY_FILTER);
        if (!body.isObject()) {
            throw new ComposeException(Constants.E_400_SIGMA_FILTER_MISSING_FILTER);
        }
        JsonNode rules = body.path(KEY_RULES);
        if (!rules.isArray() || rules.isEmpty()) {
            throw new ComposeException(Constants.E_400_SIGMA_FILTER_RULES);
        }
        for (JsonNode rule : rules) {
            if (!rule.isTextual() || rule.asText().isBlank()) {
                throw new ComposeException(Constants.E_400_SIGMA_FILTER_RULES);
            }
        }
        JsonNode condition = body.path(KEY_CONDITION);
        if (!condition.isTextual()) {
            throw new ComposeException(Constants.E_400_SIGMA_FILTER_CONDITION_NOT_STRING);
        }
        List<String> selections = new ArrayList<>();
        for (Iterator<String> it = body.fieldNames(); it.hasNext(); ) {
            String key = it.next();
            if (KEY_RULES.equals(key) || KEY_CONDITION.equals(key)) {
                continue;
            }
            if (!IDENTIFIER.matcher(key).matches()) {
                throw new ComposeException(
                        String.format(Locale.ROOT, Constants.E_400_SIGMA_FILTER_SELECTION_NAME, key));
            }
            selections.add(key);
        }
        if (selections.isEmpty()) {
            throw new ComposeException(Constants.E_400_SIGMA_FILTER_NO_SELECTION);
        }
        List<Token> tokens = tokenize(condition.asText());
        requireSingleTopLevelNot(condition.asText(), tokens);
        renameCondition(condition.asText(), tokens, selections, "");
        return selections;
    }

    /**
     * Returns a copy of the rule with the filters applied.
     *
     * @param rule the rule document ({@code id}, {@code logsource}, {@code detection}).
     * @param filters the filter documents to apply. They are applied in the order of their ids.
     * @return the composed rule, or the rule itself when there are no filters.
     * @throws ComposeException if one of the filters cannot be applied to this rule.
     */
    public static JsonNode compose(JsonNode rule, List<JsonNode> filters) throws ComposeException {
        if (filters == null || filters.isEmpty()) {
            return rule;
        }
        String ruleId = rule.path(KEY_ID).asText();
        JsonNode detection = rule.path(KEY_DETECTION);
        JsonNode ruleCondition = detection.path(KEY_CONDITION);
        if (!ruleCondition.isTextual()) {
            throw new ComposeException(
                    String.format(Locale.ROOT, Constants.E_400_SIGMA_FILTER_RULE_CONDITION, ruleId));
        }
        if (ruleCondition.asText().contains("|") || detection.has(KEY_TIMEFRAME)) {
            throw new ComposeException(
                    String.format(Locale.ROOT, Constants.E_400_SIGMA_FILTER_RULE_AGGREGATES, ruleId));
        }

        ObjectNode composed = rule.deepCopy();
        ObjectNode composedDetection = (ObjectNode) composed.get(KEY_DETECTION);
        List<String> composedIdentifiers = new ArrayList<>();
        StringBuilder condition = new StringBuilder("(").append(ruleCondition.asText()).append(")");

        List<JsonNode> sorted = new ArrayList<>(filters);
        sorted.sort(Comparator.comparing(f -> f.path(KEY_ID).asText()));
        for (JsonNode filter : sorted) {
            String filterId = filter.path(KEY_ID).asText();
            if (!logsourceContained(filter.path(KEY_LOGSOURCE), rule.path(KEY_LOGSOURCE))) {
                throw new ComposeException(
                        String.format(
                                Locale.ROOT,
                                Constants.E_400_SIGMA_FILTER_LOGSOURCE_MISMATCH,
                                filter.path(KEY_LOGSOURCE),
                                rule.path(KEY_LOGSOURCE),
                                ruleId));
            }
            List<String> selections = validateFilter(filter);
            String prefix = prefix(filterId);
            for (String selection : selections) {
                String identifier = prefix + selection;
                if (composedDetection.has(identifier)) {
                    throw new ComposeException(
                            String.format(
                                    Locale.ROOT, Constants.E_400_SIGMA_FILTER_IDENTIFIER_TAKEN, ruleId, identifier));
                }
                composedDetection.set(identifier, filter.path(KEY_FILTER).get(selection).deepCopy());
                composedIdentifiers.add(identifier);
            }
            String filterCondition = filter.path(KEY_FILTER).path(KEY_CONDITION).asText();
            condition
                    .append(" and (")
                    .append(renameCondition(filterCondition, tokenize(filterCondition), selections, prefix))
                    .append(")");
        }
        requireRuleSelectorsSkip(ruleId, ruleCondition.asText(), composedIdentifiers);
        composedDetection.put(KEY_CONDITION, condition.toString());
        return composed;
    }

    /**
     * Applies to a rule the enabled filters that target it. A filter that cannot be applied, for
     * example because CTI changed the rule's logsource after the filter was written, is skipped with
     * a warning and the others still apply: a filter never blocks the rule it targets.
     *
     * @param rule the rule document.
     * @param filtersByRule filter documents by the id of each rule they target.
     * @return the rule with its applicable filters applied, or the rule itself if none applies.
     */
    public static JsonNode applyOrKeep(JsonNode rule, Map<String, List<JsonNode>> filtersByRule) {
        String ruleId = rule.path(KEY_ID).asText();
        List<JsonNode> filters = filtersByRule.get(ruleId);
        if (filters == null || filters.isEmpty()) {
            return rule;
        }
        List<JsonNode> applicable = new ArrayList<>();
        for (JsonNode filter : filters) {
            if (!filter.path(KEY_ENABLED).asBoolean(true)) {
                continue;
            }
            try {
                compose(rule, List.of(filter));
                applicable.add(filter);
            } catch (ComposeException e) {
                log.warn(
                        Constants.W_LOG_SIGMA_FILTER_NOT_APPLIED,
                        filter.path(KEY_ID).asText(),
                        ruleId,
                        e.getMessage());
            }
        }
        try {
            return compose(rule, applicable);
        } catch (ComposeException e) {
            // Each filter applies alone but not together: two filter ids share their prefix.
            log.warn(
                    Constants.W_LOG_SIGMA_FILTER_NOT_APPLIED,
                    applicable.stream().map(f -> f.path(KEY_ID).asText()).toList(),
                    ruleId,
                    e.getMessage());
            return rule;
        }
    }

    /**
     * Whether a filter fits a rule's logsource: every key among category, product and service that
     * the filter sets has the rule's value, as in pySigma.
     *
     * @param filterLogsource the filter's logsource.
     * @param ruleLogsource the rule's logsource.
     * @return true if the filter fits the rule.
     */
    static boolean logsourceContained(JsonNode filterLogsource, JsonNode ruleLogsource) {
        for (String key : LOGSOURCE_KEYS) {
            JsonNode value = filterLogsource.path(key);
            if (!value.isMissingNode()
                    && !value.isNull()
                    && !value.asText().equals(ruleLogsource.path(key).asText(null))) {
                return false;
            }
        }
        return true;
    }

    /** Splits a condition into the tokens of Security Analytics' grammar. */
    private static List<Token> tokenize(String condition) throws ComposeException {
        List<Token> tokens = new ArrayList<>();
        Matcher m = TOKEN.matcher(condition);
        int position = 0;
        while (position < condition.length()) {
            if (!m.find(position) || m.start() != position) {
                throw new ComposeException(
                        String.format(Locale.ROOT, Constants.E_400_SIGMA_FILTER_CONDITION_SYNTAX, condition));
            }
            if (m.group("selector") != null) {
                tokens.add(new Token("selector", m.group(), m.group("quantifier"), m.group("pattern")));
            } else if (m.group("identifier") != null) {
                tokens.add(new Token("identifier", m.group(), null, null));
            } else if (m.group("paren") != null) {
                tokens.add(new Token("paren", m.group(), null, null));
            } else {
                tokens.add(new Token("space", m.group(), null, null));
            }
            position = m.end();
        }
        return tokens;
    }

    /**
     * Requires the condition to be one {@code not} over one operand: a selection, a selector or a
     * parenthesized group. {@code not} binds tighter than {@code and} and {@code or}, so {@code not a
     * and b} negates {@code a} alone and is rejected.
     */
    private static void requireSingleTopLevelNot(String condition, List<Token> tokens)
            throws ComposeException {
        List<Token> significant = tokens.stream().filter(t -> !"space".equals(t.kind())).toList();
        long negations = significant.stream().filter(t -> NOT.equals(t.text())).count();
        boolean valid =
                negations == 1 && significant.size() >= 2 && NOT.equals(significant.get(0).text());
        if (valid) {
            List<Token> operand = significant.subList(1, significant.size());
            if (operand.size() == 1) {
                Token only = operand.get(0);
                valid =
                        "selector".equals(only.kind())
                                || ("identifier".equals(only.kind()) && !OPERATORS.contains(only.text()));
            } else {
                valid = "(".equals(operand.get(0).text()) && closingParen(operand) == operand.size() - 1;
            }
        }
        if (!valid) {
            throw new ComposeException(
                    String.format(
                            Locale.ROOT, Constants.E_400_SIGMA_FILTER_CONDITION_NOT_NEGATION, condition));
        }
    }

    /** Index of the parenthesis closing the one the tokens start with, or -1. */
    private static int closingParen(List<Token> tokens) {
        int depth = 0;
        for (int i = 0; i < tokens.size(); i++) {
            String text = tokens.get(i).text();
            if ("(".equals(text)) {
                depth++;
            } else if (")".equals(text)) {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * Prefixes every selection and selector pattern of a filter condition. {@code them} becomes
     * {@code <prefix>*}, which selects the filter's own selections only. Each name must refer to the
     * filter's selections.
     */
    private static String renameCondition(
            String condition, List<Token> tokens, List<String> selections, String prefix)
            throws ComposeException {
        StringBuilder out = new StringBuilder();
        for (Token token : tokens) {
            switch (token.kind()) {
                case "identifier" -> {
                    if (OPERATORS.contains(token.text())) {
                        out.append(token.text());
                    } else if (selections.contains(token.text())) {
                        out.append(prefix).append(token.text());
                    } else {
                        throw new ComposeException(
                                String.format(
                                        Locale.ROOT,
                                        Constants.E_400_SIGMA_FILTER_UNDEFINED_SELECTION,
                                        condition,
                                        token.text()));
                    }
                }
                case "selector" -> {
                    String pattern = THEM.equals(token.pattern()) ? "*" : token.pattern();
                    Pattern regex = Pattern.compile(pattern.replace("*", ".*"));
                    if (selections.stream().noneMatch(s -> regex.matcher(s).matches())) {
                        throw new ComposeException(
                                String.format(
                                        Locale.ROOT,
                                        Constants.E_400_SIGMA_FILTER_UNDEFINED_SELECTION,
                                        condition,
                                        token.pattern()));
                    }
                    out.append(token.quantifier()).append(" of ").append(prefix).append(pattern);
                }
                default -> out.append(token.text());
            }
        }
        return out.toString();
    }

    /**
     * Rejects a rule selector that would also select the composed identifiers. Security Analytics
     * skips identifiers that start with an underscore unless the selector pattern starts with one, so
     * only those patterns can.
     */
    private static void requireRuleSelectorsSkip(
            String ruleId, String ruleCondition, List<String> composedIdentifiers)
            throws ComposeException {
        Matcher m = RULE_SELECTOR.matcher(ruleCondition);
        while (m.find()) {
            String pattern = m.group(1);
            if (!pattern.startsWith("_")) {
                continue;
            }
            Pattern regex = Pattern.compile(pattern.replace("*", ".*"));
            if (composedIdentifiers.stream().anyMatch(id -> regex.matcher(id).matches())) {
                throw new ComposeException(
                        String.format(
                                Locale.ROOT, Constants.E_400_SIGMA_FILTER_RULE_SELECTOR, m.group(), ruleId));
            }
        }
    }
}
