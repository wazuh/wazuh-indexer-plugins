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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.utils.SigmaFilterComposer;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Reads the Sigma filters and the rules they target.
 *
 * <p>A filter targets rules by their {@code document.id}: a Standard rule, or a rule of the
 * filter's own space.
 */
public class SigmaFilterService {

    private static final Logger log = LogManager.getLogger(SigmaFilterService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Client client;

    /** Validates the rules with a filter applied; {@code null} when the caller only reads. */
    private final SecurityAnalyticsService securityAnalytics;

    /**
     * Creates the service, for reading only.
     *
     * @param client the node client.
     */
    public SigmaFilterService(Client client) {
        this(client, null);
    }

    /**
     * Creates the service.
     *
     * @param client the node client.
     * @param securityAnalytics validates the rules with a filter applied, in {@link #checkTargets}.
     */
    public SigmaFilterService(Client client, SecurityAnalyticsService securityAnalytics) {
        this.client = client;
        this.securityAnalytics = securityAnalytics;
    }

    /**
     * Reads the Sigma filters of a space, grouped by the id of each rule they target. A missing index
     * or a failed read yields no filters, with a warning: a filter never blocks the rules it targets.
     *
     * @param space the space whose filters to read.
     * @param listener receives the filter documents by target rule id.
     */
    public void filtersByRule(Space space, ActionListener<Map<String, List<JsonNode>>> listener) {
        this.filtersByRule(space, null, listener);
    }

    /**
     * Reads the Sigma filters of a space that target any of the given rules, grouped by the id of
     * each rule they target. As {@link #filtersByRule(Space, ActionListener)}, a failed read yields
     * no filters.
     *
     * @param space the space whose filters to read.
     * @param ruleIds the rules whose filters to read, or {@code null} for every rule.
     * @param listener receives the filter documents by target rule id.
     */
    public void filtersByRule(
            Space space,
            Collection<String> ruleIds,
            ActionListener<Map<String, List<JsonNode>>> listener) {
        BoolQueryBuilder query =
                QueryBuilders.boolQuery()
                        .filter(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString()));
        if (ruleIds != null) {
            query.filter(QueryBuilders.termsQuery(Constants.Q_SIGMA_FILTER_RULES, ruleIds));
        }
        SearchRequest request =
                new SearchRequest(Constants.INDEX_SIGMA_FILTERS)
                        .indicesOptions(IndicesOptions.lenientExpandOpen())
                        .source(new SearchSourceBuilder().query(query).size(Constants.MAX_RESULT_WINDOW));
        this.client.search(
                request,
                ActionListener.wrap(
                        response -> {
                            Map<String, List<JsonNode>> byRule = new HashMap<>();
                            for (SearchHit hit : response.getHits().getHits()) {
                                JsonNode filter =
                                        MAPPER.readTree(hit.getSourceAsString()).path(Constants.KEY_DOCUMENT);
                                for (JsonNode ruleId :
                                        filter.path(Constants.KEY_FILTER).path(Constants.KEY_RULES)) {
                                    byRule.computeIfAbsent(ruleId.asText(), k -> new ArrayList<>()).add(filter);
                                }
                            }
                            listener.onResponse(byRule);
                        },
                        e -> {
                            log.warn(Constants.W_LOG_SIGMA_FILTERS_READ_FAILED, space, e.getMessage());
                            listener.onResponse(Collections.emptyMap());
                        }));
    }

    /**
     * Reads the rules a filter of {@code space} can target, by id. When a rule exists in that space
     * and in Standard, the space's copy is returned.
     *
     * @param ruleIds the rule ids.
     * @param space the filter's space.
     * @param listener receives the stored rules ({@code document} and {@code space}) by id; an id
     *     that is not found has no entry.
     */
    public void findRules(
            Collection<String> ruleIds, Space space, ActionListener<Map<String, JsonNode>> listener) {
        SearchRequest request =
                new SearchRequest(Constants.INDEX_RULES)
                        .source(
                                new SearchSourceBuilder()
                                        .query(
                                                QueryBuilders.boolQuery()
                                                        .filter(QueryBuilders.termsQuery(Constants.Q_DOCUMENT_ID, ruleIds))
                                                        .filter(
                                                                QueryBuilders.termsQuery(
                                                                        Constants.Q_SPACE_NAME,
                                                                        Space.STANDARD.toString(),
                                                                        space.toString())))
                                        .size(2 * ruleIds.size()));
        this.client.search(
                request,
                ActionListener.wrap(
                        response -> {
                            Map<String, JsonNode> rules = new HashMap<>();
                            for (SearchHit hit : response.getHits().getHits()) {
                                JsonNode source = MAPPER.readTree(hit.getSourceAsString());
                                String id = source.path(Constants.KEY_DOCUMENT).path(Constants.KEY_ID).asText();
                                if (space.toString().equals(source.at("/space/name").asText())) {
                                    rules.put(id, source);
                                } else {
                                    rules.putIfAbsent(id, source);
                                }
                            }
                            listener.onResponse(rules);
                        },
                        listener::onFailure));
    }

    /**
     * Reads the rules with the given ids in one space.
     *
     * @param ruleIds the rule ids.
     * @param space the space to read them from.
     * @param listener receives the rule documents by id; an id that is not found has no entry.
     */
    public void findRulesInSpace(
            Collection<String> ruleIds, Space space, ActionListener<Map<String, JsonNode>> listener) {
        SearchRequest request =
                new SearchRequest(Constants.INDEX_RULES)
                        .source(
                                new SearchSourceBuilder()
                                        .query(
                                                QueryBuilders.boolQuery()
                                                        .filter(QueryBuilders.termsQuery(Constants.Q_DOCUMENT_ID, ruleIds))
                                                        .filter(
                                                                QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString())))
                                        .size(ruleIds.size()));
        this.client.search(
                request,
                ActionListener.wrap(
                        response -> {
                            Map<String, JsonNode> rules = new HashMap<>();
                            for (SearchHit hit : response.getHits().getHits()) {
                                JsonNode rule =
                                        MAPPER.readTree(hit.getSourceAsString()).path(Constants.KEY_DOCUMENT);
                                rules.put(rule.path(Constants.KEY_ID).asText(), rule);
                            }
                            listener.onResponse(rules);
                        },
                        listener::onFailure));
    }

    /**
     * Checks that a filter of {@code space} applies to every rule it targets: each rule exists, the
     * filter composes with it and, when the service validates, Security Analytics accepts the
     * composed rule (its fields belong to WCS and it compiles to a query that parses).
     *
     * @param filter the filter document.
     * @param space the filter's space.
     * @param listener receives {@code null} when the filter applies to every target, or the reason it
     *     does not, which is safe to return to the user.
     */
    public void checkTargets(JsonNode filter, Space space, ActionListener<String> listener) {
        List<String> ruleIds = new ArrayList<>();
        filter
                .path(Constants.KEY_FILTER)
                .path(Constants.KEY_RULES)
                .forEach(id -> ruleIds.add(id.asText()));
        this.findRules(
                ruleIds,
                space,
                ActionListener.wrap(
                        rules -> {
                            List<Map.Entry<Space, JsonNode>> composed = new ArrayList<>();
                            for (String ruleId : ruleIds) {
                                JsonNode stored = rules.get(ruleId);
                                if (stored == null) {
                                    listener.onResponse(
                                            String.format(
                                                    Locale.ROOT, Constants.E_400_SIGMA_FILTER_RULE_NOT_FOUND, ruleId, space));
                                    return;
                                }
                                try {
                                    composed.add(
                                            Map.entry(
                                                    Space.fromValue(stored.at("/space/name").asText()),
                                                    SigmaFilterComposer.compose(
                                                            stored.path(Constants.KEY_DOCUMENT), List.of(filter))));
                                } catch (SigmaFilterComposer.ComposeException e) {
                                    listener.onResponse(e.getMessage());
                                    return;
                                }
                            }
                            this.validateComposed(composed, 0, listener);
                        },
                        listener::onFailure));
    }

    /**
     * Has Security Analytics validate each composed rule in turn, as it would compile it, without
     * storing it. Answers {@code null} when every rule is valid, or the first rejection's reason.
     */
    private void validateComposed(
            List<Map.Entry<Space, JsonNode>> composed, int idx, ActionListener<String> listener) {
        if (this.securityAnalytics == null || idx >= composed.size()) {
            listener.onResponse(null);
            return;
        }
        JsonNode rule = composed.get(idx).getValue();
        this.securityAnalytics.validateRule(
                rule,
                composed.get(idx).getKey(),
                ActionListener.wrap(
                        response -> this.validateComposed(composed, idx + 1, listener),
                        e -> {
                            OpenSearchException rejection =
                                    (OpenSearchException) ExceptionsHelper.unwrap(e, OpenSearchException.class);
                            if (rejection == null || rejection.status().getStatus() >= 500) {
                                listener.onFailure(e);
                                return;
                            }
                            listener.onResponse(
                                    String.format(
                                            Locale.ROOT,
                                            Constants.E_400_SIGMA_FILTER_RULE_INVALID,
                                            rule.path(Constants.KEY_ID).asText(),
                                            SecurityAnalyticsServiceImpl.extractErrorMessage(rejection.getMessage())));
                        }));
    }
}
