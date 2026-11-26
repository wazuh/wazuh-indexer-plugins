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

import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collection;
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

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Client client;

    /**
     * Creates the service.
     *
     * @param client the node client.
     */
    public SigmaFilterService(Client client) {
        this.client = client;
    }

    /**
     * Reads the rules a filter of {@code space} can target, by id. When a rule exists in that space
     * and in Standard, the space's copy is returned.
     *
     * @param ruleIds the rule ids.
     * @param space the filter's space.
     * @param listener receives the rule documents by id; an id that is not found has no entry.
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
                                JsonNode rule = source.path(Constants.KEY_DOCUMENT);
                                String id = rule.path(Constants.KEY_ID).asText();
                                if (space.toString().equals(source.at("/space/name").asText())) {
                                    rules.put(id, rule);
                                } else {
                                    rules.putIfAbsent(id, rule);
                                }
                            }
                            listener.onResponse(rules);
                        },
                        listener::onFailure));
    }

    /**
     * Checks that a filter of {@code space} applies to every rule it targets: each rule exists and
     * the filter composes with it.
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
                            for (String ruleId : ruleIds) {
                                JsonNode rule = rules.get(ruleId);
                                if (rule == null) {
                                    listener.onResponse(
                                            String.format(
                                                    Locale.ROOT, Constants.E_400_SIGMA_FILTER_RULE_NOT_FOUND, ruleId, space));
                                    return;
                                }
                                try {
                                    SigmaFilterComposer.compose(rule, List.of(filter));
                                } catch (SigmaFilterComposer.ComposeException e) {
                                    listener.onResponse(e.getMessage());
                                    return;
                                }
                            }
                            listener.onResponse(null);
                        },
                        listener::onFailure));
    }
}
