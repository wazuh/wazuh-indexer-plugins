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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Reads the data needed to decide whether a promotion would leave a detector without enabled rules:
 * the detectors currently running and the {@code enabled} state of rules in a given space.
 *
 * <p>Contains no decision logic; see {@link
 * com.wazuh.contentmanager.cti.catalog.utils.DetectorRuleGuard}.
 */
public class DetectorLookupService {

    private static final Logger log = LogManager.getLogger(DetectorLookupService.class);

    private static final int MAX_RESULTS = 10000;

    /**
     * Security Analytics detectors index. Read-only: content-manager never writes to it, and cannot
     * reference the constant from security-analytics because only its {@code commons} module is on
     * the compile classpath.
     */
    private static final String DETECTORS_INDEX = ".opensearch-sap-detectors-config";

    private static final String CUSTOM_RULES_PATH = "detector.inputs.detector_input.custom_rules";

    private final Client client;

    /**
     * @param client the OpenSearch client.
     */
    public DetectorLookupService(Client client) {
        this.client = client;
    }

    /**
     * A detector and the custom rules it references.
     *
     * @param id the detector document id.
     * @param name the detector name, used in user-facing messages.
     * @param enabled whether the detector is running.
     * @param ruleIds the content-manager rule ids referenced through {@code custom_rules}.
     */
    public record DetectorRules(String id, String name, boolean enabled, List<String> ruleIds) {}

    /**
     * Returns the enabled detectors that reference any of the given rules, with the custom rules each
     * one references.
     *
     * <p>The nested query narrows the result server-side. Because {@code custom_rules.id} is mapped
     * as {@code text}, the match is analysed and can return detectors that merely share a token of a
     * UUID; those are discarded by an exact intersection check. The match never misses a real
     * reference, so no detector is silently skipped.
     *
     * <p>Disabled detectors are filtered out: a stopped detector needs no protection.
     *
     * <p>A failed search is propagated to the caller and fails the promotion: it must not be let
     * through on a guard that could not read its inputs. A cluster with no detectors index yet is not
     * one of those failures, because the search uses {@code LENIENT_EXPAND_OPEN} and gets an empty
     * result instead of an error.
     *
     * @param ruleIds the content-manager rule ids being promoted.
     * @param listener receives the affected detectors, or the failure that prevented reading them.
     */
    public void findDetectorsUsingRules(
            Set<String> ruleIds, ActionListener<List<DetectorRules>> listener) {
        if (ruleIds.isEmpty()) {
            listener.onResponse(Collections.emptyList());
            return;
        }

        BoolQueryBuilder anyRule = QueryBuilders.boolQuery().minimumShouldMatch(1);
        for (String ruleId : ruleIds) {
            anyRule.should(QueryBuilders.matchQuery(CUSTOM_RULES_PATH + ".id", ruleId));
        }

        SearchRequest request =
                new SearchRequest(DETECTORS_INDEX)
                        .source(
                                new SearchSourceBuilder()
                                        .query(QueryBuilders.nestedQuery(CUSTOM_RULES_PATH, anyRule, ScoreMode.None))
                                        .fetchSource(
                                                new String[] {
                                                    "detector.name", "detector.enabled", CUSTOM_RULES_PATH + ".id"
                                                },
                                                null)
                                        .size(MAX_RESULTS))
                        .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN);

        this.client.search(
                request,
                ActionListener.wrap(
                        response -> {
                            List<DetectorRules> detectors = new ArrayList<>();
                            for (SearchHit hit : response.getHits()) {
                                DetectorRules parsed = parseDetector(hit);
                                if (parsed != null
                                        && parsed.enabled()
                                        && parsed.ruleIds().stream().anyMatch(ruleIds::contains)) {
                                    detectors.add(parsed);
                                }
                            }
                            listener.onResponse(detectors);
                        },
                        e -> {
                            log.warn(Constants.W_LOG_DETECTOR_LOOKUP_FAILED, e.getMessage());
                            listener.onFailure(e);
                        }));
    }

    /** Extracts the name, enabled flag and referenced custom rule ids from a detector document. */
    @SuppressWarnings("unchecked")
    private static DetectorRules parseDetector(SearchHit hit) {
        Map<String, Object> source = hit.getSourceAsMap();
        Object detectorObj = source == null ? null : source.get(Constants.KEY_DETECTOR);
        if (!(detectorObj instanceof Map)) {
            return null;
        }
        Map<String, Object> detector = (Map<String, Object>) detectorObj;

        boolean enabled = Boolean.TRUE.equals(detector.get(Constants.KEY_ENABLED));
        Object name = detector.get(Constants.KEY_NAME);

        List<String> ruleIds = new ArrayList<>();
        Object inputsObj = detector.get("inputs");
        if (inputsObj instanceof List) {
            for (Object inputObj : (List<Object>) inputsObj) {
                if (!(inputObj instanceof Map)) {
                    continue;
                }
                Object detectorInputObj = ((Map<String, Object>) inputObj).get("detector_input");
                if (!(detectorInputObj instanceof Map)) {
                    continue;
                }
                Object customRulesObj = ((Map<String, Object>) detectorInputObj).get("custom_rules");
                if (!(customRulesObj instanceof List)) {
                    continue;
                }
                for (Object ruleObj : (List<Object>) customRulesObj) {
                    if (ruleObj instanceof Map) {
                        Object id = ((Map<String, Object>) ruleObj).get(Constants.KEY_ID);
                        if (id != null) {
                            ruleIds.add(id.toString());
                        }
                    }
                }
            }
        }

        return new DetectorRules(
                hit.getId(), name == null ? hit.getId() : name.toString(), enabled, ruleIds);
    }

    /**
     * Returns the {@code enabled} state of the given rules within a space. A rule whose document has
     * no {@code enabled} field counts as enabled, matching the convention used elsewhere. Rules that
     * do not exist in the space are simply absent from the result.
     *
     * @param ruleIds the content-manager rule ids to look up.
     * @param space the space to read from.
     * @param listener receives rule id to enabled state.
     */
    public void fetchRuleEnabledStates(
            Set<String> ruleIds, Space space, ActionListener<Map<String, Boolean>> listener) {
        if (ruleIds.isEmpty()) {
            listener.onResponse(Collections.emptyMap());
            return;
        }

        SearchRequest request =
                new SearchRequest(Constants.INDEX_RULES)
                        .source(
                                new SearchSourceBuilder()
                                        .query(
                                                QueryBuilders.boolQuery()
                                                        .must(QueryBuilders.termsQuery(Constants.Q_DOCUMENT_ID, ruleIds))
                                                        .must(
                                                                QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space.toString())))
                                        .fetchSource(
                                                new String[] {Constants.Q_DOCUMENT_ID, Constants.Q_DOCUMENT_ENABLED}, null)
                                        .size(MAX_RESULTS));

        this.client.search(
                request,
                ActionListener.wrap(
                        response -> {
                            Map<String, Boolean> states = new HashMap<>();
                            for (SearchHit hit : response.getHits()) {
                                Map<String, Object> source = hit.getSourceAsMap();
                                Object documentObj = source == null ? null : source.get(Constants.KEY_DOCUMENT);
                                if (!(documentObj instanceof Map)) {
                                    continue;
                                }
                                @SuppressWarnings("unchecked")
                                Map<String, Object> document = (Map<String, Object>) documentObj;
                                Object id = document.get(Constants.KEY_ID);
                                if (id == null) {
                                    continue;
                                }
                                states.put(
                                        id.toString(), !Boolean.FALSE.equals(document.get(Constants.KEY_ENABLED)));
                            }
                            listener.onResponse(states);
                        },
                        listener::onFailure));
    }
}
