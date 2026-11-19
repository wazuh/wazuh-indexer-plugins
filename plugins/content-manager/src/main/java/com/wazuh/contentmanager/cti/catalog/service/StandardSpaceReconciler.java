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
import org.apache.lucene.search.TotalHits;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Removes from Security Analytics the standard integrations, rules and detectors that CTI no longer
 * publishes, by comparing both sides at the end of a sync pass and deleting what is left over.
 *
 * <p>Comparing rather than following the deletions is what makes a failed one retry for free: the
 * resource is still left over, so the next pass finds it again and nothing has to be persisted.
 * Only {@link Space#STANDARD} is read and written; it is CTI's alone, since {@code Space.promote()}
 * never reaches it. The reads block, so this runs on the sync thread only.
 */
class StandardSpaceReconciler {

    private static final Logger log = LogManager.getLogger(StandardSpaceReconciler.class);

    /**
     * Security Analytics log types index. Read-only, and the constant cannot be imported from
     * security-analytics because only its {@code commons} module is on the compile classpath -- the
     * same reason {@link DetectorLookupService} spells out its own copy.
     */
    private static final String LOG_TYPES_INDEX = ".opensearch-sap-log-types-config";

    /** Security Analytics pre-packaged rules index, where the standard rules live. Read-only. */
    private static final String PRE_PACKAGED_RULES_INDEX =
            ".opensearch-sap-pre-packaged-rules-config";

    /** A log type carries the content-manager id it was built from in this field. */
    private static final String LOG_TYPE_DOCUMENT_ID = "document.id";

    /** The log type's space is {@code text}, so an exact match needs the keyword sub-field. */
    private static final String LOG_TYPE_SPACE = "space.keyword";

    private static final String RULE_DOCUMENT_ID = "rule.document.id";
    private static final String RULE_SPACE = "rule.space";

    /** {@code detector} is mapped as {@code nested}, so its fields need a nested query. */
    private static final String DETECTOR_PATH = "detector";

    /**
     * {@code standard} on a detector the content-manager created, {@code custom} on one a user
     * created; see {@code DetectorFactory} and {@code Detector.DEFAULT_SOURCE} in security-analytics.
     * Filtering on it is what keeps a user's own detectors out of the diff.
     */
    private static final String DETECTOR_SOURCE = DETECTOR_PATH + ".source";

    /** The content-manager's own fields, read straight from the content indices. */
    private static final String CONTENT_RULES = Constants.KEY_DOCUMENT + "." + Constants.KEY_RULES;

    /** How many documents one page of a paginated read asks for. */
    private static final int PAGE_SIZE = 1_000;

    /**
     * How many pages a paginated read may take before it gives up. At {@link #PAGE_SIZE} that is two
     * hundred thousand resources, orders of magnitude above any published ruleset; reaching it means
     * something is wrong with the pagination itself, and reading on would be an unbounded loop.
     */
    private static final int MAX_PAGES = 200;

    private final Client client;
    private final SecurityAnalyticsService securityAnalyticsService;

    /**
     * @param client the OpenSearch client, used to read both sides.
     * @param securityAnalyticsService the service that performs the deletions.
     */
    StandardSpaceReconciler(Client client, SecurityAnalyticsService securityAnalyticsService) {
        this.client = client;
        this.securityAnalyticsService = securityAnalyticsService;
    }

    /**
     * What both sides hold, as the diff needs it.
     *
     * @param contentIntegrations content integration id to the rule ids it lists.
     * @param contentRules content rule ids.
     * @param sapIntegrations the content ids of the standard log types in Security Analytics.
     * @param sapRules the content ids of the standard rules in Security Analytics.
     * @param sapDetectors the ids of the standard detectors in Security Analytics, which are the ids
     *     of the integrations they were built from.
     */
    record Inventory(
            Map<String, List<String>> contentIntegrations,
            Set<String> contentRules,
            Set<String> sapIntegrations,
            Set<String> sapRules,
            Set<String> sapDetectors) {}

    /**
     * What has to go, in the order it has to go in.
     *
     * @param detectors detectors whose integration survives but whose rules CTI removed.
     * @param rules rules Security Analytics still holds and the content no longer has.
     * @param integrations integrations Security Analytics still holds and the content no longer has.
     */
    record Plan(List<String> detectors, List<String> rules, List<String> integrations) {

        boolean isEmpty() {
            return this.detectors.isEmpty() && this.rules.isEmpty() && this.integrations.isEmpty();
        }

        /** Every id the plan touches, for the "only report when the failures change" check. */
        Set<String> ids() {
            Set<String> all = new TreeSet<>(this.detectors);
            all.addAll(this.rules);
            all.addAll(this.integrations);
            return all;
        }
    }

    /**
     * The outcome of one reconciliation.
     *
     * @param pending the ids that had to be deleted and could not. Empty when there was nothing to
     *     delete and also when the reconciliation could not read its inputs, because then nothing is
     *     known to be pending; the read logs its own reason.
     * @param deletedDetectors how many detectors were deleted.
     * @param deletedRules how many rules were deleted.
     * @param deletedIntegrations how many integrations were deleted.
     */
    record Result(
            Set<String> pending, int deletedDetectors, int deletedRules, int deletedIntegrations) {

        private static final Result NOTHING = new Result(Collections.emptySet(), 0, 0, 0);

        /** Nothing read, nothing deleted, nothing known to be pending. */
        static Result nothing() {
            return NOTHING;
        }

        boolean deletedAnything() {
            return this.deletedDetectors + this.deletedRules + this.deletedIntegrations > 0;
        }
    }

    /**
     * Compares both sides and deletes what Security Analytics still holds and the content no longer
     * has.
     *
     * @return what was deleted and what is still pending.
     */
    Result reconcile() {
        Inventory inventory;
        try {
            inventory = this.read();
        } catch (Exception e) {
            // Never read a failure as "the content is gone, delete everything". The cause goes in
            // because the message alone is often just "all shards failed".
            log.warn(Constants.W_LOG_SAP_RECONCILE_READ_FAILED, e.getMessage(), e);
            return Result.nothing();
        }

        if (inventory.contentIntegrations().isEmpty()) {
            // A cluster whose content has not loaded yet is indistinguishable from one whose content
            // was wiped, and the blast radius is the whole space, so the diff does not run. A wipe on
            // purpose goes through StandardSpaceWiper, which clears both sides. An empty rule set
            // with integrations present does run: the content is demonstrably there.
            log.debug(Constants.D_LOG_SAP_RECONCILE_NO_CONTENT);
            return Result.nothing();
        }

        Plan plan = plan(inventory);
        if (plan.isEmpty()) {
            log.debug(Constants.D_LOG_SAP_RECONCILE_NOTHING_STALE);
            return Result.nothing();
        }

        log.info(
                Constants.I_LOG_SAP_RECONCILE_STALE,
                plan.detectors().size(),
                plan.rules().size(),
                plan.integrations().size());

        return this.apply(plan);
    }

    /**
     * Carries out a plan, in the order Security Analytics accepts: detectors, rules, integrations.
     *
     * <p>Detectors go first because one left without rules keeps its monitor and goes on matching,
     * and deleting a standard rule does not correct it. Integrations go last because the log type
     * deletion is refused while an active detector reads it; {@code deleteIntegration} handles that
     * for the standard space by deleting the detector before the log type.
     *
     * @param plan what has to go.
     * @return what was deleted and what is still pending.
     */
    Result apply(Plan plan) {
        Set<String> failed = new LinkedHashSet<>();
        int detectors = this.deleteEach(plan.detectors(), "detectors", failed, this::deleteDetector);
        int rules = this.deleteEach(plan.rules(), "rules", failed, this::deleteRule);
        int integrations =
                this.deleteEach(plan.integrations(), "integrations", failed, this::deleteIntegration);
        return new Result(failed, detectors, rules, integrations);
    }

    /**
     * Works out what is left over on the Security Analytics side.
     *
     * <p>Pure, so the decision can be tested without a cluster.
     *
     * @param inventory what both sides hold.
     * @return what has to be deleted.
     */
    static Plan plan(Inventory inventory) {
        // An integration that survives but whose rules CTI deleted leaves a detector that is still
        // matching: buildDetectorRequest returns null for it, so the detectors phase skips it.
        //
        // The trigger is "no rule it lists still exists in the content", not "no enabled rule": a
        // user who disables the last rule also leaves nothing to build, and their detector must
        // survive that. A disabled rule is still a document, so it keeps the detector out of here.
        List<String> detectors =
                inventory.sapDetectors().stream()
                        .filter(id -> inventory.contentIntegrations().containsKey(id))
                        .filter(
                                id ->
                                        inventory.contentIntegrations().get(id).stream()
                                                .noneMatch(rule -> inventory.contentRules().contains(rule)))
                        .sorted()
                        .toList();

        List<String> rules =
                inventory.sapRules().stream()
                        .filter(id -> !inventory.contentRules().contains(id))
                        .sorted()
                        .toList();

        List<String> integrations =
                inventory.sapIntegrations().stream()
                        .filter(id -> !inventory.contentIntegrations().containsKey(id))
                        .sorted()
                        .toList();

        return new Plan(detectors, rules, integrations);
    }

    /**
     * Reads both sides.
     *
     * <p>The content indices are read strictly: a missing index or a failed search is a failure, so
     * the caller aborts instead of reading "nothing" and deleting everything. The Security Analytics
     * indices are read leniently, because a cluster that has none of them yet simply holds nothing
     * left over.
     *
     * @return what both sides hold.
     * @throws IllegalStateException if a read could not be completed in full.
     */
    Inventory read() {
        Map<String, List<String>> contentIntegrations = new HashMap<>();
        this.eachPage(
                Constants.INDEX_INTEGRATIONS,
                QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.STANDARD.toString()),
                new String[] {Constants.Q_DOCUMENT_ID, CONTENT_RULES},
                Constants.Q_DOCUMENT_ID,
                IndicesOptions.strictExpandOpen(),
                hit -> {
                    String id = documentField(hit, Constants.KEY_ID);
                    if (id != null) {
                        contentIntegrations.put(id, listedRules(hit));
                    }
                });

        Set<String> contentRules = new LinkedHashSet<>();
        this.eachPage(
                Constants.INDEX_RULES,
                QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.STANDARD.toString()),
                new String[] {Constants.Q_DOCUMENT_ID},
                Constants.Q_DOCUMENT_ID,
                IndicesOptions.strictExpandOpen(),
                hit -> {
                    String id = documentField(hit, Constants.KEY_ID);
                    if (id != null) {
                        contentRules.add(id);
                    }
                });

        Set<String> sapIntegrations = new LinkedHashSet<>();
        this.wholeIndex(
                LOG_TYPES_INDEX,
                QueryBuilders.termQuery(LOG_TYPE_SPACE, Space.STANDARD.toString()),
                new String[] {LOG_TYPE_DOCUMENT_ID},
                hit -> {
                    String id = flatField(hit, LOG_TYPE_DOCUMENT_ID);
                    if (id != null) {
                        sapIntegrations.add(id);
                    }
                });

        Set<String> sapRules = new LinkedHashSet<>();
        this.wholeIndex(
                PRE_PACKAGED_RULES_INDEX,
                QueryBuilders.termQuery(RULE_SPACE, Space.STANDARD.toString()),
                new String[] {RULE_DOCUMENT_ID},
                hit -> {
                    String id = ruleDocumentId(hit);
                    if (id != null) {
                        sapRules.add(id);
                    }
                });

        Set<String> sapDetectors = new LinkedHashSet<>();
        this.wholeIndex(
                DetectorLookupService.DETECTORS_INDEX,
                QueryBuilders.nestedQuery(
                        DETECTOR_PATH,
                        QueryBuilders.termQuery(DETECTOR_SOURCE, Space.STANDARD.toString()),
                        ScoreMode.None),
                null,
                hit -> sapDetectors.add(hit.getId()));

        return new Inventory(
                contentIntegrations, contentRules, sapIntegrations, sapRules, sapDetectors);
    }

    /**
     * Reads every document a query matches on a Security Analytics index, in one search.
     *
     * <p>Not paginated: {@code search_after} needs a sort, and these indices are auto-created from
     * the first write with no template, so their string fields are {@code text} and sorting one fails
     * every shard. Hence also {@code space.keyword} in the queries. A result that does not fit one
     * search is reported as a failure rather than used in part, as {@code
     * DetectorLookupService.findDetectorsUsingRules} does.
     *
     * @param index the index to read.
     * @param query the query to match.
     * @param source the source fields to fetch, or {@code null} for the ids alone.
     * @param consumer receives every hit.
     * @throws IllegalStateException if there are more matches than one search returns.
     */
    private void wholeIndex(
            String index, QueryBuilder query, String[] source, Consumer<SearchHit> consumer) {
        SearchSourceBuilder builder =
                new SearchSourceBuilder()
                        .query(query)
                        .trackTotalHits(true)
                        .size(Constants.MAX_RESULT_WINDOW);
        if (source == null) {
            builder.fetchSource(false);
        } else {
            builder.fetchSource(source, null);
        }

        SearchResponse response =
                this.client
                        .search(
                                new SearchRequest(index)
                                        .source(builder)
                                        .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN))
                        .actionGet();

        TotalHits total = response.getHits().getTotalHits();
        if (total != null && total.value() > response.getHits().getHits().length) {
            throw new IllegalStateException(
                    String.format(
                            Locale.ROOT,
                            Constants.E_SAP_RECONCILE_TRUNCATED,
                            index,
                            total.value(),
                            Constants.MAX_RESULT_WINDOW));
        }
        for (SearchHit hit : response.getHits()) {
            consumer.accept(hit);
        }
    }

    /**
     * Reads every document a query matches, one page at a time, and hands each hit to {@code
     * consumer}.
     *
     * <p>For the content indices alone, and paginated rather than capped: a capped read here would
     * look like "these resources are no longer published" and delete them for real. These indices can
     * be sorted on because the Setup plugin creates them from templates that declare {@code
     * document.id} a {@code keyword}. The Security Analytics side uses {@link #wholeIndex}.
     *
     * @param index the index to read.
     * @param query the query to match.
     * @param source the source fields to fetch.
     * @param sortField a keyword field that is unique within the query's results, used to page.
     * @param options how to treat a missing index.
     * @param consumer receives every hit.
     * @throws IllegalStateException if the read takes more than {@link #MAX_PAGES} pages.
     */
    private void eachPage(
            String index,
            QueryBuilder query,
            String[] source,
            String sortField,
            IndicesOptions options,
            Consumer<SearchHit> consumer) {
        Object[] after = null;
        for (int page = 0; page < MAX_PAGES; page++) {
            SearchSourceBuilder builder =
                    new SearchSourceBuilder()
                            .query(query)
                            .fetchSource(source, null)
                            .sort(sortField, SortOrder.ASC)
                            .size(PAGE_SIZE);
            if (after != null) {
                builder.searchAfter(after);
            }
            SearchResponse response =
                    this.client
                            .search(new SearchRequest(index).source(builder).indicesOptions(options))
                            .actionGet();
            SearchHit[] hits = response.getHits().getHits();
            for (SearchHit hit : hits) {
                consumer.accept(hit);
            }
            if (hits.length < PAGE_SIZE) {
                return;
            }
            after = hits[hits.length - 1].getSortValues();
        }
        throw new IllegalStateException(
                String.format(
                        Locale.ROOT, Constants.E_SAP_RECONCILE_PAGINATION_CAP, index, MAX_PAGES, PAGE_SIZE));
    }

    /** Reads a field of the content wrapper's inner {@code document} object. */
    @SuppressWarnings("unchecked")
    private static String documentField(SearchHit hit, String field) {
        Map<String, Object> source = hit.getSourceAsMap();
        Object document = source == null ? null : source.get(Constants.KEY_DOCUMENT);
        if (!(document instanceof Map)) {
            return null;
        }
        Object value = ((Map<String, Object>) document).get(field);
        return value == null ? null : value.toString();
    }

    /** Reads the rule ids a content integration lists, which may be absent or empty. */
    @SuppressWarnings("unchecked")
    private static List<String> listedRules(SearchHit hit) {
        Map<String, Object> source = hit.getSourceAsMap();
        Object document = source == null ? null : source.get(Constants.KEY_DOCUMENT);
        if (!(document instanceof Map)) {
            return Collections.emptyList();
        }
        Object rules = ((Map<String, Object>) document).get(Constants.KEY_RULES);
        if (!(rules instanceof List)) {
            return Collections.emptyList();
        }
        List<String> ids = new ArrayList<>();
        for (Object rule : (List<Object>) rules) {
            if (rule != null) {
                ids.add(rule.toString());
            }
        }
        return ids;
    }

    /**
     * Reads a field whose name holds a dot. Security Analytics declares {@code document.id} as one
     * leaf with that spelling, but OpenSearch may still return it nested, so both shapes are read.
     */
    @SuppressWarnings("unchecked")
    private static String flatField(SearchHit hit, String field) {
        Map<String, Object> source = hit.getSourceAsMap();
        if (source == null) {
            return null;
        }
        Object value = source.get(field);
        if (value != null) {
            return value.toString();
        }
        int dot = field.indexOf('.');
        if (dot < 0) {
            return null;
        }
        Object parent = source.get(field.substring(0, dot));
        if (!(parent instanceof Map)) {
            return null;
        }
        Object nested = ((Map<String, Object>) parent).get(field.substring(dot + 1));
        return nested == null ? null : nested.toString();
    }

    /** Reads {@code rule.document.id} off a Security Analytics rule. */
    @SuppressWarnings("unchecked")
    private static String ruleDocumentId(SearchHit hit) {
        Map<String, Object> source = hit.getSourceAsMap();
        Object rule = source == null ? null : source.get(Constants.KEY_RULE);
        if (!(rule instanceof Map)) {
            return null;
        }
        Map<String, Object> ruleMap = (Map<String, Object>) rule;
        Object flat = ruleMap.get(LOG_TYPE_DOCUMENT_ID);
        if (flat != null) {
            return flat.toString();
        }
        Object document = ruleMap.get(Constants.KEY_DOCUMENT);
        if (!(document instanceof Map)) {
            return null;
        }
        Object id = ((Map<String, Object>) document).get(Constants.KEY_ID);
        return id == null ? null : id.toString();
    }

    /** One deletion, started on the Security Analytics service. */
    private interface Deletion {
        void start(String id, ActionListener<Object> listener);
    }

    /**
     * Deletes every id of one kind, waits for them all, and records the ones that failed.
     *
     * @param ids the ids to delete.
     * @param kind what they are, for the logs.
     * @param failed receives the ids that could not be deleted.
     * @param deletion how to delete one.
     * @return how many were deleted.
     */
    private int deleteEach(List<String> ids, String kind, Set<String> failed, Deletion deletion) {
        if (ids.isEmpty()) {
            return 0;
        }
        CountDownLatch latch = new CountDownLatch(ids.size());
        Set<String> mine = Collections.synchronizedSet(new LinkedHashSet<>());
        for (String id : ids) {
            deletion.start(
                    id,
                    ActionListener.wrap(
                            response -> latch.countDown(),
                            e -> {
                                mine.add(id);
                                log.debug(Constants.D_LOG_SAP_RECONCILE_DELETE_FAILED, kind, id, e.getMessage());
                                latch.countDown();
                            }));
        }
        try {
            if (!latch.await(
                    PluginSettings.getInstance().getSaCleanupTimeoutSeconds(), TimeUnit.SECONDS)) {
                log.warn(Constants.W_LOG_SAP_RECONCILE_TIMEOUT, kind, latch.getCount());
                // Whatever has not answered yet is reported as pending rather than as deleted: the
                // next pass finds it again if it really did not go.
                for (String id : ids) {
                    if (!mine.contains(id)) {
                        mine.add(id);
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn(Constants.W_LOG_SAP_RECONCILE_INTERRUPTED, kind);
            mine.addAll(ids);
        }
        failed.addAll(mine);
        return ids.size() - mine.size();
    }

    @SuppressWarnings("unchecked")
    private void deleteDetector(String id, ActionListener<Object> listener) {
        this.securityAnalyticsService.deleteDetector(id, (ActionListener) listener);
    }

    @SuppressWarnings("unchecked")
    private void deleteRule(String id, ActionListener<Object> listener) {
        this.securityAnalyticsService.deleteRule(id, Space.STANDARD, (ActionListener) listener);
    }

    @SuppressWarnings("unchecked")
    private void deleteIntegration(String id, ActionListener<Object> listener) {
        this.securityAnalyticsService.deleteIntegration(id, Space.STANDARD, (ActionListener) listener);
    }
}
