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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.UnaryOperator;

import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Reads and writes the single registry document that holds the user's overrides for a space: the
 * policy settings they changed and a serialized copy of the filters they created.
 *
 * <p>The document lives in the policies index under {@link Constants#USER_OVERRIDES_DOC_ID} and
 * deliberately carries no {@code space} field. That absence is what keeps it out of the
 * pre-snapshot wipe, which selects by {@code space.name}, and what makes the plan-change reindex
 * carry it into the new physical index. Its space keys live inside the {@code user_overrides}
 * object instead.
 *
 * <p>Every write is a read-modify-write on one shared document, so writers are serialized
 * optimistically with {@code ifSeqNo}/{@code ifPrimaryTerm} rather than with a mutex: a conflict
 * re-reads and re-applies the change against the winner's document, bounded by {@link
 * Constants#MAX_USER_OVERRIDES_UPDATE_ATTEMPTS}.
 */
public class UserOverridesService {

    private static final Logger log = LogManager.getLogger(UserOverridesService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Client client;
    private final SpaceService spaceService;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for the registry's get and index operations.
     * @param spaceService used to locate a space's policy and its real document id when re-applying.
     */
    public UserOverridesService(Client client, SpaceService spaceService) {
        this.client = client;
        this.spaceService = spaceService;
    }

    /**
     * Reads one space's stored overrides.
     *
     * @param spaceName the space to read.
     * @param listener receives the overrides; empty when the registry does not exist yet, which is
     *     the normal state of a cluster where nobody has changed anything.
     */
    public void read(String spaceName, ActionListener<UserOverrides> listener) {
        this.client.get(
                registryGetRequest(),
                ActionListener.wrap(
                        response -> listener.onResponse(parse(response, spaceName)),
                        e -> {
                            log.error(Constants.E_LOG_USER_OVERRIDES_REGISTRY_READ_FAILED, e.getMessage());
                            listener.onFailure(e);
                        }));
    }

    /**
     * Applies {@code mutator} to one space's stored overrides and writes the result back.
     *
     * <p>The mutator receives the overrides currently stored for that space and returns the ones to
     * store. Only that space's key is replaced; the other spaces in the document are left untouched.
     *
     * @param spaceName the space whose overrides are being changed.
     * @param mutator receives the current overrides and returns the ones to store.
     * @param listener notified once the registry has been written.
     */
    public void update(
            String spaceName, UnaryOperator<UserOverrides> mutator, ActionListener<Void> listener) {
        this.tryUpdate(spaceName, mutator, 1, listener);
    }

    private void tryUpdate(
            String spaceName,
            UnaryOperator<UserOverrides> mutator,
            int attempt,
            ActionListener<Void> listener) {
        this.client.get(
                registryGetRequest(),
                ActionListener.wrap(
                        response -> {
                            IndexRequest request = buildWriteRequest(response);
                            ObjectNode root = readRoot(response);

                            ObjectNode registry = (ObjectNode) root.get(Constants.KEY_USER_OVERRIDES);
                            mutator
                                    .apply(UserOverrides.forSpace(registry, spaceName))
                                    .writeInto(registry, spaceName);

                            this.client.index(
                                    request.source(root.toString(), XContentType.JSON),
                                    ActionListener.wrap(
                                            indexed -> listener.onResponse(null),
                                            e -> this.onWriteFailure(spaceName, mutator, attempt, e, listener)));
                        },
                        e -> {
                            log.error(Constants.E_LOG_USER_OVERRIDES_REGISTRY_READ_FAILED, e.getMessage());
                            listener.onFailure(e);
                        }));
    }

    /**
     * Retries the whole read-modify-write on a version conflict.
     *
     * <p>Re-reading is the point: retrying with the document already in hand would write the same
     * stale content again and discard the concurrent writer's change just as surely as having no
     * guard at all.
     */
    private void onWriteFailure(
            String spaceName,
            UnaryOperator<UserOverrides> mutator,
            int attempt,
            Exception e,
            ActionListener<Void> listener) {
        boolean conflict = ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) != null;
        if (conflict && attempt < Constants.MAX_USER_OVERRIDES_UPDATE_ATTEMPTS) {
            log.debug(Constants.D_LOG_USER_OVERRIDES_REGISTRY_CONFLICT, attempt);
            this.tryUpdate(spaceName, mutator, attempt + 1, listener);
            return;
        }
        log.error(Constants.E_LOG_USER_OVERRIDES_REGISTRY_WRITE_FAILED, e.getMessage());
        listener.onFailure(e);
    }

    /**
     * Re-applies a space's stored overrides after it has been rebuilt from CTI.
     *
     * <p>Runs after every sync that changed anything, so it must be idempotent: filters are recreated
     * under their original ids and their ids appended to the policy only when missing.
     *
     * <p>The order matters. Filters are restored first so their ids exist by the time the policy's
     * {@code filters} array is rewritten, and the policy is written once with everything merged
     * rather than once per change.
     *
     * @param spaceName the space to restore.
     * @param listener notified once everything has been applied. A missing policy or an unreadable
     *     stored filter resolves successfully: the registry is durable, so the next sync retries.
     */
    public void apply(String spaceName, ActionListener<Void> listener) {
        this.read(
                spaceName,
                ActionListener.wrap(
                        overrides -> {
                            if (overrides.getPolicy() == null && overrides.getFilters().isEmpty()) {
                                listener.onResponse(null);
                                return;
                            }
                            this.restoreFilters(
                                    overrides,
                                    ActionListener.wrap(
                                            restoredIds ->
                                                    this.applyToPolicy(spaceName, overrides, restoredIds, listener),
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    /**
     * Recreates the user's filters, each under the id it originally had.
     *
     * <p>Reusing the id is what lets the policy's {@code filters} array keep pointing at the same
     * values, and what makes a second apply a no-op rather than a duplicate.
     *
     * @param overrides the stored overrides.
     * @param listener receives the ids that were restored, in registry order.
     */
    private void restoreFilters(UserOverrides overrides, ActionListener<List<String>> listener) {
        List<String> ids = new ArrayList<>();
        BulkRequest bulk = new BulkRequest().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        for (UserOverrides.StoredFilter stored : overrides.getFilters()) {
            try {
                MAPPER.readTree(stored.getDocument());
            } catch (Exception e) {
                // One corrupt entry must not cost the user the rest of their filters.
                log.warn(Constants.W_LOG_USER_OVERRIDES_FILTER_UNREADABLE, stored.getId(), e.getMessage());
                continue;
            }
            bulk.add(
                    new IndexRequest(Constants.INDEX_FILTERS)
                            .id(stored.getId())
                            .source(stored.getDocument(), XContentType.JSON));
            ids.add(stored.getId());
        }

        if (bulk.numberOfActions() == 0) {
            listener.onResponse(ids);
            return;
        }
        this.client.bulk(
                bulk, ActionListener.wrap(response -> listener.onResponse(ids), listener::onFailure));
    }

    /**
     * Merges the stored settings into the rebuilt policy and writes it back once.
     *
     * <p>Everything the rebuild wrote that is not a user-owned setting passes through untouched --
     * {@code space}, {@code offset} and the rest of {@code document}. Losing {@code space.name} in
     * particular would make the policy invisible to every space-scoped query in the plugin.
     */
    private void applyToPolicy(
            String spaceName,
            UserOverrides overrides,
            List<String> restoredFilterIds,
            ActionListener<Void> listener) {
        this.spaceService.getPolicy(
                spaceName,
                ActionListener.wrap(
                        policySource -> {
                            if (policySource == null) {
                                log.warn(Constants.W_LOG_USER_OVERRIDES_POLICY_MISSING, spaceName);
                                listener.onResponse(null);
                                return;
                            }

                            ObjectNode wrapper = MAPPER.valueToTree(policySource);
                            ObjectNode document = (ObjectNode) wrapper.get(Constants.KEY_DOCUMENT);
                            if (document == null) {
                                log.warn(Constants.W_LOG_USER_OVERRIDES_POLICY_MISSING, spaceName);
                                listener.onResponse(null);
                                return;
                            }

                            mergeSettings(document, overrides.getPolicy());
                            int attached = attachFilterIds(document, restoredFilterIds);
                            refreshHash(wrapper, document);

                            log.info(
                                    Constants.I_LOG_USER_OVERRIDES_APPLIED,
                                    spaceName,
                                    overrides.getPolicy() != null,
                                    attached);

                            this.writePolicy(spaceName, document, wrapper, listener);
                        },
                        listener::onFailure));
    }

    /** Writes the merged policy back under its real document id. */
    private void writePolicy(
            String spaceName, ObjectNode document, ObjectNode wrapper, ActionListener<Void> listener) {
        this.spaceService.findDocumentIdAsync(
                Constants.INDEX_POLICIES,
                spaceName,
                document.path(Constants.KEY_ID).asText(null),
                ActionListener.wrap(
                        realId -> {
                            if (realId == null) {
                                log.warn(Constants.W_LOG_USER_OVERRIDES_POLICY_MISSING, spaceName);
                                listener.onResponse(null);
                                return;
                            }
                            this.client.index(
                                    new IndexRequest(Constants.INDEX_POLICIES)
                                            .id(realId)
                                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                                            .source(wrapper.toString(), XContentType.JSON),
                                    ActionListener.wrap(indexed -> listener.onResponse(null), listener::onFailure));
                        },
                        listener::onFailure));
    }

    /**
     * Writes the settings the user owns over CTI's values.
     *
     * <p>A {@code null} setting means the user never decided that field, so CTI's value stays. That
     * is the same absence-is-meaningful rule the integrations' {@code user_enabled} follows.
     */
    private static void mergeSettings(ObjectNode document, UserOverrides.PolicySettings settings) {
        if (settings == null) {
            return;
        }
        if (settings.getEnabled() != null) {
            document.put(Constants.KEY_ENABLED, settings.getEnabled().booleanValue());
        }
        if (settings.getIndexUnclassifiedEvents() != null) {
            document.put(
                    Constants.KEY_INDEX_UNCLASSIFIED_EVENTS,
                    settings.getIndexUnclassifiedEvents().booleanValue());
        }
        if (settings.getIndexDiscardedEvents() != null) {
            document.put(
                    Constants.KEY_INDEX_DISCARDED_EVENTS, settings.getIndexDiscardedEvents().booleanValue());
        }
        if (settings.getEnrichments() != null) {
            List<String> ctiList = new ArrayList<>();
            document.path(Constants.KEY_ENRICHMENTS).forEach(entry -> ctiList.add(entry.asText()));

            ArrayNode merged = document.arrayNode();
            settings.getEnrichments().applyTo(ctiList).forEach(merged::add);
            document.set(Constants.KEY_ENRICHMENTS, merged);
        }
    }

    /**
     * Appends the restored filter ids to the policy's {@code filters} array, which the rebuild
     * empties.
     *
     * <p>Ids already present are skipped, which is what makes applying twice harmless.
     *
     * @return how many ids were appended.
     */
    private static int attachFilterIds(ObjectNode document, List<String> filterIds) {
        ArrayNode filters =
                document.has(Constants.KEY_FILTERS) && document.get(Constants.KEY_FILTERS).isArray()
                        ? (ArrayNode) document.get(Constants.KEY_FILTERS)
                        : document.putArray(Constants.KEY_FILTERS);

        Set<String> present = new LinkedHashSet<>();
        filters.forEach(entry -> present.add(entry.asText()));

        int attached = 0;
        for (String id : filterIds) {
            if (present.add(id)) {
                filters.add(id);
                attached++;
            }
        }
        return attached;
    }

    /**
     * Recomputes {@code hash.sha256} over the merged document.
     *
     * <p>The sync compares this hash to decide whether content changed, so leaving the rebuild's hash
     * in place would make it describe a document that no longer exists.
     */
    private static void refreshHash(ObjectNode wrapper, ObjectNode document) {
        ObjectNode hashNode =
                wrapper.has(Constants.KEY_HASH) && wrapper.get(Constants.KEY_HASH).isObject()
                        ? (ObjectNode) wrapper.get(Constants.KEY_HASH)
                        : wrapper.putObject(Constants.KEY_HASH);
        hashNode.put(Constants.KEY_SHA256, Resource.computeSha256(document.toString()));
    }

    /**
     * A mutator that stores a filter the user created, or refreshes the copy of one they edited.
     *
     * <p>The document is kept as a serialized string rather than a nested object: the policies
     * mapping is {@code dynamic: true}, so nesting a filter's fields there would auto-map every field
     * of every stored filter into the policies index.
     *
     * <p>Everything else in the space's overrides passes through untouched. That matters because the
     * policy settings and the filters share one registry document, so returning a fresh instance here
     * would erase the settings the user had saved.
     *
     * @param filterId the filter's document id, reused when the filter is recreated.
     * @param document the filter's full stored document, serialized.
     * @return a mutator suitable for {@link #update(String, UnaryOperator, ActionListener)}.
     */
    public static UnaryOperator<UserOverrides> storeFilter(String filterId, String document) {
        return current -> {
            List<UserOverrides.StoredFilter> filters = new ArrayList<>(current.getFilters());
            filters.removeIf(stored -> filterId.equals(stored.getId()));
            filters.add(new UserOverrides.StoredFilter(filterId, document));
            return new UserOverrides(current.getPolicy(), filters);
        };
    }

    /**
     * A mutator that drops a filter the user deleted, so the next rebuild does not recreate it.
     *
     * <p>Removing an id that was never stored is a no-op: the caller does not have to know whether
     * the filter had been recorded, which keeps the delete path free of an extra read.
     *
     * @param filterId the filter's document id.
     * @return a mutator suitable for {@link #update(String, UnaryOperator, ActionListener)}.
     */
    public static UnaryOperator<UserOverrides> removeFilter(String filterId) {
        return current -> {
            List<UserOverrides.StoredFilter> filters = new ArrayList<>(current.getFilters());
            filters.removeIf(stored -> filterId.equals(stored.getId()));
            return new UserOverrides(current.getPolicy(), filters);
        };
    }

    private static GetRequest registryGetRequest() {
        return new GetRequest(Constants.INDEX_POLICIES, Constants.USER_OVERRIDES_DOC_ID);
    }

    /**
     * Builds the write request for the registry, guarded against concurrent writers.
     *
     * <p>An existing document is written with the sequence number and primary term just read, so a
     * writer that raced us loses and retries. A document that does not exist yet has no sequence
     * number to compare, so {@code opType=CREATE} takes that role: of two callers creating the
     * registry at once, exactly one succeeds.
     */
    private static IndexRequest buildWriteRequest(GetResponse response) {
        IndexRequest request =
                new IndexRequest(Constants.INDEX_POLICIES)
                        .id(Constants.USER_OVERRIDES_DOC_ID)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        if (response.isExists()) {
            return request.setIfSeqNo(response.getSeqNo()).setIfPrimaryTerm(response.getPrimaryTerm());
        }
        return request.opType(DocWriteRequest.OpType.CREATE);
    }

    /**
     * @return the registry document's root, with the {@code user_overrides} object guaranteed
     *     present.
     */
    private static ObjectNode readRoot(GetResponse response) throws Exception {
        ObjectNode root =
                response.isExists()
                        ? (ObjectNode) MAPPER.readTree(response.getSourceAsString())
                        : MAPPER.createObjectNode();

        if (!root.has(Constants.KEY_USER_OVERRIDES)) {
            root.set(Constants.KEY_USER_OVERRIDES, MAPPER.createObjectNode());
        }
        return root;
    }

    private static UserOverrides parse(GetResponse response, String spaceName) throws Exception {
        if (!response.isExists()) {
            return UserOverrides.forSpace(null, spaceName);
        }
        ObjectNode root = (ObjectNode) MAPPER.readTree(response.getSourceAsString());
        return UserOverrides.forSpace(root.get(Constants.KEY_USER_OVERRIDES), spaceName);
    }
}
