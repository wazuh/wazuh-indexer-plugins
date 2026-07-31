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
package com.wazuh.contentmanager.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.Objects;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Shared helper methods for transport actions. */
public final class TransportActionHelper {

    private static final Logger log = LogManager.getLogger(TransportActionHelper.class);

    private TransportActionHelper() {}

    /**
     * Checks if the draft policy exists.
     *
     * @param client the OpenSearch client
     * @param listener receives null if the draft policy exists, or a RestResponse with the error
     */
    public static void validateDraftPolicyExists(
            Client client, ActionListener<RestResponse> listener) {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
        sourceBuilder.size(0);
        searchRequest.source(sourceBuilder);

        client.search(
                searchRequest,
                ActionListener.wrap(
                        response -> {
                            if (Objects.requireNonNull(response.getHits().getTotalHits()).value() == 0) {
                                log.error(Constants.E_500_MISSING_DRAFT_POLICY);
                                listener.onResponse(
                                        new RestResponse(
                                                Constants.E_500_MISSING_DRAFT_POLICY,
                                                RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        ex -> {
                            OpenSearchSecurityException secEx = extractSecurityException(ex);
                            if (secEx != null) {
                                listener.onResponse(
                                        new RestResponse(secEx.getMessage(), secEx.status().getStatus()));
                            } else {
                                listener.onResponse(
                                        new RestResponse(
                                                "Draft policy check failed: " + ex.getMessage(),
                                                RestStatus.BAD_REQUEST.getStatus()));
                            }
                        }));
    }

    /**
     * Reloads the standard space into the Engine when a mutation changed that space's hash.
     *
     * <p>The Engine holds its own copy of the standard policy and resolves asset selection from it,
     * for both the production router and the log test endpoint. Content mutations only write to the
     * OpenSearch indices, so without this reload the Engine keeps serving the snapshot it received at
     * the last full load and changes such as toggling an integration's {@code enabled} flag never
     * reach log test.
     *
     * <p>Fire-and-forget: the reload runs asynchronously and failures are only logged. The mutation
     * that triggered it has already been persisted, so it must not be reported as failed.
     *
     * @param engine the Engine service; a {@code null} value is logged and skipped.
     * @param spaceService used to build the Engine payload for the standard space.
     * @param changedSpaces the spaces whose hash changed, as reported by {@link
     *     SpaceService#calculateAndUpdate}. The reload is skipped unless it contains the standard
     *     space.
     */
    public static void reloadStandardSpaceIntoEngine(
            EngineService engine, SpaceService spaceService, Set<String> changedSpaces) {
        if (changedSpaces == null || !changedSpaces.contains(Space.STANDARD.toString())) {
            return;
        }
        if (engine == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            return;
        }

        spaceService.buildEnginePayload(
                Space.STANDARD.toString(),
                ActionListener.wrap(
                        payload ->
                                engine.promoteAsync(
                                        payload,
                                        ActionListener.wrap(
                                                response -> {
                                                    if (response.getStatus() == RestStatus.OK.getStatus()) {
                                                        log.info(Constants.I_LOG_ENGINE_STANDARD_LOADED);
                                                    } else {
                                                        log.warn(
                                                                Constants.W_LOG_ENGINE_STANDARD_LOAD_STATUS,
                                                                response.getStatus(),
                                                                response.getMessage());
                                                    }
                                                },
                                                e ->
                                                        log.error(
                                                                Constants.E_LOG_ENGINE_STANDARD_LOAD_FAILED, e.getMessage()))),
                        e -> log.error(Constants.E_LOG_ENGINE_STANDARD_LOAD_FAILED, e.getMessage())));
    }

    /** Walks the exception cause chain looking for an OpenSearchSecurityException. */
    public static OpenSearchSecurityException extractSecurityException(Throwable throwable) {
        Throwable cause = throwable;
        while (cause != null) {
            if (cause instanceof OpenSearchSecurityException) {
                return (OpenSearchSecurityException) cause;
            }
            cause = cause.getCause();
        }
        return null;
    }

    /**
     * Walks the exception cause chain looking for an OpenSearchException, e.g. a {@code
     * MapperParsingException} raised when a caller-supplied value (such as a malformed date) fails
     * index mapping validation. OpenSearchException subclasses carry their own correct {@link
     * org.opensearch.core.rest.RestStatus} (400 for mapping/parsing failures), so callers should
     * prefer it over a hardcoded Internal Server Error.
     */
    public static OpenSearchException extractOpenSearchException(Throwable throwable) {
        Throwable cause = throwable;
        while (cause != null) {
            if (cause instanceof OpenSearchException) {
                return (OpenSearchException) cause;
            }
            cause = cause.getCause();
        }
        return null;
    }
}
