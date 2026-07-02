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
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.Objects;
import java.util.function.Consumer;

import com.wazuh.contentmanager.cti.catalog.model.Space;
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
     * @param onValid called when the draft policy exists
     * @param onError called with a RestResponse describing the error
     */
    public static void validateDraftPolicyExists(
            Client client, Runnable onValid, Consumer<RestResponse> onError) {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
        sourceBuilder.size(0);
        searchRequest.source(sourceBuilder);

        client.search(
                searchRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(SearchResponse response) {
                        if (Objects.requireNonNull(response.getHits().getTotalHits()).value() == 0) {
                            log.error(Constants.E_500_MISSING_DRAFT_POLICY);
                            onError.accept(
                                    new RestResponse(
                                            Constants.E_500_MISSING_DRAFT_POLICY,
                                            RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                        } else {
                            onValid.run();
                        }
                    }

                    @Override
                    public void onFailure(Exception e) {
                        OpenSearchSecurityException secEx = extractSecurityException(e);
                        if (secEx != null) {
                            onError.accept(
                                    new RestResponse(secEx.getMessage(), secEx.status().getStatus()));
                        } else {
                            onError.accept(
                                    new RestResponse(
                                            "Draft policy check failed: " + e.getMessage(),
                                            RestStatus.BAD_REQUEST.getStatus()));
                        }
                    }
                });
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
}
