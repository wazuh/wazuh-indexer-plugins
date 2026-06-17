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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.Objects;

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
     * @return RestResponse with error if missing, null if ok
     */
    public static RestResponse validateDraftPolicyExists(Client client) {
        try {
            SearchRequest searchRequest = new SearchRequest(Constants.INDEX_POLICIES);
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
            sourceBuilder.query(
                    QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
            sourceBuilder.size(0);
            searchRequest.source(sourceBuilder);

            SearchResponse response = client.search(searchRequest).actionGet();

            if (Objects.requireNonNull(response.getHits().getTotalHits()).value() == 0) {
                log.error(Constants.E_500_MISSING_DRAFT_POLICY);
                return new RestResponse(
                        Constants.E_500_MISSING_DRAFT_POLICY,
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }
        } catch (Exception ex) {
            OpenSearchSecurityException secEx = extractSecurityException(ex);
            if (secEx != null) {
                return new RestResponse(secEx.getMessage(), secEx.status().getStatus());
            }
            return new RestResponse(
                    "Draft policy check failed: " + ex.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    /**
     * Walks the exception cause chain looking for an OpenSearchSecurityException.
     */
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
