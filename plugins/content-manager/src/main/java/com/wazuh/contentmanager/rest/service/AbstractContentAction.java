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
package com.wazuh.contentmanager.rest.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Base abstract class for Content Manager REST actions.
 *
 * <p>This class provides the foundational structure for handling CTI content requests.
 * Business logic has been moved to transport actions; REST handlers now delegate
 * to the transport layer via {@code client.execute()}.
 */
public abstract class AbstractContentAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(AbstractContentAction.class);

    /**
     * Constructor for AbstractContentAction.
     *
     */
    public AbstractContentAction() {
    }

    /**
     * Checks whether the incoming request uses {@code application/yaml} content type.
     *
     * @param request The REST request.
     * @return {@code true} if the request content type is YAML.
     */
    protected boolean isYamlRequest(RestRequest request) {
        try {
            return XContentType.YAML.equals(request.getMediaType());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Indicates if this resource type supports YAML field storage.
     *
     * @return false by default. Override to return true for Decoders, KVDBs, and Filters.
     */
    protected boolean supportsYamlField() {
        return false;
    }

    /**
     * Walks the exception cause chain looking for an {@link OpenSearchSecurityException}. Returns it
     * if found, or {@code null} otherwise.
     */
    protected static OpenSearchSecurityException extractSecurityException(Throwable throwable) {
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
     * Returns the content type string ("json" or "yaml") from the request.
     *
     * @param request the REST request
     * @return "yaml" if YAML content type, "json" otherwise
     */
    protected String getContentTypeString(RestRequest request) {
        return isYamlRequest(request) ? "yaml" : "json";
    }
}
