/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Default callback class for SimpleHttpResponse that implements completed() and failed() response
 * methods.
 */
public class HttpResponseCallback implements FutureCallback<SimpleHttpResponse> {

    private static final Logger log = LogManager.getLogger(HttpResponseCallback.class);

    /** The Http get request. */
    final SimpleHttpRequest httpRequest;

    /** The error message. */
    final String errorMessage;

    /** The level {@link #failed} logs at. */
    private final Level failureLevel;

    /**
     * Default constructor. The failure is logged at {@code ERROR}: the caller has no retry, so a
     * failed exchange is a failed request.
     *
     * @param httpRequest the request
     * @param errorMessage the error message
     */
    public HttpResponseCallback(SimpleHttpRequest httpRequest, String errorMessage) {
        this(httpRequest, errorMessage, Level.ERROR);
    }

    /**
     * Constructor that chooses the level of the failure line.
     *
     * <p>{@code DEBUG} is for a caller that reports the outcome itself. This callback sees one
     * exchange and runs before anyone decides what that exchange means, so at {@code ERROR} it marks
     * attempts that are about to be re-issued and succeed. A caller that leaves the visible line to
     * its own retry warning, or to the exception it rethrows, passes {@code DEBUG} and keeps this one
     * as detail.
     *
     * @param httpRequest the request
     * @param errorMessage the error message
     * @param failureLevel the level to log a failed exchange at
     */
    public HttpResponseCallback(
            SimpleHttpRequest httpRequest, String errorMessage, Level failureLevel) {
        this.httpRequest = httpRequest;
        this.errorMessage = errorMessage;
        this.failureLevel = failureLevel;
    }

    @Override
    public void completed(SimpleHttpResponse response) {
        log.debug("{}->{}", this.httpRequest, new StatusLine(response));
        if (log.isDebugEnabled()) {
            log.debug("Got response: {} {}", response.getCode(), response.getBodyText());
        }
        log.debug(
                "CTI compression check: request Accept-Encoding=[{}] response Content-Encoding=[{}]"
                        + " wireContentLength=[{}] decodedBodyBytes=[{}]",
                this.httpRequest.getFirstHeader("Accept-Encoding"),
                response.getFirstHeader("Content-Encoding"),
                response.getFirstHeader("Content-Length"),
                response.getBodyBytes() != null ? response.getBodyBytes().length : -1);
    }

    @Override
    public void failed(Exception ex) {
        log.log(this.failureLevel, "{}->{}", this.httpRequest, ex);
    }

    @Override
    public void cancelled() {
        log.debug("{} cancelled", this.httpRequest);
    }
}
