/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.commandmanager.utils.httpclient;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Default callback class for SimpleHttpResponse that implements completed() and failed() response
 * methods.
 */
public class HttpResponseCallback implements FutureCallback<SimpleHttpResponse> {

    private static final Logger log = LogManager.getLogger(HttpResponseCallback.class);

    /** The Http get request. */
    SimpleHttpRequest httpRequest;

    /** The error message. */
    String errorMessage;

    /**
     * Deafult constructor
     *
     * @param httpRequest the request
     * @param errorMessage the error message
     */
    public HttpResponseCallback(SimpleHttpRequest httpRequest, String errorMessage) {
        this.httpRequest = httpRequest;
        this.errorMessage = errorMessage;
    }

    @Override
    public void completed(SimpleHttpResponse response) {
        log.debug("{}->{}", httpRequest, new StatusLine(response));
        log.debug("Got response: {} {}", response.getCode(), response.getBodyText());
    }

    @Override
    public void failed(Exception ex) {
        log.error("{}->{}", httpRequest, ex);
        // throw new HttpException(errorMessage, ex);
    }

    @Override
    public void cancelled() {
        log.debug("{} cancelled", httpRequest);
    }
}
