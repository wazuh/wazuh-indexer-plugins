/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
 */
package com.wazuh.commandmanager.utils.httpclient;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpResponseCallback implements FutureCallback<SimpleHttpResponse> {

    private static final Logger log = LogManager.getLogger(HttpResponseCallback.class);

    /** The Http get request. */
    SimpleHttpRequest httpRequest;

    /** The Error message. */
    String errorMessage;

    public HttpResponseCallback(SimpleHttpRequest httpRequest, String errorMessage) {
        this.httpRequest = httpRequest;
        this.errorMessage = errorMessage;
    }

    @Override
    public void completed(SimpleHttpResponse response) {
        log.debug("{}->{}", httpRequest, new StatusLine(response));
        log.debug("Got response: {}", response.getBody());
    }

    @Override
    public void failed(Exception ex) {
        log.error("{}->{}", httpRequest, ex);
        // throw new HttpException(errorMessage, ex);
    }

    @Override
    public void cancelled() {
        log.debug(httpRequest + " cancelled");
    }
}
