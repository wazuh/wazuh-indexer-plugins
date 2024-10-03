/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
package com.wazuh.commandmanager.http.client;

import com.wazuh.commandmanager.config.reader.ConfigReader;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.impl.Http1StreamListener;
import org.apache.hc.core5.http.impl.bootstrap.AsyncRequesterBootstrap;
import org.apache.hc.core5.http.impl.bootstrap.HttpAsyncRequester;
import org.apache.hc.core5.http.message.RequestLine;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.nio.entity.StringAsyncEntityConsumer;
import org.apache.hc.core5.http.nio.support.AsyncRequestBuilder;
import org.apache.hc.core5.http.nio.support.BasicResponseConsumer;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class AsyncRequestRepository {

    private static final Logger logger = LogManager.getLogger(AsyncRequestRepository.class);
    private final HttpHost target;
    private final String requestUri;
    HttpAsyncRequester requester;

    public AsyncRequestRepository(ConfigReader configReader) throws Exception {
        this.target = new HttpHost(configReader.getHostName(), configReader.getPort());
        this.requestUri = configReader.getPath();
        prepareAsyncRequest();
    }

    public void prepareAsyncRequest() {
        IOReactorConfig ioReactorConfig = IOReactorConfig.custom()
            .setSoTimeout(5, TimeUnit.SECONDS)
            .build();

        // Create and start requester
        this.requester = AsyncRequesterBootstrap.bootstrap()
            .setIOReactorConfig(ioReactorConfig)
            .setStreamListener(new Http1StreamListener() {

                @Override
                public void onRequestHead(final HttpConnection connection, final HttpRequest request) {
                    logger.info("{} {}", connection.getRemoteAddress(), new RequestLine(request));
                }

                @Override
                public void onResponseHead(final HttpConnection connection, final HttpResponse response) {
                    logger.info("{} {}", connection.getRemoteAddress(), new StatusLine(response));
                }

                @Override
                public void onExchangeComplete(final HttpConnection connection, final boolean keepAlive) {
                    if (keepAlive) {
                        logger.info("{} exchange completed (connection kept alive)", connection.getRemoteAddress());
                    } else {
                        logger.info("{} exchange completed (connection closed)", connection.getRemoteAddress());
                    }
                }

            })
            .create();
    }

    public CompletableFuture<String> performAsyncRequest() throws Exception {
        this.requester.start();
        CompletableFuture<String> future = new CompletableFuture<>();

        this.requester.execute(
            AsyncRequestBuilder.post()
                .setHttpHost(this.target)
                .setPath(this.requestUri)
                .setEntity("{\"field\":\"value\"}",ContentType.APPLICATION_JSON)
                .build(),
            new BasicResponseConsumer<>(new StringAsyncEntityConsumer()),
            Timeout.ofSeconds(5),
            new FutureCallback<Message<HttpResponse, String>>() {

                @Override
                public void completed(final Message<HttpResponse, String> message) {
                    final HttpResponse response = message.getHead();
                    final String body = message.getBody();
                    logger.info(requestUri + "->{}", response.getCode());
                    logger.info(body);
                    future.complete(body);
                }

                @Override
                public void failed(final Exception ex) {
                    logger.info("{}->{}", requestUri, String.valueOf(ex));
                }

                @Override
                public void cancelled() {
                    logger.info("{} cancelled", requestUri);
                }

            });

        logger.info("Shutting down I/O reactor");
        this.requester.initiateShutdown();
        return future;
    }

    public void close() {
        logger.info("HTTP requester shutting down");
        this.requester.close(CloseMode.GRACEFUL);
    }
}