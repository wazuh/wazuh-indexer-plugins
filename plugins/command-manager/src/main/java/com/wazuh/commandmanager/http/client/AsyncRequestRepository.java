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
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class AsyncRequestRepository {

    private static final Logger logger = LogManager.getLogger(AsyncRequestRepository.class);
    private final HttpHost target;
    private final String requestUri;
    private final CloseableHttpAsyncClient client;

    public AsyncRequestRepository(ConfigReader configReader) throws Exception {
        this.target = new HttpHost(configReader.getHostName(), configReader.getPort());
        this.requestUri = configReader.getPath();
        this.client = prepareAsyncRequest();
    }

    public CloseableHttpAsyncClient prepareAsyncRequest() throws IOException {
        logger.info("Preparing Async Request");
        IOReactorConfig ioReactorConfig = IOReactorConfig.custom()
            .setSoTimeout(5, TimeUnit.SECONDS)
            .build();

        try (CloseableHttpAsyncClient client = HttpAsyncClients.custom()
            .setIOReactorConfig(ioReactorConfig)
            .build()) {
            client.start();
            return client;
        }
    }

    public CompletableFuture<SimpleBody> performAsyncRequest() throws Exception {

        final SimpleHttpRequest request = SimpleRequestBuilder.post()
            .setHttpHost(target)
            .setPath(requestUri)
            .setBody("{\"field\":\"value\"}", ContentType.APPLICATION_JSON)
            .build();

        logger.info("Executing {} request", request);

        CompletableFuture<SimpleBody> completableFuture = new CompletableFuture<>();

        Future<SimpleHttpResponse> future = this.client.execute(
            SimpleRequestProducer.create(request),
            SimpleResponseConsumer.create(),
            new FutureCallback<>() {
                @Override
                public void completed(final SimpleHttpResponse response) {
                    logger.info("{}->{}", request, new StatusLine(response));
                    completableFuture.complete(response.getBody());
                }

                @Override
                public void failed(final Exception ex) {
                    logger.error("Could not process {} request: {}", request, ex.getMessage());
                }

                @Override
                public void cancelled() {
                    logger.error("{} cancelled", request);
                }
            }
        );
        future.get();
        return completableFuture;

    }

    public void close() {
        logger.info("HTTP requester shutting down");
        this.client.close(CloseMode.GRACEFUL);
    }
}