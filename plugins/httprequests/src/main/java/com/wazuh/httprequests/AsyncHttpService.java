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
package com.wazuh.httprequests;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.HttpConnection;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.http.impl.Http1StreamListener;
import org.apache.hc.core5.http.impl.bootstrap.AsyncRequesterBootstrap;
import org.apache.hc.core5.http.impl.bootstrap.HttpAsyncRequester;
import org.apache.hc.core5.http.message.RequestLine;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.nio.entity.StringAsyncEntityConsumer;
import org.apache.hc.core5.http.nio.support.AsyncRequestBuilder;
import org.apache.hc.core5.http.nio.support.BasicResponseConsumer;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.util.Timeout;

/**
 * Example of asynchronous HTTP/1.1 request execution.
 */


public class AsyncHttpService {
    HttpAsyncRequester requester;

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
                    System.out.println(connection.getRemoteAddress() + " " + new RequestLine(request));
                }

                @Override
                public void onResponseHead(final HttpConnection connection, final HttpResponse response) {
                    System.out.println(connection.getRemoteAddress() + " " + new StatusLine(response));
                }

                @Override
                public void onExchangeComplete(final HttpConnection connection, final boolean keepAlive) {
                    if (keepAlive) {
                        System.out.println(connection.getRemoteAddress() + " exchange completed (connection kept alive)");
                    } else {
                        System.out.println(connection.getRemoteAddress() + " exchange completed (connection closed)");
                    }
                }

            })
            .create();
    }

    public CompletableFuture<String> performAsyncRequest() throws Exception {
        this.requester.start();
        final HttpHost target = HttpRequestsPlugin.TARGET;
        final String requestUri = HttpRequestsPlugin.REQUEST_URI;

        CompletableFuture<String> future = new CompletableFuture<>();

        // @Todo: Modify the plugin to handle multiple requests concurrently

        final CountDownLatch latch = new CountDownLatch(1);
        this.requester.execute(
            AsyncRequestBuilder.get()
                .setHttpHost(target)
                .setPath(requestUri)
                .build(),
            new BasicResponseConsumer<>(new StringAsyncEntityConsumer()),
            Timeout.ofSeconds(5),
            new FutureCallback<Message<HttpResponse, String>>() {

                @Override
                public void completed(final Message<HttpResponse, String> message) {
                    final HttpResponse response = message.getHead();
                    final String body = message.getBody();
                    System.out.println(requestUri + "->" + response.getCode());
                    System.out.println(body);
                    latch.countDown();
                    future.complete(body);
                }

                @Override
                public void failed(final Exception ex) {
                    System.out.println(requestUri + "->" + ex);
                    latch.countDown();
                }

                @Override
                public void cancelled() {
                    System.out.println(requestUri + " cancelled");
                    latch.countDown();
                }

            });

        latch.await();
        System.out.println("Shutting down I/O reactor");
        this.requester.initiateShutdown();
        return future;
    }

    public void close() {
        System.out.println("HTTP requester shutting down");
        this.requester.close(CloseMode.GRACEFUL);
    }
}