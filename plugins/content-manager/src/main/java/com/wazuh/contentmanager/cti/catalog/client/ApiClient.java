package com.wazuh.contentmanager.cti.catalog.client;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.client.HttpResponseCallback;
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class ApiClient {
    private static final String BASE_URI = "https://cti-pre.wazuh.com";
    private static final String API_PREFIX = "/api/v1";

    private CloseableHttpAsyncClient client;

    private final int TIMEOUT = 5;

    /**
     * Constructs an ApiClient instance.
     */
    public ApiClient() {
        this.buildClient();
    }

    /**
     * Builds and starts the Http client.
     */
    private void buildClient() {
        IOReactorConfig ioReactorConfig = IOReactorConfig.custom()
            .setSoTimeout(Timeout.ofSeconds(TIMEOUT))
            .build();

        SSLContext sslContext;
        try {
            sslContext =
                SSLContextBuilder.create()
                    .loadTrustMaterial(null, (chains, authType) -> true)
                    .build();
        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            throw new RuntimeException("Failed to initialize HttpClient", e);
        }

        this.client = HttpAsyncClients.custom()
            .setIOReactorConfig(ioReactorConfig)
            .setConnectionManager(
                PoolingAsyncClientConnectionManagerBuilder.create()
                    .setTlsStrategy(
                        ClientTlsStrategyBuilder.create().setSslContext(sslContext).build())
                    .build())
            .build();

        this.client.start();
    }

    /**
     * Closes the underlying HTTP asynchronous client. Used in tests
     */
    public void close() {
        this.client.close(CloseMode.GRACEFUL);
    }

    private String buildConsumerURI(String context, String consumer) {
        return BASE_URI + API_PREFIX + "/catalog/contexts/" + context + "/consumers/" + consumer;
    }

    public SimpleHttpResponse getConsumer(String context, String consumer) throws ExecutionException, InterruptedException, TimeoutException {
        SimpleHttpRequest request = SimpleRequestBuilder
            .get(this.buildConsumerURI(context, consumer))
            .build();

        final Future<SimpleHttpResponse> future = client.execute(
            SimpleRequestProducer.create(request),
            SimpleResponseConsumer.create(),
            new HttpResponseCallback(
                request, "Outgoing request failed"
            )
        );

        return future.get(TIMEOUT, TimeUnit.SECONDS);
    }
}
