package com.wazuh.contentmanager.cti.catalog.client;

import com.wazuh.contentmanager.client.HttpResponseCallback;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Client for interacting with the Wazuh CTI Catalog API.
 * <p>
 * This client manages an asynchronous HTTP client to perform requests against
 * the catalog service, specifically handling consumer context retrieval.
 */
public class ApiClient {

    private final String baseUri;
    private CloseableHttpAsyncClient client;

    /**
     * Constructs an ApiClient instance and initializes the underlying HTTP client.
     */
    public ApiClient() {
        // Retrieve base URI from PluginSettings
        this.baseUri = PluginSettings.getInstance().getCtiBaseUrl();
        this.buildClient();
    }

    /**
     * Builds and starts the asynchronous HTTP client.
     *
     * @throws RuntimeException if the SSL context cannot be initialized.
     */
    private void buildClient() {
        IOReactorConfig ioReactorConfig = IOReactorConfig.custom()
            .setSoTimeout(Timeout.ofSeconds(PluginSettings.getInstance().getClientTimeout()))
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
     * Closes the underlying HTTP asynchronous client gracefully.
     */
    public void close() {
        this.client.close(CloseMode.GRACEFUL);
    }

    /**
     * Constructs the full URI for a specific consumer within a given context.
     *
     * @param context  The context identifier (e.g., the specific catalog section).
     * @param consumer The consumer identifier.
     * @return A string representing the full absolute URL for the resource.
     */
    private String buildConsumerURI(String context, String consumer) {
        return this.baseUri + "/catalog/contexts/" + context + "/consumers/" + consumer;
    }

    /**
     * Retrieves consumer details from the CTI Catalog.
     *
     * @param context  The context associated with the consumer.
     * @param consumer The name or ID of the consumer to retrieve.
     * @return A {@link SimpleHttpResponse} containing the API response.
     * @throws ExecutionException   If the computation threw an exception.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException     If the wait timed out.
     */
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

        return future.get(PluginSettings.getInstance().getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Retrieves the changes for a specific consumer within a given context.
     *
     * @param context    The context identifier.
     * @param consumer   The consumer identifier.
     * @param fromOffset The starting offset (exclusive).
     * @param toOffset   The ending offset (inclusive).
     * @return A {@link SimpleHttpResponse} containing the API response.
     * @throws ExecutionException   If the computation threw an exception.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException     If the wait timed out.
     */
    public SimpleHttpResponse getChanges(String context, String consumer, long fromOffset, long toOffset) throws ExecutionException, InterruptedException, TimeoutException {
        String uri = this.buildConsumerURI(context, consumer) + "/changes?from_offset=" + fromOffset + "&to_offset=" + toOffset;

        SimpleHttpRequest request = SimpleRequestBuilder
            .get(uri)
            .build();

        final Future<SimpleHttpResponse> future = client.execute(
            SimpleRequestProducer.create(request),
            SimpleResponseConsumer.create(),
            new HttpResponseCallback(
                request, "Failed to send request to CTI service"
            )
        );

        return future.get(PluginSettings.getInstance().getClientTimeout(), TimeUnit.SECONDS);
    }
}
