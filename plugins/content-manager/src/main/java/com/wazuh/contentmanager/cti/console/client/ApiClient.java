package com.wazuh.contentmanager.cti.console.client;

import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.catalog.utils.HttpResponseCallback;
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * CTI Console API client.
 */
public class ApiClient {

    private static final String BASE_URI = "https://localhost:8443";
    private static final String API_PREFIX = "/api/v1";
    private static final String TOKEN_URI = BASE_URI + API_PREFIX + "/instances/token";
    private static final String PRODUCTS_URI = BASE_URI + API_PREFIX + "/instances/me";
    private static final String RESOURCE_URI = BASE_URI + API_PREFIX + "/instances/token/exchange";

    private CloseableHttpAsyncClient client;

    private final int TIMEOUT = 5;

    /**
     * Constructs an CtiApiClient instance.
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

    /**
     * Perform an HTTP POST request to the CTI Console to obtain a permanent token for this XDR/SIEM Wazuh instance
     * @param clientId unique client identifier for the instance.
     * @param deviceCode unique device code provided by the CTI Console during the registration of the instance.
     * @return HTTP response.
     * @throws ExecutionException request failed.
     * @throws InterruptedException request failed / interrupted.
     * @throws TimeoutException request timed out.
     */
    public SimpleHttpResponse getToken(String clientId, String deviceCode) throws ExecutionException, InterruptedException, TimeoutException {
        String grantType = "grant_type=urn:ietf:params:oauth:grant-type:device_code";
        String formBody = String.format(Locale.ROOT, "%s&client_id=%s&device_code=%s", grantType, clientId, deviceCode);

        SimpleHttpRequest request = SimpleRequestBuilder
            .post(TOKEN_URI)
            .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
            .setBody(formBody, ContentType.APPLICATION_FORM_URLENCODED)
            .build();

        final Future<SimpleHttpResponse> future = client.execute(
            SimpleRequestProducer.create(request),
            SimpleResponseConsumer.create(),
            new HttpResponseCallback(
                request, "Outgoing request failed"
            ));
        return future.get(TIMEOUT, TimeUnit.SECONDS);
    }

    /***
     * Perform an HTTP POST request to the CTI Console to obtain a temporary HMAC-signed URL token for the given resource.
     * @param permanentToken permanent token for the instance.
     * @param resource resource to request the access token to.
     * @return HTTP response.
     * @throws ExecutionException request failed.
     * @throws InterruptedException request failed / interrupted.
     * @throws TimeoutException request timed out.
     */
    public SimpleHttpResponse getResourceToken(Token permanentToken, String resource) throws ExecutionException, InterruptedException, TimeoutException {
        String formBody = String.join("&", List.of(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type=urn:wazuh:params:oauth:token-type:signed_url",
            "resource=" + resource
        ));
        String token = String.format(Locale.ROOT, "%s %s", permanentToken.getTokenType(), permanentToken.getAccessToken());

        SimpleHttpRequest request = SimpleRequestBuilder
            .post(RESOURCE_URI)
            .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
            .addHeader(HttpHeaders.AUTHORIZATION, token)
            .setBody(formBody, ContentType.APPLICATION_FORM_URLENCODED)
            .build();

        final Future<SimpleHttpResponse> future = client.execute(
            SimpleRequestProducer.create(request),
            SimpleResponseConsumer.create(),
            new HttpResponseCallback(
                request, "Outgoing request failed"
            ));
        return future.get(TIMEOUT, TimeUnit.SECONDS);
    }

    /**
     * Perform an HTTP GET request to the CTI Console to obtain the list of plans the instance is subscribed to.
     * @param permanentToken permanent token for the instance.
     * @return HTTP response.
     * @throws ExecutionException request failed.
     * @throws InterruptedException request failed / interrupted.
     * @throws TimeoutException request timed out.
     */
    public SimpleHttpResponse getPlans(Token permanentToken) throws ExecutionException, InterruptedException, TimeoutException {
        String token = String.format(Locale.ROOT, "%s %s", permanentToken.getTokenType(), permanentToken.getAccessToken());

        SimpleHttpRequest request = SimpleRequestBuilder
            .get(PRODUCTS_URI)
            .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
            .addHeader(HttpHeaders.AUTHORIZATION, token)
            .addHeader("wazuh-tag", "v5.0.0") // TODO make dynamic
            .build();

        final Future<SimpleHttpResponse> future = client.execute(
            SimpleRequestProducer.create(request),
            SimpleResponseConsumer.create(),
            new HttpResponseCallback(
                request, "Outgoing request failed"
            ));
        return future.get(TIMEOUT, TimeUnit.SECONDS);
    }
}
