package com.wazuh.contentmanager.cti.client;

import com.wazuh.contentmanager.utils.http.HttpResponseCallback;
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class CtiApiClient {

    private static final String BASE_URI = "https://localhost:8443";
    private static final String API_PREFIX = "/api/v1";
    private static final String TOKEN_URI = BASE_URI + API_PREFIX + "/instances/token";
    private static final String PRODUCTS_URI = BASE_URI + API_PREFIX + "/instances/me";
    private static final String RESOURCE_URI = BASE_URI + API_PREFIX + "/instances/token/exchange";

    private CloseableHttpAsyncClient client;

    /**
     * Constructs an CtiApiClient instance.
     */
    public CtiApiClient() {
//        super(URI.create(API_URI));

        this.buildClient();
    }

    private void buildClient() {
        IOReactorConfig ioReactorConfig = IOReactorConfig.custom()
            .setSoTimeout(Timeout.ofSeconds(5))
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

    public SimpleHttpResponse getToken(String clientId, String deviceCode) throws ExecutionException, InterruptedException, TimeoutException {
        String grantType = "grant_type=urn:ietf:params:oauth:grant-type:device_code";
        String formBody = String.format("%s&client_id=%s&device_code=%s", grantType, clientId, deviceCode);

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
        return future.get(5, TimeUnit.SECONDS);
    }

    public SimpleHttpResponse getResourceToken(String permanentToken, String resource) throws ExecutionException, InterruptedException, TimeoutException {
        String formBody = String.join("&", List.of(
            "grant_type=urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type=urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type=urn:wazuh:params:oauth:token-type:signed_url",
            "resource=" + resource
        ));
        String token = String.format("Bearer %s", permanentToken);

        SimpleHttpRequest request = SimpleRequestBuilder
            .post(RESOURCE_URI)
            .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
            .setHeader(HttpHeaders.AUTHORIZATION, token)
            .setBody(formBody, ContentType.APPLICATION_FORM_URLENCODED)
            .build();

        final Future<SimpleHttpResponse> future = client.execute(
            SimpleRequestProducer.create(request),
            SimpleResponseConsumer.create(),
            new HttpResponseCallback(
                request, "Outgoing request failed"
            ));
        return future.get(5, TimeUnit.SECONDS);
    }
}
