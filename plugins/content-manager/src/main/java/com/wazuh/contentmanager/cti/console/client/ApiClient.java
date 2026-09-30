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
package com.wazuh.contentmanager.cti.console.client;

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;
import org.opensearch.core.action.ActionListener;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.utils.HttpResponseCallback;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/** CTI Console API client. */
public class ApiClient {

    // Endpoint paths, appended to the CTI base URL. Package-private for testing.
    static final String TOKEN_PATH = "/instances/token";
    static final String PRODUCTS_PATH = "/instances/me";
    static final String RESOURCE_PATH = "/platform/environments/token/exchange";
    static final String ENVIRONMENTS_ME_PATH = "/platform/environments/me";
    static final String CATALOG_PLANS_PATH = "/catalog/plans";

    protected CloseableHttpAsyncClient client;

    private final int TIMEOUT = 5;

    /** Constructs an CtiApiClient instance. */
    public ApiClient() {
        this.buildClient();
    }

    /** Builds and starts the Http client. */
    private void buildClient() {
        IOReactorConfig ioReactorConfig =
                IOReactorConfig.custom().setSoTimeout(Timeout.ofSeconds(this.TIMEOUT)).build();

        List<Header> defaultHeaders =
                List.of(
                        new BasicHeader(HttpHeaders.USER_AGENT, PluginSettings.getInstance().getUserAgent()));

        this.client =
                HttpAsyncClients.custom()
                        .setIOReactorConfig(ioReactorConfig)
                        .setDefaultHeaders(defaultHeaders)
                        .setConnectionManager(
                                PoolingAsyncClientConnectionManagerBuilder.create()
                                        .setTlsStrategy(
                                                ClientTlsStrategyBuilder.create()
                                                        // JDK truststore + DefaultHostnameVerifier. Honours
                                                        // javax.net.ssl.trustStore* so an operator behind a
                                                        // TLS-terminating proxy adds a CA instead of disabling
                                                        // checks.
                                                        .setSslContext(SSLContexts.createSystemDefault())
                                                        .setTlsVersions(TLS.V_1_2, TLS.V_1_3)
                                                        .build())
                                        .build())
                        .build();

        this.client.start();
    }

    /** Closes the underlying HTTP asynchronous client. Used in tests */
    public void close() {
        this.client.close(CloseMode.GRACEFUL);
    }

    /**
     * Builds the absolute URI of a CTI endpoint from the configured base URL ({@code
     * plugins.content_manager.cti.api}). The Console endpoints served here live under the same base
     * URL as the catalog ones, so pointing the plugin at a different CTI environment moves both.
     *
     * <p>Resolved per call, as {@link #getCatalogPlans()} already did, so the client does not capture
     * the settings singleton at construction time.
     *
     * <p>Package-private for testing.
     *
     * @param path endpoint path, relative to the CTI base URL.
     * @return the absolute request URI.
     */
    static String ctiUri(String path) {
        return PluginSettings.getInstance().getCtiBaseUrl() + path;
    }

    /**
     * Perform an HTTP POST request to the CTI Console to obtain a permanent token for this XDR/SIEM
     * Wazuh instance
     *
     * @param clientId unique client identifier for the instance.
     * @param deviceCode unique device code provided by the CTI Console during the registration of the
     *     instance.
     * @return HTTP response.
     * @throws ExecutionException request failed.
     * @throws InterruptedException request failed / interrupted.
     * @throws TimeoutException request timed out.
     */
    public SimpleHttpResponse getToken(String clientId, String deviceCode)
            throws ExecutionException, InterruptedException, TimeoutException {
        String grantType = "grant_type=urn:ietf:params:oauth:grant-type:device_code";
        String formBody =
                String.format(
                        Locale.ROOT, "%s&client_id=%s&device_code=%s", grantType, clientId, deviceCode);

        SimpleHttpRequest request =
                SimpleRequestBuilder.post(ctiUri(TOKEN_PATH))
                        .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
                        .addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP)
                        .setBody(formBody, ContentType.APPLICATION_FORM_URLENCODED)
                        .build();

        final Future<SimpleHttpResponse> future =
                this.client.execute(
                        SimpleRequestProducer.create(request),
                        SimpleResponseConsumer.create(),
                        new HttpResponseCallback(request, "Outgoing request failed"));
        return future.get(this.TIMEOUT, TimeUnit.SECONDS);
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
    public SimpleHttpResponse getResourceToken(Token permanentToken, String resource)
            throws ExecutionException, InterruptedException, TimeoutException {
        String formBody =
                String.join(
                        "&",
                        List.of(
                                "grant_type=" + this.encode("urn:ietf:params:oauth:grant-type:token-exchange"),
                                "subject_token=" + this.encode(permanentToken.getAccessToken()),
                                "subject_token_type="
                                        + this.encode("urn:ietf:params:oauth:token-type:access_token"),
                                "requested_token_type="
                                        + this.encode("urn:wazuh:params:oauth:token-type:signed_url"),
                                "resource=" + this.encode(resource)));
        String token =
                String.format(
                        Locale.ROOT, "%s %s", permanentToken.getTokenType(), permanentToken.getAccessToken());

        SimpleHttpRequest request =
                SimpleRequestBuilder.post(ctiUri(RESOURCE_PATH))
                        .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
                        .addHeader(HttpHeaders.AUTHORIZATION, token)
                        .addHeader("wazuh-uid", PluginSettings.getInstance().getClusterUUID())
                        .addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP)
                        .setBody(formBody, ContentType.APPLICATION_FORM_URLENCODED)
                        .build();

        final Future<SimpleHttpResponse> future =
                this.client.execute(
                        SimpleRequestProducer.create(request),
                        SimpleResponseConsumer.create(),
                        new HttpResponseCallback(request, "Outgoing request failed"));
        return future.get(this.TIMEOUT, TimeUnit.SECONDS);
    }

    /** URL-encodes a value for inclusion in an {@code application/x-www-form-urlencoded} body. */
    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Perform an HTTP GET request to the CTI Console to obtain the list of plans the instance is
     * subscribed to.
     *
     * @param permanentToken permanent token for the instance.
     * @return HTTP response.
     * @throws ExecutionException request failed.
     * @throws InterruptedException request failed / interrupted.
     * @throws TimeoutException request timed out.
     */
    public SimpleHttpResponse getPlans(Token permanentToken)
            throws ExecutionException, InterruptedException, TimeoutException {
        String token =
                String.format(
                        Locale.ROOT, "%s %s", permanentToken.getTokenType(), permanentToken.getAccessToken());

        SimpleHttpRequest request =
                SimpleRequestBuilder.get(ctiUri(PRODUCTS_PATH))
                        .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                        .addHeader(HttpHeaders.AUTHORIZATION, token)
                        .addHeader("wazuh-uid", PluginSettings.getInstance().getClusterUUID())
                        .addHeader("wazuh-tag", "v" + PluginSettings.getInstance().getVersion())
                        .addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP)
                        .build();

        final Future<SimpleHttpResponse> future =
                this.client.execute(
                        SimpleRequestProducer.create(request),
                        SimpleResponseConsumer.create(),
                        new HttpResponseCallback(request, "Outgoing request failed"));
        return future.get(this.TIMEOUT, TimeUnit.SECONDS);
    }

    /**
     * Perform an HTTP GET request to the CTI Console to obtain the exact plan associated with the
     * registered environment.
     *
     * @param permanentToken permanent token for the instance.
     * @return HTTP response.
     * @throws ExecutionException request failed.
     * @throws InterruptedException request failed / interrupted.
     * @throws TimeoutException request timed out.
     */
    public SimpleHttpResponse getEnvironmentMe(Token permanentToken)
            throws ExecutionException, InterruptedException, TimeoutException {
        String token =
                String.format(
                        Locale.ROOT, "%s %s", permanentToken.getTokenType(), permanentToken.getAccessToken());

        SimpleHttpRequest request =
                SimpleRequestBuilder.get(ctiUri(ENVIRONMENTS_ME_PATH))
                        .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                        .addHeader(HttpHeaders.AUTHORIZATION, token)
                        .addHeader("wazuh-uid", PluginSettings.getInstance().getClusterUUID())
                        .addHeader("wazuh-tag", "v" + PluginSettings.getInstance().getVersion())
                        .addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP)
                        .build();

        final Future<SimpleHttpResponse> future =
                this.client.execute(
                        SimpleRequestProducer.create(request),
                        SimpleResponseConsumer.create(),
                        new HttpResponseCallback(request, "Outgoing request failed"));
        return future.get(this.TIMEOUT, TimeUnit.SECONDS);
    }

    /**
     * Async variant of {@link #getEnvironmentMe(Token)}. Notifies the listener with the HTTP response
     * instead of blocking.
     *
     * @param permanentToken permanent token for the instance.
     * @param listener listener notified with the HTTP response on success, or on failure.
     */
    public void getEnvironmentMe(Token permanentToken, ActionListener<SimpleHttpResponse> listener) {
        String token =
                String.format(
                        Locale.ROOT, "%s %s", permanentToken.getTokenType(), permanentToken.getAccessToken());

        SimpleHttpRequest request =
                SimpleRequestBuilder.get(ctiUri(ENVIRONMENTS_ME_PATH))
                        .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                        .addHeader(HttpHeaders.AUTHORIZATION, token)
                        .addHeader("wazuh-uid", PluginSettings.getInstance().getClusterUUID())
                        .addHeader("wazuh-tag", "v" + PluginSettings.getInstance().getVersion())
                        .addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP)
                        .build();

        this.client.execute(
                SimpleRequestProducer.create(request),
                SimpleResponseConsumer.create(),
                new HttpResponseCallback(request, "Outgoing request failed") {
                    @Override
                    public void completed(SimpleHttpResponse response) {
                        super.completed(response);
                        listener.onResponse(response);
                    }

                    @Override
                    public void failed(Exception ex) {
                        super.failed(ex);
                        listener.onFailure(ex);
                    }

                    @Override
                    public void cancelled() {
                        super.cancelled();
                        listener.onFailure(new InterruptedException("HTTP request cancelled"));
                    }
                });
    }

    /**
     * Perform an HTTP GET request to the public CTI catalog plans endpoint. No authentication
     * required.
     *
     * @return HTTP response.
     * @throws ExecutionException request failed.
     * @throws InterruptedException request failed / interrupted.
     * @throws TimeoutException request timed out.
     */
    public SimpleHttpResponse getCatalogPlans()
            throws ExecutionException, InterruptedException, TimeoutException {
        String url = ctiUri(CATALOG_PLANS_PATH);

        SimpleHttpRequest request =
                SimpleRequestBuilder.get(url)
                        .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                        .addHeader("wazuh-tag", "v" + PluginSettings.getInstance().getVersion())
                        .addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP)
                        .build();

        final Future<SimpleHttpResponse> future =
                this.client.execute(
                        SimpleRequestProducer.create(request),
                        SimpleResponseConsumer.create(),
                        new HttpResponseCallback(request, "Outgoing request failed"));
        return future.get(this.TIMEOUT, TimeUnit.SECONDS);
    }

    /**
     * Async variant of {@link #getCatalogPlans()}. Notifies the listener with the HTTP response
     * instead of blocking.
     *
     * @param listener listener notified with the HTTP response on success, or on failure.
     */
    public void getCatalogPlans(ActionListener<SimpleHttpResponse> listener) {
        String url = ctiUri(CATALOG_PLANS_PATH);

        SimpleHttpRequest request =
                SimpleRequestBuilder.get(url)
                        .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                        .addHeader("wazuh-tag", "v" + PluginSettings.getInstance().getVersion())
                        .addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP)
                        .build();

        this.client.execute(
                SimpleRequestProducer.create(request),
                SimpleResponseConsumer.create(),
                new HttpResponseCallback(request, "Outgoing request failed") {
                    @Override
                    public void completed(SimpleHttpResponse response) {
                        super.completed(response);
                        listener.onResponse(response);
                    }

                    @Override
                    public void failed(Exception ex) {
                        super.failed(ex);
                        listener.onFailure(ex);
                    }

                    @Override
                    public void cancelled() {
                        super.cancelled();
                        listener.onFailure(new InterruptedException("HTTP request cancelled"));
                    }
                });
    }
}
