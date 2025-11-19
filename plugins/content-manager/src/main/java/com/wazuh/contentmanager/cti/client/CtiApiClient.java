package com.wazuh.contentmanager.cti.client;

import com.wazuh.contentmanager.client.HttpClient;
import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.Method;

import java.net.URI;
import java.util.Map;

public class CtiApiClient extends HttpClient {

    private static final String BASE_URI = "http://localhost:8080";
    private static final String API_PREFIX = "/api/v1";
    private static final String API_URI = BASE_URI + API_PREFIX;
    private static final String TOKEN_URI = API_URI + "/instances/token";
    private static final String PRODUCTS_URI = API_URI + "/instances/me";
    private static final String RESOURCE_URI = API_URI + "/instances/token/exchange";

    /**
     * Constructs an CtiApiClient instance.
     */
    public CtiApiClient() {
        super(URI.create(API_URI));
        SimpleRequestBuilder.post()
    }

    public SimpleHttpResponse get(String endpoint, Map<String, String> queryParams, Header... headers) {
        return this.sendRequest(Method.GET, endpoint, null, queryParams, headers);
    }

    public void getToken(String clientId, String deviceCode) {
        String grantType = "grant_type=urn:ietf:params:oauth:grant-type:device_code";
        String formBody = String.format("%s&client_id=%s&device_code=%s", grantType, clientId, deviceCode);

        SimpleHttpRequest request = SimpleRequestBuilder
            .post(TOKEN_URI)
//            .addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_FORM_URLENCODED.toString())
            .setBody(formBody, ContentType.APPLICATION_FORM_URLENCODED)
            .build();


    }
}
