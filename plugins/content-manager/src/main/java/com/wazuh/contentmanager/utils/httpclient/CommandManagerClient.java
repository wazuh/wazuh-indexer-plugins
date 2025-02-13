package com.wazuh.contentmanager.utils.httpclient;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;


import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class CommandManagerClient extends HttpClient {
    private static volatile CommandManagerClient instance;
    public static final String BASE_COMMAND_MANAGER_URI = "/_plugins/_command_manager";
    public static final String CREATE_COMMAND_URI = BASE_COMMAND_MANAGER_URI + "/commands";

    /**
     * Private default constructor
     */
    CommandManagerClient() {
        super(null);
    }

    public static CommandManagerClient getInstance() {
        if (instance == null) {
            synchronized (CommandManagerClient.class) {
                if (instance == null) {
                    instance = new CommandManagerClient();
                }
            }
        }
        return instance;
    }

    public CompletableFuture<SimpleHttpResponse> postCommand(
            String requestBody, Map<String, String> queryParameters, Header headers) {
        return privilegedRequestAsync("POST", requestBody, CREATE_COMMAND_URI, queryParameters, headers);
    }
}
