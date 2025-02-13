package com.wazuh.contentmanager.utils.httpclient;

import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class CTIClient extends HttpClient {

    private static final Logger log = LogManager.getLogger(CTIClient.class);

    private static CTIClient instance;

    private static final String apiUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";//PluginSettings.getInstance().getCtiBaseUrl().concat( "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0");
    private static URI uri;

    protected CTIClient() {
        super(uri);
    }

    public static CTIClient getInstance() {
        if (instance == null) {
            synchronized (CTIClient.class) {
                if (instance == null) {
                    try {
                        uri = new URI(apiUrl);
                    } catch (URISyntaxException e) {
                        log.error("Problems in the creation of URI {}", e.getMessage());
                    }
                    instance = new CTIClient();
                }
            }
        }
        return instance;
    }

    public CompletableFuture<SimpleHttpResponse> getChanges(
            String requestBody, Map<String, String> queryParameters, Header... headers) {
            return super.sendRequestAsync("POST", requestBody, null, queryParameters, headers);

    }

    public CompletableFuture<SimpleHttpResponse> getCatalog(
            String requestBody, Map<String, String> queryParameters, Header headers) {
        String endpoint = "/catalog";
            return super.sendRequestAsync("POST", requestBody, endpoint, queryParameters, headers);
    }
}
