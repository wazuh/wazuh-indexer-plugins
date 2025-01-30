package com.wazuh.contentmanager.action.cti;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.util.http.HttpClient;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.message.BasicHeader;
import org.opensearch.rest.RestRequest;

import java.net.URI;

public class GetConsumers {
    public static SimpleHttpResponse handleGet(RestRequest request) {
        if (request.hasContent()) {
            request.content();
        }
        return HttpClient.getInstance()
                .get(
                        URI.create(PluginSettings.getInstance().getUri()),
                        null,
                        new BasicHeader("authorization", "Bearer: API-TOKEN"));
    }
}
