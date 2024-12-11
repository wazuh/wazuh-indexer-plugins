/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
 */
package com.wazuh.commandmanager;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedAction;

import com.wazuh.commandmanager.utils.httpclient.HttpRestClient;

public class CommandManagerTests extends OpenSearchTestCase {
    // Add unit tests for your plugin

    private HttpRestClient httpClient;

    public void testPost_success() {
        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<SimpleHttpResponse>)
                            () -> {
                                this.httpClient = HttpRestClient.getInstance();
                                URI uri;
                                try {
                                    uri = new URI("https://httpbin.org/post");
                                } catch (URISyntaxException e) {
                                    throw new RuntimeException(e);
                                }
                                String payload = "{\"message\": \"Hello world!\"}";
                                SimpleHttpResponse postResponse =
                                        this.httpClient.post(
                                                uri,
                                                payload,
                                                "randomId",
                                                (org.apache.hc.core5.http.Header) null);

                                String responseText = postResponse.getBodyText();
                                assertNotEquals(null, postResponse);
                                assertNotEquals(null, responseText);
                                assertEquals(200, postResponse.getCode());
                                assertNotEquals(0, responseText.length());
                                assertTrue(responseText.contains("Hello world!"));
                                return postResponse;
                            });
        } catch (Exception e) {
            Assert.fail("Failed to execute HTTP request: " + e);
        } finally {
            this.httpClient.stopHttpAsyncClient();
        }
    }

    public void testPost_badUri() {}

    public void testPost_badPayload() {}
}
