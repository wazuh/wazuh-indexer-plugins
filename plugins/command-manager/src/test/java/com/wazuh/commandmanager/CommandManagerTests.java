/*
 * Copyright (C) 2024, Wazuh Inc.
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

    // FIXME Test is flaky
    @AwaitsFix(bugUrl = "https://github.com/wazuh/wazuh-indexer-plugins/issues/163")
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
