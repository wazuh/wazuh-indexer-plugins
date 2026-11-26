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
package com.wazuh.contentmanager.cti.catalog.service;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.Level;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.utils.CapturingAppender;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Tests the remote consumer lookup of {@link ConsumerServiceImpl}. */
public class ConsumerServiceImplTests extends OpenSearchTestCase {

    private static final String RESOURCE =
            "https://cti.example.invalid/api/v1/catalog/contexts/c/consumers/k";

    /**
     * A status other than 200 is logged with its code. Behind a proxy it can be the proxy's own
     * answer, such as a 407 for missing credentials, which otherwise reads as an unreachable feed.
     */
    public void testNon200ConsumerResponseIsLogged() throws Exception {
        ApiClient client = mock(ApiClient.class);
        when(client.getConsumer(RESOURCE)).thenReturn(SimpleHttpResponse.create(407));
        ConsumerServiceImpl service =
                new ConsumerServiceImpl(
                        "c", "k", "cti:catalog:consumer:ruleset", RESOURCE, mock(ConsumersIndex.class), client);

        try (CapturingAppender appender = CapturingAppender.attach(ConsumerServiceImpl.class)) {
            assertNull(service.getRemoteConsumer());
            assertEquals(
                    List.of("Couldn't obtain consumer from CTI: HTTP 407"), appender.messages(Level.ERROR));
        }
    }
}
