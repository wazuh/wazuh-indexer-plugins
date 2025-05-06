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
package com.wazuh.contentmanager.client;

import org.apache.hc.client5.http.HttpHostConnectException;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.Method;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.model.cti.ContentChanges;

import static org.mockito.Mockito.*;

/** Tests the CTIClient */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class CTIClientTests extends OpenSearchIntegTestCase {

    private CTIClient ctiClient;
    private CTIClient spyCtiClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp(); // Ensure OpenSearch test setup runs
        this.ctiClient = new CTIClient("www.test.com");
        this.spyCtiClient = spy(this.ctiClient);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        this.ctiClient = null;
        try {
            this.spyCtiClient.close();
        } catch (IOException e) {
            logger.error(
                    "Exception trying to close spy of CtiClient {} in test testSendRequest_SuccessfulRequest",
                    e.getMessage());
        }
        super.tearDown();
    }

    /** */
    public void testSendRequest_SuccessfulRequest() {
        // Arrange
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");

        when(this.spyCtiClient.doHttpClientSendRequest(
                        Method.GET,
                        "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes",
                        null,
                        Collections.emptyMap(),
                        null))
                .thenReturn(mockResponse);

        // Act
        SimpleHttpResponse response;
        response =
                this.spyCtiClient.sendRequest(
                        Method.GET,
                        "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes",
                        null,
                        Collections.emptyMap(),
                        null,
                        3);

        // Assert
        assertNotNull("Response should not be null", response);

        assertEquals(HttpStatus.SC_SUCCESS, response.getCode());
        verify(this.spyCtiClient, times(1))
                .sendRequest(
                        any(Method.class),
                        eq("/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes"),
                        isNull(),
                        anyMap(),
                        isNull(),
                        eq(3));
    }

    /** */
    public void testSendRequest_BadRequest() {
        // Arrange
        SimpleHttpResponse mockResponse =
                new SimpleHttpResponse(HttpStatus.SC_BAD_REQUEST, "Bad Request");

        when(this.spyCtiClient.doHttpClientSendRequest(
                        Method.GET,
                        "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes",
                        null,
                        Collections.emptyMap(),
                        null))
                .thenReturn(mockResponse);

        SimpleHttpResponse response;
        response =
                this.spyCtiClient.sendRequest(
                        Method.GET,
                        "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes",
                        null,
                        Collections.emptyMap(),
                        null,
                        3);

        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getCode());
    }

    /** */
    public void testSendRequest_TooManyRequests_RetriesThreeTimes() {
        // Arrange
        SimpleHttpResponse mockResponse429 =
                new SimpleHttpResponse(HttpStatus.SC_TOO_MANY_REQUESTS, "Too Many Requests");
        mockResponse429.setHeader("Retry-After", "1"); // Timeout para el cooldown

        // Mock that sendRequest returns 429 three times.
        when(this.spyCtiClient.doHttpClientSendRequest(
                        Method.GET,
                        "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes",
                        null,
                        Collections.emptyMap(),
                        null))
                .thenReturn(mockResponse429);

        // Act
        SimpleHttpResponse response =
                this.spyCtiClient.sendRequest(
                        Method.GET,
                        "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes",
                        null,
                        Collections.emptyMap(),
                        null,
                        3);

        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.SC_TOO_MANY_REQUESTS, response.getCode());

        // Verify three calls of doHttpClientSendRequest
        verify(this.spyCtiClient, times(3))
                .doHttpClientSendRequest(
                        any(Method.class),
                        eq("/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes"),
                        isNull(),
                        any(Map.class),
                        isNull());
    }

    /**
     * @throws IOException
     */
    @AwaitsFix(bugUrl = "")
    public void testGetConsumerInfo_SuccessfulRequest() throws IOException {
        // Arrange
        SimpleHttpResponse response = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");
        response.setBody(
                "{\"data\":[{\"offset\":1761037,\"type\":\"update\",\"version\":19,\"context\":\"vd_1.0.0\",\"resource\":\"CVE-2019-0605\",\"operations\":[{\"op\":\"add\",\"path\":\"/containers/cna/x_remediations/windows/0/anyOf/133\",\"value\":\"KB5058922\"},{\"op\":\"add\",\"path\":\"/containers/cna/x_remediations/windows/5/anyOf/140\",\"value\":\"KB5058921\"}]}]}",
                ContentType.APPLICATION_JSON);

        // spotless:off
        when(this.spyCtiClient.sendRequest(
            Method.GET,
            CTIClient.CONSUMER_INFO_ENDPOINT,
            null,
            null,
            null,
            CTIClient.MAX_ATTEMPTS))
        .thenReturn(response);
        // spotless:on

        // Act
        ConsumerInfo consumerInfo = this.spyCtiClient.getConsumerInfo();

        // Assert
        verify(this.spyCtiClient, times(1))
                .sendRequest(any(Method.class), anyString(), isNull(), isNull(), isNull(), anyInt());
        assertEquals(1761037, consumerInfo.getOffset());
    }

    /**
     * Test that {@link CTIClient#getConsumerInfo()} throws {@link HttpHostConnectException} on no
     * response.
     */
    public void testGetConsumerInfo_ThrowException() {
        // Arrange
        doReturn(null).when(this.spyCtiClient).sendRequest(any(), any(), any(), any(), any(), anyInt());

        // Act & Assert
        assertThrows(HttpHostConnectException.class, () -> this.spyCtiClient.getConsumerInfo());
    }

    /** */
    public void testGetChanges_SuccessfulRequest() {
        // Arrange
        SimpleHttpResponse response = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");
        response.setBody(
                "{\"data\":[{\"offset\":1761037,\"type\":\"update\",\"version\":19,\"context\":\"vd_1.0.0\",\"resource\":\"CVE-2019-0605\",\"operations\":[{\"op\":\"add\",\"path\":\"/containers/cna/x_remediations/windows/0/anyOf/133\",\"value\":\"KB5058922\"},{\"op\":\"add\",\"path\":\"/containers/cna/x_remediations/windows/5/anyOf/140\",\"value\":\"KB5058921\"}]}]}",
                ContentType.APPLICATION_JSON);

        when(this.spyCtiClient.sendRequest(
                        any(Method.class), anyString(), anyString(), anyMap(), any(Header.class), anyInt()))
                .thenReturn(response);

        // Act
        ContentChanges changes = this.spyCtiClient.getChanges(0, 200, true);

        // Assert
        verify(this.spyCtiClient, times(1))
                .sendRequest(any(Method.class), anyString(), isNull(), anyMap(), isNull(), anyInt());
    }

    /** */
    public void testGetChanges_NullResponse() {
        when(this.spyCtiClient.sendRequest(
                        any(Method.class), anyString(), anyString(), anyMap(), any(Header.class)))
                .thenReturn(null);

        ContentChanges changes = this.spyCtiClient.getChanges(0, 100, true);
        assertNull(changes);
    }

    /** */
    public void testContextQueryParameters() {
        Map<String, String> params = CTIClient.contextQueryParameters(0, 10, true);
        assertEquals(3, params.size());
        assertEquals(String.valueOf(0), params.get(CTIClient.QueryParameters.FROM_OFFSET.getValue()));
        assertEquals(String.valueOf(10), params.get(CTIClient.QueryParameters.TO_OFFSET.getValue()));
        assertEquals(
                String.valueOf(true), params.get(CTIClient.QueryParameters.WITH_EMPTIES.getValue()));
    }
}
