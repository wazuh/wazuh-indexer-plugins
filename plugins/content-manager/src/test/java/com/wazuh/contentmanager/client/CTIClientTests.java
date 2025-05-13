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
import com.wazuh.contentmanager.model.cti.Offset;
import com.wazuh.contentmanager.model.cti.OperationType;

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

    /**
     * Tests a successful request to the CTI API verifying that:
     *
     * <pre>
     *     - The response is not null.
     *     - The response code is 200 OK.
     *     - The {@link CTIClient#sendRequest(Method, String, String, Map, Header, int)} is invoked exactly 1 time.
     * </pre>
     */
    public void testSendRequest_SuccessfulRequest() {
        // Arrange
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");

        // spotless:off
        when(this.spyCtiClient.doHttpClientSendRequest(
            any(Method.class),
            anyString(),
            any(),
            anyMap(),
            any()))
        .thenReturn(mockResponse);
        // spotless:on

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

    /**
     * Tests a bad request to the CTI API verifying that:
     *
     * <pre>
     *     - The response is not null.
     *     - The response code is 400 BAD_REQUEST.
     *     - The {@link CTIClient#sendRequest(Method, String, String, Map, Header, int)} is invoked exactly 1 time.
     * </pre>
     */
    public void testSendRequest_BadRequest() {
        // Arrange
        SimpleHttpResponse mockResponse =
                new SimpleHttpResponse(HttpStatus.SC_BAD_REQUEST, "Bad Request");

        // spotless:off
        when(this.spyCtiClient.doHttpClientSendRequest(
            any(Method.class),
            anyString(),
            any(),
            anyMap(),
            any()))
        .thenReturn(mockResponse);
        // spotless:on

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
        verify(this.spyCtiClient, times(1))
                .sendRequest(
                        any(Method.class),
                        eq("/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes"),
                        isNull(),
                        anyMap(),
                        isNull(),
                        eq(3));
    }

    /**
     * Tests the rate limiting management for requests the CTI API verifying that:
     *
     * <pre>
     *     - The response is not null.
     *     - The response code is 429 TOO_MANY_REQUESTS.
     *     - The {@link CTIClient#sendRequest(Method, String, String, Map, Header, int)} is invoked exactly 3 times.
     * </pre>
     */
    public void testSendRequest_TooManyRequests_RetriesThreeTimes() {
        // Arrange
        // spotless:off
        SimpleHttpResponse mockResponse429 = new SimpleHttpResponse(
            HttpStatus.SC_TOO_MANY_REQUESTS,
            "Too Many Requests"
        );
        // spotless:on
        // Required by the API.
        mockResponse429.setHeader("Retry-After", "1");

        // Mock that sendRequest returns 429 three times.
        // spotless:off
        when(this.spyCtiClient.doHttpClientSendRequest(
            any(Method.class),
            anyString(),
            any(),
            anyMap(),
            any()))
        .thenReturn(mockResponse429);
        // spotless:on

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
     * Tests a successful request to the CTI API to obtain a consumer's information, verifying that:
     *
     * <pre>
     *     - The response is not null.
     *     - The {@link ConsumerInfo} instance matches the response's data.
     *     - The {@link CTIClient#sendRequest(Method, String, String, Map, Header, int)} is invoked exactly 3 times.
     * </pre>
     *
     * @throws IOException {@inheritDoc}
     */
    public void testGetConsumerInfo_SuccessfulRequest() throws IOException {
        // Arrange
        SimpleHttpResponse response = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");
        response.setBody(
                "{\"data\":{\"id\":4,\"name\":\"vd_4.8.0\",\"context\":\"vd_1.0.0\",\"operations\":null,\"inserted_at\":\"2023-11-23T19:34:18.698495Z\",\"updated_at\":\"2025-03-31T15:17:32.839974Z\",\"changes_url\":\"cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes\",\"last_offset\":1675416,\"last_snapshot_at\":\"2025-03-31T10:24:21.822354Z\",\"last_snapshot_link\":\"https://cti.wazuh.com/store/contexts/vd_1.0.0/consumers/vd_4.8.0/1672583_1743416661.zip\",\"last_snapshot_offset\":1672583,\"paths_filter\":null}}",
                ContentType.APPLICATION_JSON);

        // spotless:off
        when(this.spyCtiClient.doHttpClientSendRequest(
            any(Method.class),
            anyString(),
            any(),
            any(),
            any()
        )).thenReturn(response);
        // spotless:on

        // Act
        ConsumerInfo consumerInfo = this.spyCtiClient.getConsumerInfo();

        // Assert
        assertNotNull(consumerInfo);
        verify(this.spyCtiClient, times(1))
                .sendRequest(any(Method.class), anyString(), isNull(), isNull(), isNull(), anyInt());
        assertEquals(1675416, consumerInfo.getLastOffset());
        assertEquals(
                "https://cti.wazuh.com/store/contexts/vd_1.0.0/consumers/vd_4.8.0/1672583_1743416661.zip",
                consumerInfo.getLastSnapshotLink());
        assertEquals("vd_1.0.0", consumerInfo.getContext());
        assertEquals("vd_4.8.0", consumerInfo.getName());
    }

    /**
     * Test that {@link CTIClient#getConsumerInfo()} throws {@link HttpHostConnectException} on no
     * response.
     */
    public void testGetConsumerInfo_ThrowException() {
        // spotless:off
        when(this.spyCtiClient.sendRequest(
            any(Method.class),
            anyString(),
            anyString(),
            anyMap(),
            any(Header.class)))
        .thenReturn(null);
        // spotless:on

        // Act & Assert
        assertThrows(HttpHostConnectException.class, () -> this.spyCtiClient.getConsumerInfo());
    }

    /**
     * Tests a successful request to the CTI API to obtain changes in a consumer, verifying that:
     *
     * <pre>
     *     - The list of changes is not null.
     *     - The list of changes is not empty.
     *     - The {@link ContentChanges} instance matches the response's data.
     *     - The {@link CTIClient#sendRequest(Method, String, String, Map, Header, int)} is invoked exactly 1 time.
     * </pre>
     */
    public void testGetChanges_SuccessfulRequest() {
        // Arrange
        SimpleHttpResponse response = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");
        response.setBody(
                "{\"data\":[{\"offset\":1761037,\"type\":\"update\",\"version\":19,\"context\":\"vd_1.0.0\",\"resource\":\"CVE-2019-0605\",\"operations\":[{\"op\":\"replace\",\"path\":\"/containers/cna/x_remediations/windows/0/anyOf/133\",\"value\":\"KB5058922\"},{\"op\":\"replace\",\"path\":\"/containers/cna/x_remediations/windows/5/anyOf/140\",\"value\":\"KB5058921\"}]}]}",
                ContentType.APPLICATION_JSON);

        // spotless:off
        when(this.spyCtiClient.doHttpClientSendRequest(
            any(Method.class),
            anyString(),
            any(),
            anyMap(),
            any()))
        .thenReturn(response);
        // spotless:on

        // Act
        ContentChanges changes = this.spyCtiClient.getChanges(0, 200, true);

        // Assert
        assertNotNull(changes);
        assertNotEquals(0, changes.getChangesList().size());
        Offset change = changes.getChangesList().get(0);
        assertEquals(1761037, change.getOffset());
        assertEquals(OperationType.UPDATE, change.getType());
        assertEquals("CVE-2019-0605", change.getResource());
        assertEquals(2, change.getOperations().size());
        verify(this.spyCtiClient, times(1))
                .sendRequest(any(Method.class), anyString(), isNull(), anyMap(), isNull(), anyInt());
    }

    /**
     * Tests an unsuccessful request to the CTI API to obtain changes in a consumer, verifying that
     * even though the response is null:
     *
     * <pre>
     *     - The list of changes is not null (properly initialized).
     *     - The list of changes is empty.
     *     - The {@link CTIClient#sendRequest(Method, String, String, Map, Header, int)} is invoked exactly 1 time.
     * </pre>
     */
    public void testGetChanges_NullResponse() {
        // spotless:off
        when(this.spyCtiClient.sendRequest(
            any(Method.class),
            anyString(),
            anyString(),
            anyMap(),
            any(Header.class)))
        .thenReturn(null);
        // spotless:on

        ContentChanges changes = this.spyCtiClient.getChanges(0, 100, true);
        assertNotNull(changes);
        assertEquals(
                new ContentChanges().getChangesList().isEmpty(), changes.getChangesList().isEmpty());
        verify(this.spyCtiClient, times(1))
                .sendRequest(any(Method.class), anyString(), isNull(), anyMap(), isNull(), anyInt());
    }

    /** Tests the {@link CTIClient#contextQueryParameters} utility method: */
    public void testContextQueryParameters() {
        Map<String, String> params = CTIClient.contextQueryParameters(0, 10, true);
        assertEquals(3, params.size());
        assertEquals(String.valueOf(0), params.get(CTIClient.QueryParameters.FROM_OFFSET.getValue()));
        assertEquals(String.valueOf(10), params.get(CTIClient.QueryParameters.TO_OFFSET.getValue()));
        assertEquals(
                String.valueOf(true), params.get(CTIClient.QueryParameters.WITH_EMPTIES.getValue()));
    }
}
