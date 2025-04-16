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

import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.model.ctiapi.ContextChanges;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.Method;
import org.mockito.Mock;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.After;
import org.junit.Before;


import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import static org.mockito.Mockito.*;

/** Tests the CTIClient */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class CTIClientTests extends OpenSearchIntegTestCase{

    private CTIClient ctiClient;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp(); // Ensure OpenSearch test setup runs
        this.ctiClient = new CTIClient("www.test.com");
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (ctiClient != null) {
            ctiClient.close();
        }
        super.tearDown();
    }

    public void testFetchWithRetry_SuccessfulRequest() {
        // Arrange
        SimpleHttpResponse mockResponse = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");

        CTIClient spyCtiClient = spy(this.ctiClient);

        when(spyCtiClient.sendRequest(
            Method.GET, "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes", null, Collections.emptyMap(), (Header[]) null))
            .thenReturn(mockResponse);

        // Act
        SimpleHttpResponse response = spyCtiClient.fetchWithRetry(Method.GET,
            "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes",
            null,
            Collections.emptyMap(),
            null);

        // Assert
        assertNotNull("Response should not be null", response);

        if (response != null) {
            assertEquals(HttpStatus.SC_SUCCESS, response.getCode());
            verify(spyCtiClient, times(1)).sendRequest(any(Method.class), eq("/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0/changes"), isNull(), anyMap(), isNull());
        }
        try {
            spyCtiClient.close();
        } catch (IOException e) {
            logger.error("Exception tryng to close spy of CtiClient {}", e.getMessage());
        }
        this.ctiClient = this.ctiClient.clearInstance();
    }

    public void testGetCatalogNullResponse() {
        // Arrange
        CTIClient spyCtiClient = spy(this.ctiClient);

        doReturn(null).when(spyCtiClient).fetchWithRetry(any(), any(), any(), any(), any());

        // Act
        ConsumerInfo result = spyCtiClient.getCatalog();

        // Assert
        assertNull(result);

        try {
            spyCtiClient.close();
        } catch (IOException e) {
            logger.error("Exception tryng to close spy of CtiClient {}", e.getMessage());
        }
        this.ctiClient = this.ctiClient.clearInstance();
    }

    /*
    public void testGetCatalogSuccess() {
        // Mock the HTTP response
        SimpleHttpResponse response = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");
        when(ctiClient.fetchWithRetry(any(Method.class), anyString(), anyString(), anyMap(), any(Header.class))).thenReturn(response);
        when(response.getBodyBytes()).thenReturn("{\"data\": \"sample\"}".getBytes());

        // Act
        ContextChanges changes = ctiClient.getChanges("0", "200", "true");

        ConsumerInfo catalog = ctiClient.getCatalog();
        assertNotNull(catalog);
        assertEquals(catalog, mockConsumerInfo);
    }
   */

    public void testGetChangesNullResponse() {
        // Mock the HTTP response
        CTIClient spyCtiClient = spy(this.ctiClient);

        when(spyCtiClient.fetchWithRetry(any(Method.class), anyString(), anyString(), anyMap(), any(Header.class))).thenReturn(null);

        ContextChanges changes = spyCtiClient.getChanges("0", "100", "true");
        assertNull(changes);

        try {
            spyCtiClient.close();
        } catch (IOException e) {
            logger.error("Exception tryng to close spy of CtiClient {}", e.getMessage());
        }
        this.ctiClient = this.ctiClient.clearInstance();
    }

    /*
    public void testGetChangesSuccess() throws Exception {
        // Mock the HTTP response
        SimpleHttpResponse response = new SimpleHttpResponse(HttpStatus.SC_SUCCESS, "OK");
        response.setBody("{\"data\":[{\"offset\":1761037,\"type\":\"update\",\"version\":19,\"context\":\"vd_1.0.0\",\"resource\":\"CVE-2019-0605\",\"operations\":[{\"op\":\"add\",\"path\":\"/containers/cna/x_remediations/windows/0/anyOf/133\",\"value\":\"KB5058922\"},{\"op\":\"add\",\"path\":\"/containers/cna/x_remediations/windows/5/anyOf/140\",\"value\":\"KB5058921\"}]}]}", ContentType.APPLICATION_JSON);

        // Configurar los parámetros simulados
        Map<String, String> params = new HashMap<>();
        params.put("from_offset", "1000");
        params.put("to_offset", "2000");
        params.put("with_empties", "false");

        // Mockear el metodo separado que construye los parámetros
        CTIClient spyCtiClient = spy(ctiClient);
        when(spyCtiClient.fetchWithRetry(any(Method.class), anyString(), anyString(), anyMap(), any(Header.class)))
            .thenReturn(response);

        // Act
        ContextChanges changes = spyCtiClient.getChanges("1000", "2000", "false");

        // Assert
        assertNotNull(changes);
        // Additional assertions as needed
    }
    */


    public void testContextQueryParameters() {
        Map<String, String> params = CTIClient.contextQueryParameters("fromOffset", "toOffset", "withEmpties");
        assertEquals(3, params.size());
        assertEquals("fromOffset", params.get(CTIClient.QueryParameters.FROM_OFFSET.getValue()));
        assertEquals("toOffset", params.get(CTIClient.QueryParameters.TO_OFFSET.getValue()));
        assertEquals("withEmpties", params.get(CTIClient.QueryParameters.WITH_EMPTIES.getValue()));

        this.ctiClient = this.ctiClient.clearInstance();
    }

}
