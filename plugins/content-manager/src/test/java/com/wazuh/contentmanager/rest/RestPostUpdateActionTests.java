package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.services.RestPostUpdateAction;
import org.junit.Before;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RestPostUpdateActionTests extends OpenSearchTestCase {
    private CtiConsole console;
    private RestPostUpdateAction action;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        console = mock(CtiConsole.class);
        action = new RestPostUpdateAction(console);
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when the token is created (mock).
     *  The expected response is: {200, Token}
     */
    public void testGetToken202() throws IOException {
        // Mock
        Token token = new Token("test_token", "test_type");
        when(console.getToken()).thenReturn(token);

        // Act
        BytesRestResponse bytesRestResponse = action.handleRequest();

        // Expected response
        RestResponse expectedResponse = new RestResponse("Update accepted", RestStatus.ACCEPTED.getStatus());

        // Assert
        assertTrue(bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        assertTrue(bytesRestResponse.content().utf8ToString().contains(String.valueOf(expectedResponse.getStatus())));
        assertEquals(RestStatus.ACCEPTED, bytesRestResponse.status());
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when the token has not been created (mock).
     *  The expected response is: {404, RestResponse}
     */
    public void testGetToken404() throws IOException {
        // Mock
        when(console.getToken()).thenReturn(null);

        // Act
        BytesRestResponse bytesRestResponse = action.handleRequest();

        // Expected response
        RestResponse expectedResponse = new RestResponse("Token not found", RestStatus.NOT_FOUND.getStatus());

        // Assert
        assertTrue(bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        assertTrue(bytesRestResponse.content().utf8ToString().contains(String.valueOf(expectedResponse.getStatus())));
        assertEquals(RestStatus.NOT_FOUND, bytesRestResponse.status());
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when there is already a request being performed.
     *  The expected response is: {409, RestResponse}
     */
    public void testGetToken409() throws IOException {
        // TODO
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when the rate limit is exceeded.
     *  The expected response is: {429, RestResponse}
     */
    public void testGetToken429() throws IOException {
        // TODO
    }

}
