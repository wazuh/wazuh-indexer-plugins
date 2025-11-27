package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.services.RestDeleteSubscriptionAction;
import org.junit.Before;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;

import static org.mockito.Mockito.*;

public class RestDeleteSubscriptionActionTests extends OpenSearchTestCase {
    private CtiConsole console;
    private RestDeleteSubscriptionAction action;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.console = mock(CtiConsole.class);
        this.action = new RestDeleteSubscriptionAction(this.console);
    }

    /** Test the {@link RestDeleteSubscriptionAction#handleRequest()} method when the token is created (mock).
     *  The expected response is: {200, RestResponse}
     */
    public void testDeleteToken200() throws IOException {
        // Mock
        Token token = new Token("test_token", "test_type");
        when(this.console.getToken()).thenReturn(token);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Expected response
        RestResponse expectedResponse = new RestResponse("Subscription deleted successfully", RestStatus.OK.getStatus());

        // Assert
        assertTrue(bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        assertTrue(bytesRestResponse.content().utf8ToString().contains(String.valueOf(expectedResponse.getStatus())));
        assertEquals(RestStatus.OK, bytesRestResponse.status());
    }

    /** Test the {@link RestDeleteSubscriptionAction#handleRequest()} method when the token has not been created (mock).
     *  The expected response is: {404, RestResponse}
     */
    public void testDeleteToken404() throws IOException {
        // Mock
        when(this.console.getToken()).thenReturn(null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Expected response
        RestResponse expectedResponse = new RestResponse("Token not found", RestStatus.NOT_FOUND.getStatus());

        // Assert
        assertTrue(bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        assertTrue(bytesRestResponse.content().utf8ToString().contains(String.valueOf(expectedResponse.getStatus())));
        assertEquals(RestStatus.NOT_FOUND, bytesRestResponse.status());
    }

}
