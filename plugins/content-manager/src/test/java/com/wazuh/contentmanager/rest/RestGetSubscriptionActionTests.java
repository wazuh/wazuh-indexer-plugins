package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.services.RestGetSubscriptionAction;
import org.junit.Before;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RestGetSubscriptionActionTests extends OpenSearchTestCase {
    private CtiConsole console;
    private RestGetSubscriptionAction action;

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
        this.action = new RestGetSubscriptionAction(this.console);
    }

    /** Test the {@link RestGetSubscriptionAction#handleRequest()} method when the token is created (mock).
     *  The expected response is: {200, Token}
     */
    public void testGetToken200() throws IOException {
        // Mock
        Token token = new Token("test_token", "test_type");
        when(this.console.getToken()).thenReturn(token);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Assert
        assertTrue(bytesRestResponse.content().utf8ToString().contains(token.getAccessToken()));
        assertTrue(bytesRestResponse.content().utf8ToString().contains(token.getTokenType()));
        assertEquals(RestStatus.OK, bytesRestResponse.status());
    }

    /** Test the {@link RestGetSubscriptionAction#handleRequest()} method when the token has not been created (mock).
     *  The expected response is: {404, RestResponse}
     */
    public void testGetToken404() throws IOException {
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
