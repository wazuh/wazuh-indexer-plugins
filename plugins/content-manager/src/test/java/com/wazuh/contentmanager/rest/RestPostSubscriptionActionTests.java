package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Subscription;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.services.RestPostSubscriptionAction;
import org.junit.Before;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;

import static org.mockito.Mockito.*;

public class RestPostSubscriptionActionTests extends OpenSearchTestCase {
    private CtiConsole console;
    private RestPostSubscriptionAction action;

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
        this.action = new RestPostSubscriptionAction(this.console);
    }

    /** Test the {@link RestPostSubscriptionAction#handleRequest(Subscription)} method when the request is complete.
     *  The expected response is: {201, RestResponse}
     */
    public void testPostToken201() throws IOException {
        // Mock
        Subscription subscription = new Subscription();

        //Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(subscription);

        // Expected response
        RestResponse expectedResponse = new RestResponse("Subscription created successfully", RestStatus.CREATED.getStatus());

        // Assert
        assertTrue(bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        assertTrue(bytesRestResponse.content().utf8ToString().contains(String.valueOf(expectedResponse.getStatus())));
        assertEquals(RestStatus.CREATED, bytesRestResponse.status());

    }

    /** Test the {@link RestPostSubscriptionAction#handleRequest(Subscription)} method when the token has not been created (mock).
     *  The expected response is: {400, RestResponse}
     */
    public void testPostToken400() throws IOException {
        // Mock
        Subscription subscription = new Subscription();
        doThrow(new IllegalArgumentException("Missing required parameters")).when(this.console).onPostSubscriptionRequest(subscription);

        //Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest(subscription);

        // Expected response
        RestResponse expectedResponse = new RestResponse("Missing required parameters", RestStatus.BAD_REQUEST.getStatus());

        // Assert
        assertTrue(bytesRestResponse.content().utf8ToString().contains(expectedResponse.getMessage()));
        assertTrue(bytesRestResponse.content().utf8ToString().contains(String.valueOf(expectedResponse.getStatus())));
        assertEquals(RestStatus.BAD_REQUEST, bytesRestResponse.status());
    }

}
