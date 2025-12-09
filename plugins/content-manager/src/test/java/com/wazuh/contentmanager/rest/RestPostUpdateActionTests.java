package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.services.RestPostUpdateAction;
import org.junit.Before;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.mockito.Mockito.*;

public class RestPostUpdateActionTests extends OpenSearchTestCase {
    private CtiConsole console;
    private CatalogSyncJob catalogSyncJob;
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
        this.console = mock(CtiConsole.class);
        this.catalogSyncJob = mock(CatalogSyncJob.class);
        this.action = new RestPostUpdateAction(this.console, this.catalogSyncJob);
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when the token is created (mock).
     *  The expected response is: {200, Token}
     */
    public void testHandleRequest_Accepted() throws IOException {
        // Mock
        Token token = new Token("test_token", "test_type");
        when(this.console.getToken()).thenReturn(token);
        when(this.catalogSyncJob.isRunning()).thenReturn(false);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Expected response
        RestResponse expectedResponse = new RestResponse("Update accepted", RestStatus.ACCEPTED.getStatus());

        // Assert
        assertEquals(RestStatus.ACCEPTED, bytesRestResponse.status());
        String content = bytesRestResponse.content().utf8ToString();
        assertTrue(content.contains(expectedResponse.getMessage()));

        // Verify trigger was called
        verify(this.catalogSyncJob, times(1)).trigger();
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when the token has not been created (mock).
     *  The expected response is: {404, RestResponse}
     */
    public void testHandleRequest_NoToken() throws IOException {
        // Mock
        when(this.console.getToken()).thenReturn(null);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Expected response
        RestResponse expectedResponse = new RestResponse("Token not found", RestStatus.NOT_FOUND.getStatus());

        // Assert
        assertEquals(RestStatus.NOT_FOUND, bytesRestResponse.status());
        String content = bytesRestResponse.content().utf8ToString();
        assertTrue(content.contains(expectedResponse.getMessage()));

        // Verify trigger was NOT called
        verify(this.catalogSyncJob, never()).trigger();
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when there is already a request being performed.
     *  The expected response is: {409, RestResponse}
     */
    public void testHandleRequest_Conflict() throws IOException {
        // Mock
        Token token = new Token("test_token", "test_type");
        when(this.console.getToken()).thenReturn(token);
        when(this.catalogSyncJob.isRunning()).thenReturn(true);

        // Act
        BytesRestResponse bytesRestResponse = this.action.handleRequest();

        // Expected response
        RestResponse expectedResponse = new RestResponse("An update operation is already in progress", RestStatus.CONFLICT.getStatus());

        // Assert
        assertEquals(RestStatus.CONFLICT, bytesRestResponse.status());
        String content = bytesRestResponse.content().utf8ToString();
        assertTrue(content.contains("An update operation is already in progress"));

        // Verify trigger was NOT called
        verify(this.catalogSyncJob, never()).trigger();
    }

    /** Test the {@link RestPostUpdateAction#handleRequest()} method when the rate limit is exceeded.
     *  The expected response is: {429, RestResponse}
     */
    public void testGetToken429() throws IOException {
        // TODO
    }
}
