package com.wazuh.contentmanager.rest.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * General error response model for REST API endpoints.
 * Provides a standardized error format across all API responses.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RestResponse implements ToXContent {
    private static final String MESSAGE = "message";
    private static final String STATUS = "status";

    @JsonProperty(MESSAGE)
    private String message;
    @JsonProperty(STATUS)
    private int status;

    /**
     * Default constructor for frameworks that require a no-arg constructor
     */
    public RestResponse() { }

    /**
     * Creates an ErrorResponse with the provided message and HTTP status code.
     *
     * @param message human-readable error message
     * @param status  HTTP status code representing the error condition
     */
    public RestResponse(String message, int status) {
        this.message = message;
        this.status = status;
    }

    /**
     * Returns the error message.
     *
     * @return the error message string, may be null
     */
    public String getMessage() {
        return this.message;
    }

    /**
     * Sets or updates the error message.
     *
     * @param message the new error message
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * Returns the HTTP status code associated with this error.
     *
     * @return the HTTP status code
     */
    public int getStatus() {
        return this.status;
    }

    /**
     * Sets the HTTP status code for this error response.
     *
     * @param status the HTTP status code to set
     */
    public void setStatus(int status) {
        this.status = status;
    }

    @Override
    /**
     * Returns a compact string representation of this ErrorResponse.
     *
     * @return string representation containing message and status
     */
    public String toString() {
        return "{" +
            "message='" + message + '\'' +
            ", status=" + status +
            '}';
    }

    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field(MESSAGE, this.getMessage())
            .field(STATUS, this.getStatus())
            .endObject();

        return builder;
    }
}

