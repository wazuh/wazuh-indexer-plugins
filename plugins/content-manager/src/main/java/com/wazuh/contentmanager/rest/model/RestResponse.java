package com.wazuh.contentmanager.rest.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * General response model for REST API endpoints.
 *
 * <p>This class provides a standardized format for API responses that include
 * a human-readable message and an HTTP status code. It can be serialized to
 * OpenSearch XContent via the {@link org.opensearch.core.xcontent.ToXContent}
 * interface implementation.
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

    /**
     * Serializes this RestResponse into an {@link XContentBuilder} using JSON
     * format.
     *
     * @return an {@link XContentBuilder} containing the JSON representation
     *         of this RestResponse
     * @throws IOException if an I/O error occurs while building the content
     */
    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    /**
     * Writes the fields of this RestResponse into the provided
     * {@link XContentBuilder}. The resulting structure is a JSON object with
     * the keys {@code message} and {@code status}.
     *
     * @param builder the XContent builder to write into
     * @param params  optional parameters (may be ignored)
     * @return the same {@link XContentBuilder} instance passed as {@code builder}
     * @throws IOException if an I/O error occurs while writing to the builder
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .field(MESSAGE, this.getMessage())
            .field(STATUS, this.getStatus())
            .endObject();

        return builder;
    }
}

