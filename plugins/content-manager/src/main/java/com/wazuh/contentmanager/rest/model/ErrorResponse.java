package com.wazuh.contentmanager.rest.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * General error response model for REST API endpoints.
 * Provides a standardized error format across all API responses.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ErrorResponse {
    @JsonProperty("message")
    private String message;
    @JsonProperty("status")
    private int status;

    /**
     * Default constructor for frameworks that require a no-arg constructor
     */
    public ErrorResponse() { }

    /**
     * Creates an ErrorResponse with the provided message and HTTP status code.
     *
     * @param message human-readable error message
     * @param status  HTTP status code representing the error condition
     */
    public ErrorResponse(String message, int status) {
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
}

