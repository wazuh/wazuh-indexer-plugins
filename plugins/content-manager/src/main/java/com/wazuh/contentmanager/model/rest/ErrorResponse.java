package com.wazuh.contentmanager.model.rest;

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

    public ErrorResponse() { }

    public ErrorResponse(String message, int status) {
        this.message = message;
        this.status = status;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    @Override
    public String toString() {
        return "{" +
            "message='" + message + '\'' +
            ", status=" + status +
            '}';
    }
}

