package com.wazuh.contentmanager.model.rest;

/**
 * General error response model for REST API endpoints.
 * Provides a standardized error format across all API responses.
 */
public class ErrorResponse {
    private String message;
    private int status;

    public ErrorResponse(String message, int status) {
        this.message = message;
        this.status = status;
    }

    public String getMessage() { return message; }
    public int getStatus() { return status; }

}
