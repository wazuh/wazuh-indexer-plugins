/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.setup.rest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;

import java.io.IOException;
import java.util.Objects;

/**
 * General response model for REST API endpoints. Provides a standardized JSON format with a
 * human-readable message and an HTTP status code.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RestResponse implements ToXContent {
    private static final String MESSAGE = "message";
    private static final String STATUS = "status";

    @JsonProperty(MESSAGE)
    private String message;

    @JsonProperty(STATUS)
    private int status;

    /** Default constructor for frameworks that require a no-arg constructor. */
    public RestResponse() {}

    /**
     * Creates a RestResponse with the provided message and HTTP status code.
     *
     * @param message human-readable message
     * @param status HTTP status code
     */
    public RestResponse(String message, int status) {
        this.message = message;
        this.status = status;
    }

    /**
     * Returns the message.
     *
     * @return the message string
     */
    public String getMessage() {
        return this.message;
    }

    /**
     * Sets or updates the message.
     *
     * @param message the new message
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * Returns the HTTP status code.
     *
     * @return the HTTP status code
     */
    public int getStatus() {
        return this.status;
    }

    /**
     * Sets the HTTP status code for this response.
     *
     * @param status the HTTP status code to set
     */
    public void setStatus(int status) {
        this.status = status;
    }

    @Override
    public String toString() {
        return "{" + "message='" + this.message + '\'' + ", status=" + this.status + '}';
    }

    /**
     * Serializes this RestResponse into an {@link XContentBuilder} using JSON format.
     *
     * @return an {@link XContentBuilder} containing the JSON representation of this RestResponse
     * @throws IOException if an I/O error occurs while building the content
     */
    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject().field(MESSAGE, this.message).field(STATUS, this.status).endObject();
        return builder;
    }

    /**
     * Converts this response to a {@link BytesRestResponse}.
     *
     * @return a BytesRestResponse suitable for the REST channel
     */
    public BytesRestResponse toBytesRestResponse() {
        try {
            return new BytesRestResponse(
                    RestStatus.fromCode(this.status), this.toXContent(XContentFactory.jsonBuilder(), null));
        } catch (IOException e) {
            return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    @Override
    public boolean equals(Object other) {
        if (other == null || this.getClass() != other.getClass()) {
            return false;
        }
        RestResponse response = (RestResponse) other;
        return this.status == response.status && Objects.equals(this.message, response.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.message, this.status);
    }
}
