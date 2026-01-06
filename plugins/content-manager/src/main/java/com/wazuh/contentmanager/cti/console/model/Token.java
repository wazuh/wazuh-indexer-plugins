/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/**
 * Data transfer object that represents an authentication token returned by a CTI provider. This
 * class is used to deserialize JSON responses that contain an access token and its type (for
 * example, "Bearer").
 *
 * <p>Instances of this class can be converted to OpenSearch XContent using the {@link
 * org.opensearch.core.xcontent.ToXContent} interface implementation.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Token implements ToXContent {
    private static final String ACCESS_TOKEN = "access_token";
    private static final String TOKEN_TYPE = "token_type";

    @JsonProperty(ACCESS_TOKEN)
    private String accessToken;

    @JsonProperty(TOKEN_TYPE)
    private String tokenType;

    /** Default constructor. */
    public Token() {}

    /**
     * Creates a Token instance with the provided access token and token type.
     *
     * @param accessToken the access token issued by the CTI provider
     * @param tokenType the type of the token (e.g., "Bearer")
     */
    public Token(String accessToken, String tokenType) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
    }

    /**
     * Getter for accessToken.
     *
     * @return Access Token.
     */
    public String getAccessToken() {
        return this.accessToken;
    }

    /**
     * Returns the token type (e.g., "Bearer").
     *
     * @return the token type string, may be null
     */
    public String getTokenType() {
        return this.tokenType;
    }

    /**
     * Returns a compact string representation of this Token for logging.
     *
     * @return string representation containing accessToken and tokenType
     */
    @Override
    public String toString() {
        return "Token{"
                + "accessToken='"
                + this.accessToken
                + '\''
                + ", tokenType='"
                + this.tokenType
                + '\''
                + '}';
    }

    /**
     * Serializes this Token into an {@link XContentBuilder} using JSON format.
     *
     * @return an {@link XContentBuilder} containing the JSON representation of this Token
     * @throws IOException if an I/O error occurs while building the content
     */
    public XContentBuilder toXContent() throws IOException {
        return this.toXContent(XContentFactory.jsonBuilder(), null);
    }

    /**
     * Writes the fields of this Token into the provided {@link XContentBuilder}. The resulting
     * structure is a JSON object with the keys {@code access_token} and {@code token_type}.
     *
     * @param builder the XContent builder to write into
     * @param params optional parameters (may be ignored)
     * @return the same {@link XContentBuilder} instance passed as {@code builder}
     * @throws IOException if an I/O error occurs while writing to the builder
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder
                .startObject()
                .field(ACCESS_TOKEN, this.getAccessToken())
                .field(TOKEN_TYPE, this.getTokenType())
                .endObject();

        return builder;
    }
}
