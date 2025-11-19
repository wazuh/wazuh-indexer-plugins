package com.wazuh.contentmanager.cti.model;

import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

public class Token implements Writeable, ToXContent {

    private static final String ACCESS_TOKEN_FIELD = "access_token";
    private static final String EXPIRES_IN_FIELDS = "expires_in";

    private final String accessToken;
    private final Integer expiresIn;

    public Token(String accessToken, Integer expiresIn) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
    }

    public static Token parse(XContentParser xcp) throws IOException {
        String accessToken = null;
        Integer expiresIn = null;

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case ACCESS_TOKEN_FIELD:
                    accessToken = xcp.text();
                    break;
                case EXPIRES_IN_FIELDS:
                    expiresIn = xcp.intValue();
                    break;
                default:
                    break;
            }
        }
        return new Token(accessToken, expiresIn);
    }

    /**
     * Write this into the {@linkplain StreamOutput}.
     *
     * @param out
     */
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(this.accessToken);
        out.writeOptionalInt(this.expiresIn);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (this.accessToken != null) {
            builder.field(ACCESS_TOKEN_FIELD, this.accessToken);
        }
        if(this.expiresIn != null) {
            builder.field(EXPIRES_IN_FIELDS, this.expiresIn);
        }
        builder.endObject();
        builder.endObject();
        return builder;
    }
}
