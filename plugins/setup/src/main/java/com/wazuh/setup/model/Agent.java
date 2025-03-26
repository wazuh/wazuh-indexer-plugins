package com.wazuh.setup.model;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.List;

/** Command's agent fields. */
public class Agent implements ToXContentObject {
    public static final String AGENT = "agent";
    public static final String ID = "id";
    public static final String GROUPS = "groups";
    public static final String STATUS = "status";
    public static final String LAST_LOGIN = "last_login";
    private final String id;
    private final List<String> groups;
    private final String status;
    private final String lastLogin;

    /**
     * Default constructor.
     *
     * @param groups Agent's groups
     */
    public Agent(String id, List<String> groups, String status, String lastLogin) {
        this.id = id;
        this.groups = groups;
        this.status = status;
        this.lastLogin = lastLogin;
    }

    /**
     * Parses data from an XContentParser into this model.
     *
     * @param parser xcontent parser.
     * @return initialized instance of Agent.
     * @throws IOException parsing error occurred.
     */
    public static Agent parse(XContentParser parser) throws IOException {
        List<Object> groups = List.of();
        String id = null;
        String status = null;
        String lastLogin = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case GROUPS:
                    groups = parser.list();
                    break;
                case ID:
                    id = parser.text();
                    break;
                case STATUS:
                    status = parser.text();
                    break;
                case LAST_LOGIN:
                    lastLogin = parser.text();
                    break;
                default:
                    parser.skipChildren();
                    break;
            }
        }

        // Cast args field Object list to String list
        List<String> convertedGroupFields = (List<String>) (List<?>) (groups);
        return new Agent(id, convertedGroupFields, status, lastLogin);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(AGENT);
        builder.field(ID, this.id);
        builder.field(GROUPS, this.groups);
        builder.field(STATUS, this.status);
        builder.field(LAST_LOGIN, this.lastLogin);
        return builder.endObject();
    }

    /**
     * Retrieves the agent's id.
     *
     * @return id of the agent.
     */
    public String getId() {
        return this.id;
    }

    @Override
    public String toString() {
        return "Agent{" + "id='" + id + '\'' + " ,status=" + status  + '\'' + ", groups=" + groups + '}';
    }
}
