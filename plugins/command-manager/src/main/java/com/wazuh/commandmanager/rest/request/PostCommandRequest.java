package com.wazuh.commandmanager.rest.request;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

public class PostCommandRequest extends ActionRequest {

    private static String documentId;
    private static String commandOrderId;
    private static String commandRequestId;
    private static String commandSource;
    private static String commandTarget;
    private static String commandTimeout;
    private static String commandType;
    private static String commandUser;
    private static Map<String, Object> commandAction;
    private static Map<String, Object> commandResult;

    public static final String DOCUMENT_ID = "document_id";
    public static final String COMMAND_ORDER_ID = "command_order_id";
    public static final String COMMAND_REQUEST_ID = "command_request_id";
    public static final String COMMAND_SOURCE = "command_source";
    public static final String COMMAND_TARGET = "command_target";
    public static final String COMMAND_TIMEOUT = "command_timeout";
    public static final String COMMAND_TYPE = "command_type";
    public static final String COMMAND_USER = "command_user";
    public static final String COMMAND_ACTION = "command_action";
    public static final String COMMAND_RESULT = "command_result";

    public PostCommandRequest(StreamInput in) throws IOException {
        super(in);
        documentId = in.readString();
        commandOrderId = in.readString();
        commandRequestId = in.readString();
        commandSource = in.readOptionalString();
        commandTarget = in.readString();
        commandTimeout = in.readString();
        commandType = in.readString();
        commandUser = in.readString();
        commandAction = in.readMap();
        commandResult = in.readMap();
    }

    public PostCommandRequest(
        String documentId,
        String commandOrderId,
        String commandRequestId,
        String commandSource,
        String commandTarget,
        String commandTimeout,
        String commandType,
        String commandUser,
        Map<String,Object> commandAction,
        Map<String,Object> commandResult
    ) {
        super();
        this.documentId = documentId;
        this.commandOrderId = Objects.requireNonNull(commandOrderId);
        this.commandRequestId = Objects.requireNonNull(commandRequestId);
        this.commandSource = Objects.requireNonNull(commandSource);
        this.commandTarget = Objects.requireNonNull(commandTarget);
        this.commandTimeout = Objects.requireNonNull(commandTimeout);
        this.commandType = Objects.requireNonNull(commandType);
        this.commandUser = Objects.requireNonNull(commandUser);
        this.commandAction = Objects.requireNonNull(commandAction);
        this.commandResult = Objects.requireNonNull(commandResult);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(documentId);
        out.writeString(commandOrderId);
        out.writeString(commandRequestId);
        out.writeString(commandSource);
        out.writeString(commandTarget);
        out.writeString(commandTimeout);
        out.writeString(commandType);
        out.writeString(commandUser);
        out.writeMap(commandAction);
        out.writeMap(commandResult);
    }

    public String getDocumentId() {
        return documentId;
    }
    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    public String getCommandOrderId() {
        return commandOrderId;
    }
    public void setCommandOrderId(String commandOrderId) {
        this.commandOrderId = commandOrderId;
    }

    public String getCommandRequestId() {
        return commandRequestId;
    }
    public void setCommandRequestId(String commandRequestId) {
        this.commandRequestId = commandRequestId;
    }

    public String getCommandSource() {
        return commandSource;
    }
    public void setCommandSource(String commandSource) {
        this.commandSource = commandSource;
    }

    public String getCommandTarget() {
        return commandTarget;
    }
    public void setCommandTarget(String commandTarget) {
        this.commandTarget = commandTarget;
    }

    public String getCommandTimeout() {
        return commandTimeout;
    }
    public void setCommandTimeout(String commandTimeout) {
        this.commandTimeout = commandTimeout;
    }

    public String getCommandType() {
        return commandType;
    }
    public void setCommandType(String commandType) {
        this.commandType = commandType;
    }

    public String getCommandUser() {
        return commandUser;
    }
    public void setCommandUser(String commandUser) {
        this.commandUser = commandUser;
    }

    public Map<String, Object> getCommandAction() {
        return commandAction;
    }
    public void setCommandAction(Map<String, Object> commandAction) {
        this.commandAction = commandAction;
    }

    public Map<String, Object> getCommandResult() {
        return commandResult;
    }
    public void setCommandResult(Map<String, Object> commandResult) {
        this.commandResult = commandResult;
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public static PostCommandRequest parse(XContentParser parser) throws IOException {

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();

            switch (fieldName) {
                case DOCUMENT_ID:
                    documentId = parser.textOrNull();
                    break;
                case COMMAND_ORDER_ID:
                    commandOrderId = parser.textOrNull();
                    break;
                case COMMAND_REQUEST_ID:
                    commandRequestId = parser.textOrNull();
                    break;
                case COMMAND_SOURCE:
                    commandSource = parser.textOrNull();
                    break;
                case COMMAND_TARGET:
                    commandTarget = parser.textOrNull();
                    break;
                case COMMAND_TIMEOUT:
                    commandTimeout = parser.textOrNull();
                    break;
                case COMMAND_TYPE:
                    commandType = parser.textOrNull();
                    break;
                case COMMAND_USER:
                    commandUser = parser.textOrNull();
                    break;
                case COMMAND_ACTION:
                    commandAction = parser.map();
                    break;
                case COMMAND_RESULT:
                    commandResult = parser.map();
                    break;
                default:
                    parser.skipChildren();
                    break;
            }

        }
        return new PostCommandRequest(
            documentId,
            commandOrderId,
            commandRequestId,
            commandSource,
            commandTarget,
            commandTimeout,
            commandType,
            commandUser,
            commandAction,
            commandResult
        );
    }
}
