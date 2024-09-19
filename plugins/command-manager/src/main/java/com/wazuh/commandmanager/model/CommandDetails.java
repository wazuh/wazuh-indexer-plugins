package com.wazuh.commandmanager.model;

import org.opensearch.common.Nullable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

public class CommandDetails implements ToXContentObject {


    private String commandOrderId;
    private String commandRequestId;
    private String commandSource;
    private String commandTarget;
    private String commandTimeout;
    private String commandType;
    private String commandUser;
    private Map<String, Object> commandAction;
    private Map<String, Object> commandResult;

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

    public CommandDetails() {}

    public CommandDetails(
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
        this.commandOrderId = commandOrderId;
        this.commandRequestId = commandRequestId;
        this.commandSource = commandSource;
        this.commandTarget = commandTarget;
        this.commandTimeout = commandTimeout;
        this.commandType = commandType;
        this.commandUser = commandUser;
        this.commandAction = commandAction;
        this.commandResult = commandResult;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        XContentBuilder xContentBuilder = builder.startObject();
        if (commandOrderId != null) {
            xContentBuilder.field(COMMAND_ORDER_ID, commandOrderId);
        }
        if (commandRequestId != null) {
            xContentBuilder.field(COMMAND_REQUEST_ID, commandRequestId);
        }
        if (commandSource != null) {
            xContentBuilder.field(COMMAND_SOURCE, commandSource);
        }
        if (commandTarget != null) {
            xContentBuilder.field(COMMAND_TARGET, commandTarget);
        }
        if (commandTimeout != null) {
            xContentBuilder.field(COMMAND_TIMEOUT, commandTimeout);
        }
        if (commandType != null) {
            xContentBuilder.field(COMMAND_TYPE, commandType);
        }
        if (commandUser != null) {
            xContentBuilder.field(COMMAND_USER, commandUser);
        }
        if (commandAction != null) {
            xContentBuilder.field(COMMAND_ACTION, commandAction);
        }
        if (commandResult != null) {
            xContentBuilder.field(COMMAND_RESULT, commandResult);
        }
        return xContentBuilder.endObject();
    }

    public static CommandDetails parse(XContentParser parser) throws IOException {
        String commandOrderId = null;
        String commandRequestId = null;
        String commandSource = null;
        String commandTarget = null;
        String commandTimeout = null;
        String commandType = null;
        String commandUser = null;
        Map<String,Object> commandAction = null;
        Map<String,Object> commandResult = null;

        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            switch (fieldName) {
                case COMMAND_ORDER_ID:
                    commandOrderId = parser.text();
                    break;
                case COMMAND_REQUEST_ID:
                    commandRequestId = parser.text();
                    break;
                case COMMAND_SOURCE:
                    commandSource = parser.text();
                    break;
                case COMMAND_TARGET:
                    commandTarget = parser.text();
                    break;
                case COMMAND_TIMEOUT:
                    commandTimeout = parser.text();
                    break;
                case COMMAND_TYPE:
                    commandType = parser.text();
                    break;
                case COMMAND_USER:
                    commandUser = parser.text();
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

        return new CommandDetails(
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

    public CommandDetails(final CommandDetails copyCommandDetails) {
        this(
            copyCommandDetails.commandOrderId,
            copyCommandDetails.commandRequestId,
            copyCommandDetails.commandSource,
            copyCommandDetails.commandTarget,
            copyCommandDetails.commandTimeout,
            copyCommandDetails.commandType,
            copyCommandDetails.commandUser,
            copyCommandDetails.commandAction,
            copyCommandDetails.commandResult
        );
    }

    @Nullable
    public String getCommandOrderId() {
        return commandOrderId;
    }
    public void setCommandOrderId(String commandOrderId) {
        this.commandOrderId = commandOrderId;
    }

    @Nullable
    public String getCommandRequestId() {
        return commandRequestId;
    }
    public void setCommandRequestId(String commandRequestId) {
        this.commandRequestId = commandRequestId;
    }

    @Nullable
    public String getCommandSource() {
        return commandSource;
    }
    public void setCommandSource(String commandSource) {
        this.commandSource = commandSource;
    }

    @Nullable
    public String getCommandTarget() {
        return commandTarget;
    }
    public void setCommandTarget(String commandTarget) {
        this.commandTarget = commandTarget;
    }

    @Nullable
    public String getCommandTimeout() {
        return commandTimeout;
    }
    public void setCommandTimeout(String commandTimeout) {
        this.commandTimeout = commandTimeout;
    }

    @Nullable
    public String getCommandType() {
        return commandType;
    }
    public void setCommandType(String commandType) {
        this.commandType = commandType;
    }

    @Nullable
    public String getCommandUser() {
        return commandUser;
    }
    public void setCommandUser(String commandUser) {
        this.commandUser = commandUser;
    }

    @Nullable
    public Map<String, Object> getCommandAction() {
        return commandAction;
    }
    public void setCommandAction(Map<String,Object> commandAction) {
        this.commandAction = commandAction;
    }

    @Nullable
    public Map<String, Object> getCommandResult() {
        return commandResult;
    }
    public void setCommandResult(Map<String,Object> commandResult) {
        this.commandResult = commandResult;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CommandDetails that = (CommandDetails) o;
        return Objects.equals(commandOrderId, that.commandOrderId)
            && Objects.equals(commandRequestId, that.commandRequestId)
            && Objects.equals(commandSource, that.commandSource)
            && Objects.equals(commandTarget, that.commandTarget)
            && Objects.equals(commandTimeout, that.commandTimeout)
            && Objects.equals(commandType, that.commandType)
            && Objects.equals(commandUser, that.commandUser)
            && Objects.equals(commandAction, that.commandAction)
            && Objects.equals(commandResult, that.commandResult);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
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

    @Override
    public String toString() {
        return "CommandDetails{"
            + "commandOrderId='"
            + commandOrderId
            + '\''
            + ", commandRequestId='"
            + commandRequestId
            + '\''
            + ", commandSource='"
            + commandSource
            + '\''
            + ", commandTarget='"
            + commandTarget
            + '\''
            + ", commandTimeout='"
            + commandTimeout
            + '\''
            + ", commandType='"
            + commandType
            + '\''
            + ", commandUser='"
            + commandUser
            + '\''
            + ", commandAction='"
            + commandAction
            + '\''
            + ", commandResult='"
            + commandResult
            + '\''
            + '}';
    }
}
