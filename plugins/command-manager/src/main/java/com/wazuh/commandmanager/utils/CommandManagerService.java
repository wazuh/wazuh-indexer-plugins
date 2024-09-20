package com.wazuh.commandmanager.utils;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.CommandDetails;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.engine.DocumentMissingException;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.index.shard.IndexingOperationListener;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class CommandManagerService implements IndexingOperationListener {

    private static final Logger logger = LogManager.getLogger(CommandManagerService.class);

    public static Long TIME_OUT_FOR_REQUEST = 15L;
    private final Client client;
    private final ClusterService clusterService;

    public CommandManagerService(
        final Client client,
        final ClusterService clusterService
    ) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public boolean commandManagerIndexExists() {
        return clusterService.state().routingTable().hasIndex(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
    }

    public void processCommand(
        final String documentId,
        final String commandOrderId,
        final String commandRequestId,
        final String commandSource,
        final String commandTarget,
        final String commandTimeout,
        final String commandType,
        final String commandUser,
        final Map<String, Object> commandAction,
        final Map<String, Object> commandResult,
        ActionListener<String> listener
    ) {
        // Validate command detail params
        if (
            commandOrderId == null
            || commandOrderId.isEmpty()
            || commandRequestId == null
            || commandRequestId.isEmpty()
            || commandSource == null
            || commandSource.isEmpty()
            || commandTarget == null
            || commandTarget.isEmpty()
            || commandTimeout == null
            || commandTimeout.isEmpty()
            || commandType == null
            || commandType.isEmpty()
            || commandUser == null
            || commandUser.isEmpty()
            || commandAction == null
            || commandAction.isEmpty()
            || commandResult == null
            || commandResult.isEmpty()
            ) {
            listener.onFailure(
                new IllegalArgumentException(
                    "command_order_id, command_request_id, command_source, command_target, command_timeout, command_type, command_user, command_action, command_result: are mandatory fields"
                )
            );
        } else {
            // Ensure command details index has been created
            createCommandManagerIndex(ActionListener.wrap(created -> {
                if (created) {
                    try {
                        // Update entry request
                        // Create CommandDetails from params
                        CommandDetails tempCommandDetails = new CommandDetails(
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

                        // Index new command Details entry
                        logger.info(
                            "Creating command details" + " : " + tempCommandDetails.toString()
                        );
                        createCommandDetails(tempCommandDetails, listener);
                    } catch (VersionConflictEngineException e) {
                        logger.debug("could not process command" + commandOrderId, e.getMessage());
                        listener.onResponse(null);
                    }
                } else {
                    listener.onResponse(null);
                }
            }, listener::onFailure));
        }
    }

    private void createCommandDetails(final CommandDetails tempCommandDetails, ActionListener<String> listener) {
        try {
            // Create index request, document Id will be randomly generated
            final IndexRequest request = new IndexRequest(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME).source(
                tempCommandDetails.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)
            ).setIfSeqNo(SequenceNumbers.UNASSIGNED_SEQ_NO).setIfPrimaryTerm(SequenceNumbers.UNASSIGNED_PRIMARY_TERM).create(true);

            client.index(request, ActionListener.wrap(response -> { listener.onResponse(response.getId()); }, exception -> {
                if (exception instanceof IOException) {
                    logger.error("IOException occurred creating command details", exception);
                }
                listener.onResponse(null);
            }));
        } catch (IOException e) {
            logger.error("IOException occurred creating command details", e);
            listener.onResponse(null);
        }
    }

    /**
     * Find command details for a particular document Id
     * @param documentId unique id for command Details document
     * @param listener an {@code ActionListener} that has onResponse and onFailure that is used to return the command details if it was found
     *                 or else null.
     */
    private void findCommandDetails(final String documentId, ActionListener<CommandDetails> listener) {
        GetRequest getRequest = new GetRequest(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME).id(documentId);
        client.get(getRequest, ActionListener.wrap(response -> {
            if (!response.isExists()) {
                logger.info("Non-existent command: " + documentId);
                listener.onResponse(null);
            } else {
                try {
                    XContentParser parser = XContentType.JSON.xContent()
                        .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, response.getSourceAsString());
                    parser.nextToken();
                    listener.onResponse(CommandDetails.parse(parser));
                } catch (IOException e) {
                    logger.error("IOException occurred finding CommandDetails for documentId " + documentId, e);
                    listener.onResponse(null);
                }
            }
        }, exception -> {
            logger.error("Exception occurred finding command details for documentId " + documentId, exception);
            listener.onFailure(exception);
        }));
    }

    /**
     * Delete command details to a corresponding document Id
     * @param documentId unique id to find and delete the command details document in the index
     * @param listener an {@code ActionListener} that has onResponse and onFailure that is used to return the command details if it was deleted
     *                 or else null.
     */
    public void deleteCommandDetails(final String documentId, ActionListener<Boolean> listener) {
        DeleteRequest deleteRequest = new DeleteRequest(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME).id(documentId);
        client.delete(deleteRequest, ActionListener.wrap(response -> {
            listener.onResponse(
                response.getResult() == DocWriteResponse.Result.DELETED || response.getResult() == DocWriteResponse.Result.NOT_FOUND
            );
        }, exception -> {
            if (exception instanceof IndexNotFoundException || exception.getCause() instanceof IndexNotFoundException) {
                logger.debug("Index is not found to delete command details for document id. {} " + documentId, exception.getMessage());
                listener.onResponse(true);
            } else {
                listener.onFailure(exception);
            }
        }));
    }

    /**
     * Update command details to a corresponding documentId
     * @param updateCommandDetails update command details object entry
     * @param documentId unique id to find and update the corresponding document mapped to it
     * @param listener an {@code ActionListener} that has onResponse and onFailure that is used to return the command details if it was updated
     *                 or else null.
     */
    private void updateCommandDetails(final String documentId, final CommandDetails updateCommandDetails, ActionListener<String> listener) {
        try {
            UpdateRequest updateRequest = new UpdateRequest().index(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME)
                .id(documentId)
                .doc(updateCommandDetails.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .fetchSource(true);

            client.update(updateRequest, ActionListener.wrap(response -> listener.onResponse(response.getId()), exception -> {
                if (exception instanceof VersionConflictEngineException) {
                    logger.debug("could not update command details for documentId " + documentId, exception.getMessage());
                }
                if (exception instanceof DocumentMissingException) {
                    logger.debug("Document is deleted. This happens if the command details is already removed {}", exception.getMessage());
                }
                if (exception instanceof IOException) {
                    logger.error("IOException occurred in updating command details.", exception);
                }
                listener.onResponse(null);
            }));
        } catch (IOException e) {
            logger.error("IOException occurred updating command details for documentId " + documentId, e);
            listener.onResponse(null);
        }
    }
    /**
     *
     * @param listener an {@code ActionListener} that has onResponse and onFailure that is used to return the command details index if it was created
     *                 or else null.
     */
    void createCommandManagerIndex(ActionListener<Boolean> listener) {
        if (commandManagerIndexExists()) {
            listener.onResponse(true);
        } else {
            CreateIndexRequest request = new CreateIndexRequest(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
            client.admin()
                .indices()
                .create(request, ActionListener.wrap(response -> listener.onResponse(response.isAcknowledged()), exception -> {
                    if (exception instanceof ResourceAlreadyExistsException
                        || exception.getCause() instanceof ResourceAlreadyExistsException) {
                        listener.onResponse(true);
                    } else {
                        listener.onFailure(exception);
                    }
                }));
        }
    }

    public String generateRandomString(int stringLength) {
        Random random = new Random();
        String randomString = "";
        // Build a list of ascii indices for Alphanumeric characters
        // to be accessed by index
        List<Integer> asciiCharIndices = new ArrayList<>();
        // Decimal numbers
        for(int i = 48; i <= 57 ; i++)
        {
            asciiCharIndices.add(i);
        }
        // Uppercase Latin Characters
        for(int i = 65; i <= 90 ; i++)
        {
            asciiCharIndices.add(i);
        }
        // Lowercase Latin Characters
        for(int i = 97; i <= 122 ; i++)
        {
            asciiCharIndices.add(i);
        }
        for(int i = 0; i <= stringLength; i++)
        {
            //randomString = randomString + (char) random.nextInt(asciiCharIndices.size());
            randomString = randomString + (char) (int) asciiCharIndices.get(random.nextInt(asciiCharIndices.size()));
            logger.info((char) random.nextInt(asciiCharIndices.size()));
        }
        return randomString;
    }

}
