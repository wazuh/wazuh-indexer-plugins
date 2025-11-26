package com.wazuh.contentmanager.cti.catalog.service;

import com.wazuh.contentmanager.cti.catalog.index.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

public class ConsumerServiceImpl extends AbstractService implements ConsumerService {
    private static final Logger log = LogManager.getLogger(ConsumerServiceImpl.class);

//    private static final String CONTEXT = "rules_development_0.0.1";
//    private static final String CONSUMER = "rules_consumer";

    private final String context;
    private final String consumer;
    private final ConsumersIndex consumerIndex;

    public ConsumerServiceImpl(String context, String consumer, ConsumersIndex consumerIndex) {
        this.context = context;
        this.consumer = consumer;
        this.consumerIndex = consumerIndex;
    }

    @Override
    public LocalConsumer getLocalConsumer() {
        try {
            GetResponse response = this.consumerIndex.getConsumer(this.context, this.consumer);

            return response.isExists() ?
                this.mapper.readValue(response.getSourceAsString(), LocalConsumer.class):
                this.setConsumer();
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain consumer from internal index: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse local consumer: {}", e.getMessage());
        }
        return null;
    }

    @Override
    public RemoteConsumer getRemoteConsumer() {
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getConsumer(this.context, this.consumer);

            if (response.getCode() == 200) {
                return this.mapper.readValue(response.getBodyText(), RemoteConsumer.class);
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain consumer from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse remote consumer: {}", e.getMessage());
        }
        return null;
    }

    public LocalConsumer setConsumer() {
        // Default consumer. Initialize.
        LocalConsumer consumer = new LocalConsumer(this.context, this.consumer);

        try {
            IndexResponse response = this.consumerIndex.setConsumer(consumer);

            if (response.status() == RestStatus.CREATED || response.status() == RestStatus.OK) {
                log.info("Local consumer with id [{}] created or updated", response.getId());
                return consumer;
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't save consumer to internal index: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Attempt to save invalid local consumer: {}", e.getMessage());
        }
        return null;
    }
}
