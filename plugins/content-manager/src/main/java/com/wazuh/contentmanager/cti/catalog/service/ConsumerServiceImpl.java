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
package com.wazuh.contentmanager.cti.catalog.service;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

/**
 * Implementation of the ConsumerService. Manages the retrieval and persistence of Local and Remote
 * consumer states using internal indices and the CTI API client.
 */
public class ConsumerServiceImpl extends AbstractService implements ConsumerService {
    private static final Logger log = LogManager.getLogger(ConsumerServiceImpl.class);

    private final String context;
    private final String consumer;
    private final ConsumersIndex consumerIndex;

    /**
     * Constructs a ConsumerServiceImpl.
     *
     * @param context The context identifier.
     * @param consumer The consumer identifier.
     * @param consumerIndex The index service for storing consumer metadata.
     */
    public ConsumerServiceImpl(String context, String consumer, ConsumersIndex consumerIndex) {
        this.context = context;
        this.consumer = consumer;
        this.consumerIndex = consumerIndex;
    }

    /**
     * Retrieves the local consumer state from the internal index. If the consumer does not exist
     * locally, it attempts to initialize it.
     *
     * @return The {@link LocalConsumer} object, or null if retrieval/parsing fails.
     */
    @Override
    public LocalConsumer getLocalConsumer() {
        try {
            GetResponse response = this.consumerIndex.getConsumer(this.context, this.consumer);

            return response.isExists()
                    ? this.mapper.readValue(response.getSourceAsString(), LocalConsumer.class)
                    : this.setConsumer();
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain consumer from internal index: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse local consumer: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Retrieves the remote consumer state from the CTI API.
     *
     * @return The {@link RemoteConsumer} object, or null if the API call fails.
     */
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

    /**
     * Creates or updates the default local consumer state in the internal index.
     *
     * @return The initialized {@link LocalConsumer}, or null if persistence fails.
     */
    public LocalConsumer setConsumer() {
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
