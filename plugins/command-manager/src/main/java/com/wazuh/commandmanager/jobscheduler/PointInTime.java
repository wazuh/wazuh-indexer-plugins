/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

import com.wazuh.commandmanager.CommandManagerPlugin;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.search.builder.PointInTimeBuilder;

import java.sql.Time;

public class PointInTime {
    private static final Logger log = LogManager.getLogger(PointInTime.class);
    private static PointInTime INSTANCE;
    private String id;
    private CreatePitRequest createPitRequest;
    private PointInTimeBuilder pointInTimeBuilder;
    private CreatePitResponse createPitResponse;
    private final TimeValue keepAlive = TimeValue.timeValueSeconds(30L);

    public PointInTime(Client client, String index) {
        createPit(client, index);
    }

    public void createPit(Client client, String index) {
        Boolean allowPartialPitCreation = false;
        setCreatePitRequest(
            new CreatePitRequest(getKeepAlive(), allowPartialPitCreation, index)
        );
        client.createPit(
            getCreatePitRequest(),
            new ActionListener<>() {
                @Override
                public void onResponse(CreatePitResponse createPitResponse) {
                    setCreatePitResponse(createPitResponse);
                    setId(createPitResponse.getId());
                    setPointInTimeBuilder(
                        new PointInTimeBuilder(createPitResponse.getId())
                    );
                    getPointInTimeBuilder().setKeepAlive(
                        TimeValue.timeValueSeconds(
                            CommandManagerPlugin.PIT_KEEPALIVE_SECONDS
                        )
                    );
                }

                @Override
                public void onFailure(Exception e) {
                    log.error(e.getMessage());
                }
            });
    }

    public void setCreatePitResponse(CreatePitResponse createPitResponse) {
        this.createPitResponse = createPitResponse;
    }

    private CreatePitResponse getCreatePitResponse() {
        return this.createPitResponse;
    }

    public PointInTimeBuilder getPointInTimeBuilder() {
        return pointInTimeBuilder;
    }

    public void setPointInTimeBuilder(PointInTimeBuilder pointInTimeBuilder) {
        this.pointInTimeBuilder = pointInTimeBuilder;
    }

    public CreatePitRequest getCreatePitRequest() {
        return this.createPitRequest;
    }

    public void setCreatePitRequest(CreatePitRequest createPitRequest) {
        this.createPitRequest = createPitRequest;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public TimeValue getKeepAlive() {
        return keepAlive;
    }

}
