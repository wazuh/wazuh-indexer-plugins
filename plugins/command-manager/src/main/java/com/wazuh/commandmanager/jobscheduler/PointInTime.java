package com.wazuh.commandmanager.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.search.builder.PointInTimeBuilder;

import javax.swing.*;
import java.sql.Time;

public class PointInTime {
    private static final Logger log = LogManager.getLogger(PointInTime.class);
    private static PointInTime INSTANCE;
    private String id;
    private CreatePitRequest createPitRequest;
    private PointInTimeBuilder pointInTimeBuilder;
    private CreatePitResponse createPitResponse;
    private TimeValue keepAlive = TimeValue.timeValueSeconds(60L);

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
                    getPointInTimeBuilder().setKeepAlive(getKeepAlive());
                }

                @Override
                public void onFailure(Exception e) {
                    log.error(e);
                }
            });
    }


    public CreatePitResponse getCreatePitResponse() {
        return createPitResponse;
    }

    public void setCreatePitResponse(CreatePitResponse createPitResponse) {
        this.createPitResponse = createPitResponse;
    }

    public PointInTimeBuilder getPointInTimeBuilder() {
        return pointInTimeBuilder;
    }

    public void setPointInTimeBuilder(PointInTimeBuilder pointInTimeBuilder) {
        this.pointInTimeBuilder = pointInTimeBuilder;
    }

    public PointInTime() {
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

    public void setKeepAlive(TimeValue keepAlive) {
        this.keepAlive = keepAlive;
    }

    public static PointInTime getInstance(Client client, String index) {
        log.info("Getting Job Runner Instance");
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (SearchJob.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new PointInTime();
            INSTANCE.createPit(client, index);
            return INSTANCE;
        }
    }
}
