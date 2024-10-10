package com.wazuh.commandmanager.scheduler.model;

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.Schedule;

import java.io.IOException;
import java.time.Instant;

public class AsyncHttpQueryRequest implements ScheduledJobParameter {
    @Override
    public String getName() {
        return "";
    }

    @Override
    public Instant getLastUpdateTime() {
        return null;
    }

    @Override
    public Instant getEnabledTime() {
        return null;
    }

    @Override
    public Schedule getSchedule() {
        return null;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public Long getLockDurationSeconds() {
        return ScheduledJobParameter.super.getLockDurationSeconds();
    }

    @Override
    public Double getJitter() {
        return ScheduledJobParameter.super.getJitter();
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        return null;
    }

    @Override
    public boolean isFragment() {
        return ScheduledJobParameter.super.isFragment();
    }
}
