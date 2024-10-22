/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.jobscheduler;

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.Schedule;

import java.io.IOException;
import java.time.Instant;

public class CommandManagerJobParameter implements ScheduledJobParameter {
    public static final String NAME_FIELD = "name";
    public static final String ENABLED_FIELD = "enabled";
    public static final String LAST_UPDATE_TIME_FIELD = "last_update_time";
    public static final String LAST_UPDATE_TIME_FIELD_READABLE = "last_update_time_field";
    public static final String SCHEDULE_FIELD = "schedule";
    public static final String ENABLED_TIME_FIELD = "enabled_time";
    public static final String ENABLED_TIME_FIELD_READABLE = "enabled_time_field";

    private String jobName;
    private Instant lastUpdateTime;
    private Instant enabledTime;
    private boolean isEnabled;
    private Schedule schedule;


    public CommandManagerJobParameter() {}

    public CommandManagerJobParameter(String jobName, Schedule schedule) {
        this.jobName = jobName;
        this.schedule = schedule;

        Instant now = Instant.now();
        this.isEnabled = true;
        this.enabledTime = now;
        this.lastUpdateTime = now;
    }


    @Override
    public String getName() {
        return this.jobName;
    }


    @Override
    public Instant getLastUpdateTime() {
        return this.lastUpdateTime;
    }


    @Override
    public Instant getEnabledTime() {
        return this.enabledTime;
    }


    @Override
    public Schedule getSchedule() {
        return this.schedule;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    public void setJobName(String jobName) {
        this.jobName = jobName;
    }

    public void setLastUpdateTime(Instant lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }

    public void setEnabledTime(Instant enabledTime) {
        this.enabledTime = enabledTime;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    public void setSchedule(Schedule schedule) {
        this.schedule = schedule;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NAME_FIELD, this.jobName);
        builder.field(ENABLED_FIELD, this.isEnabled);
        builder.field(SCHEDULE_FIELD, this.schedule);
        if (this.enabledTime != null) {
            builder.timeField(ENABLED_TIME_FIELD, ENABLED_TIME_FIELD_READABLE, this.enabledTime.toEpochMilli());
        }
        if (this.lastUpdateTime != null) {
            builder.timeField(LAST_UPDATE_TIME_FIELD, LAST_UPDATE_TIME_FIELD_READABLE, this.lastUpdateTime.toEpochMilli());
        }
        builder.endObject();

        return builder;
    }
}
