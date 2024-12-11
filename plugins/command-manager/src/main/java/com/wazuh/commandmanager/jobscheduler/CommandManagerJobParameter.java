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
package com.wazuh.commandmanager.jobscheduler;

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.Schedule;

import java.io.IOException;
import java.time.Instant;

/** A model for the parameters and schema to be indexed to the jobs index. */
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
            builder.timeField(
                    ENABLED_TIME_FIELD,
                    ENABLED_TIME_FIELD_READABLE,
                    this.enabledTime.toEpochMilli());
        }
        if (this.lastUpdateTime != null) {
            builder.timeField(
                    LAST_UPDATE_TIME_FIELD,
                    LAST_UPDATE_TIME_FIELD_READABLE,
                    this.lastUpdateTime.toEpochMilli());
        }
        builder.endObject();

        return builder;
    }
}
