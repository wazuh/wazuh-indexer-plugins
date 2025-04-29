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
package com.wazuh.contentmanager.jobscheduler;

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.Schedule;

import java.io.IOException;
import java.time.Instant;

/** A model for the Content Updater job parameters, defining the schema of the scheduled job. */
public class ContentUpdaterJobParameter implements ScheduledJobParameter {
    /** Field for name of the job. (Stirng) */
    public static final String NAME_FIELD = "name";

    /** Field for the enabled status of the job. (Boolean) */
    public static final String ENABLED_FIELD = "enabled";

    /** Field for the last update time of the job. (Instant) */
    public static final String LAST_UPDATE_TIME_FIELD = "last_update_time";

    /** Readable field for the last update time of the job. (Stirng) */
    public static final String LAST_UPDATE_TIME_FIELD_READABLE = "last_update_time_field";

    /** Field for the schedule of the job. (Schedule) */
    public static final String SCHEDULE_FIELD = "schedule";

    /** Field for the enabled time of the job. (Instant) */
    public static final String ENABLED_TIME_FIELD = "enabled_time";

    /** Readable field for the enabled time of the job. (Stirng) */
    public static final String ENABLED_TIME_FIELD_READABLE = "enabled_time_field";

    private String name;
    private Schedule schedule;
    private Instant lastUpdateTime;
    private Instant enabledTime;
    private boolean isEnabled;

    /** Default constructor. */
    public ContentUpdaterJobParameter() {}

    /**
     * Default constructor with parameters.
     *
     * @param name the name for the job.
     * @param schedule the schedule for the job.
     */
    public ContentUpdaterJobParameter(String name, Schedule schedule) {
        this.name = name;
        this.schedule = schedule;
        //
        Instant now = Instant.now();
        this.isEnabled = true;
        this.enabledTime = now;
        this.lastUpdateTime = now;
    }

    // Getters

    @Override
    public String getName() {
        return this.name;
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

    // Setters

    /**
     * Set the name of the job.
     *
     * @param name the name of the job.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Set the schedule of the job.
     *
     * @param schedule the schedule of the job.
     */
    public void setSchedule(Schedule schedule) {
        this.schedule = schedule;
    }

    /**
     * Set the last update time of the job.
     *
     * @param lastUpdateTime the last update time of the job.
     */
    public void setLastUpdateTime(Instant lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }

    /**
     * Set the enabled time of the job.
     *
     * @param enabledTime the enabled time of the job.
     */
    public void setEnabledTime(Instant enabledTime) {
        this.enabledTime = enabledTime;
    }

    /**
     * Set the enabled status of the job.
     *
     * @param isEnabled the enabled status of the job.
     */
    public void setEnabled(boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    /**
     * Set the job name.
     *
     * @param jobName the job name.
     */
    public void setJobName(String jobName) {
        this.name = jobName;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NAME_FIELD, this.name);
        builder.field(ENABLED_FIELD, this.isEnabled);
        builder.field(SCHEDULE_FIELD, this.schedule);
        if (this.enabledTime != null) {
            builder.timeField(
                    ENABLED_TIME_FIELD, ENABLED_TIME_FIELD_READABLE, this.enabledTime.toEpochMilli());
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ContentUpdaterJobParameter)) return false;

        ContentUpdaterJobParameter that = (ContentUpdaterJobParameter) o;

        if (isEnabled != that.isEnabled) return false;
        if (!name.equals(that.name)) return false;
        if (!schedule.equals(that.schedule)) return false;
        if (!lastUpdateTime.equals(that.lastUpdateTime)) return false;
        return enabledTime.equals(that.enabledTime);
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + schedule.hashCode();
        result = 31 * result + lastUpdateTime.hashCode();
        result = 31 * result + enabledTime.hashCode();
        result = 31 * result + (isEnabled ? 1 : 0);
        return result;
    }

    @Override
    public String toString() {
        return "ContentUpdaterJobParameter{"
                + "name=\""
                + this.name
                + "\""
                + ", schedule="
                + this.schedule
                + ", lastUpdateTime="
                + this.lastUpdateTime
                + ", enabledTime="
                + this.enabledTime
                + ", isEnabled="
                + this.isEnabled
                + '}';
    }
}
