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
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;

import java.io.IOException;
import java.time.Instant;

/**
 * Represents the data model for a scheduled job. This class handles serialization and
 * deserialization required by the OpenSearch plugin system to store job details.
 */
public class ContentJobParameter implements ScheduledJobParameter {

    // Field names used in JSON/XContent serialization
    public static final String NAME_FIELD = "name";
    public static final String JOB_TYPE_FIELD = "job_type";
    public static final String SCHEDULE_FIELD = "schedule";
    public static final String ENABLED_FIELD = "enabled";

    private final String name;
    private final String jobType; // Determines which executor handles this job
    private final Schedule schedule; // Defines when the job runs (Cron, Interval, etc.)
    private final boolean isEnabled;
    private final Instant lastUpdateTime;
    private final Instant enabledTime;

    public ContentJobParameter(
            String name,
            String jobType,
            Schedule schedule,
            boolean isEnabled,
            Instant lastUpdateTime,
            Instant enabledTime) {
        this.name = name;
        this.jobType = jobType;
        this.schedule = schedule;
        this.isEnabled = isEnabled;
        this.lastUpdateTime = lastUpdateTime;
        this.enabledTime = enabledTime;
    }

    /**
     * Gets the job type identifier.
     *
     * @return The job type string (e.g., "hello-world-task").
     */
    public String getJobType() {
        return this.jobType;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public Schedule getSchedule() {
        return this.schedule;
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
    public boolean isEnabled() {
        return this.isEnabled;
    }

    /**
     * Serializes this object into an XContentBuilder (JSON-like structure). This is used to save the
     * job definition into the system index.
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NAME_FIELD, this.name);
        builder.field(JOB_TYPE_FIELD, this.jobType);
        builder.field(SCHEDULE_FIELD, this.schedule);
        builder.field(ENABLED_FIELD, this.isEnabled);
        builder.endObject();
        return builder;
    }

    /**
     * Static factory method to parse XContent (JSON) back into a ContentJobParameter object. This is
     * used when loading job definitions from the system index.
     */
    public static ContentJobParameter parse(XContentParser parser) throws IOException {
        String name = null;
        String jobType = null;
        Schedule schedule = null;
        boolean enabled = true;
        Instant lastUpdateTime = Instant.now();
        Instant enabledTime = Instant.now();

        // Ensure we are pointing at the start of the object
        XContentParser.Token token = parser.currentToken();
        if (token == null) {
            token = parser.nextToken();
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, token, parser);

        // Iterate over fields in the JSON object
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken(); // Move to the value

            switch (fieldName) {
                case NAME_FIELD:
                    name = parser.text();
                    break;
                case JOB_TYPE_FIELD:
                    jobType = parser.text();
                    break;
                case SCHEDULE_FIELD:
                    // Delegate schedule parsing to the SPI ScheduleParser
                    schedule = ScheduleParser.parse(parser);
                    break;
                case ENABLED_FIELD:
                    enabled = parser.booleanValue();
                    break;
                default:
                    parser.skipChildren(); // Ignore unknown fields
                    break;
            }
        }
        return new ContentJobParameter(name, jobType, schedule, enabled, lastUpdateTime, enabledTime);
    }
}
