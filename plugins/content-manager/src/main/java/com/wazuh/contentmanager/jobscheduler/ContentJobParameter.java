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
 * Represents the data model for a scheduled job in the content manager plugin. This class handles
 * serialization and deserialization required by the OpenSearch job scheduler plugin to persist and
 * retrieve job definitions from the system index.
 *
 * <p>Each job parameter defines when a job runs (via schedule), what type of work it performs (via
 * jobType), and whether it is currently active. The job scheduler uses these parameters to
 * determine execution timing and route jobs to the appropriate executor implementations.
 *
 * <p>This class implements the ScheduledJobParameter interface from the OpenSearch job scheduler
 * SPI, enabling seamless integration with the job scheduling framework. Jobs are persisted as JSON
 * documents in the system index and deserialized on startup to resume scheduled operations.
 */
public class ContentJobParameter implements ScheduledJobParameter {

    /** Field name for the job name in JSON serialization. */
    public static final String NAME_FIELD = "name";

    /** Field name for the job type in JSON serialization. */
    public static final String JOB_TYPE_FIELD = "job_type";

    /** Field name for the schedule configuration in JSON serialization. */
    public static final String SCHEDULE_FIELD = "schedule";

    /** Field name for the enabled status in JSON serialization. */
    public static final String ENABLED_FIELD = "enabled";

    /** Unique identifier for the scheduled job. */
    private final String name;

    /** Job type identifier determining which executor handles this job. */
    private final String jobType;

    /** Schedule defining when the job runs (Cron, Interval, etc.). */
    private final Schedule schedule;

    /** Flag indicating whether the job is currently active and should be executed. */
    private final boolean isEnabled;

    /** Timestamp of the last update to this job's configuration. */
    private final Instant lastUpdateTime;

    /** Timestamp when this job was enabled. */
    private final Instant enabledTime;

    /**
     * Constructs a new ContentJobParameter with the specified configuration.
     *
     * @param name Unique identifier for the scheduled job.
     * @param jobType Job type identifier determining which executor handles this job.
     * @param schedule Schedule defining when the job runs (Cron, Interval, etc.).
     * @param isEnabled Flag indicating whether the job is currently active.
     * @param lastUpdateTime Timestamp of the last update to this job's configuration.
     * @param enabledTime Timestamp when this job was enabled.
     */
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
     * Gets the job type identifier that determines which executor will handle this job.
     *
     * @return The job type string (e.g., "content-sync-task").
     */
    public String getJobType() {
        return this.jobType;
    }

    /**
     * Gets the unique identifier for this scheduled job.
     *
     * @return The job name.
     */
    @Override
    public String getName() {
        return this.name;
    }

    /**
     * Gets the schedule configuration defining when this job runs.
     *
     * @return The schedule (Cron, Interval, etc.).
     */
    @Override
    public Schedule getSchedule() {
        return this.schedule;
    }

    /**
     * Gets the timestamp of the last update to this job's configuration.
     *
     * @return The last update time.
     */
    @Override
    public Instant getLastUpdateTime() {
        return this.lastUpdateTime;
    }

    /**
     * Gets the timestamp when this job was enabled.
     *
     * @return The enabled time.
     */
    @Override
    public Instant getEnabledTime() {
        return this.enabledTime;
    }

    /**
     * Checks whether this job is currently active and should be executed.
     *
     * @return true if the job is enabled, false otherwise.
     */
    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    /**
     * Serializes this job parameter into an XContentBuilder (JSON-like structure). The serialized
     * format is used to persist the job definition in the OpenSearch system index.
     *
     * <p>The method writes all job configuration fields to the builder, which will then be stored in
     * the job scheduler's system index. This enables the job to be restored and rescheduled after
     * cluster restarts.
     *
     * @param builder The XContentBuilder to write the serialized content to.
     * @param params Additional parameters for serialization (currently unused).
     * @return The XContentBuilder with this job's serialized content.
     * @throws IOException If an error occurs during serialization.
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
     * Parses an XContent (JSON) document from the parser and constructs a ContentJobParameter object.
     * This static factory method is used by the job scheduler to deserialize job definitions when
     * loading them from the system index.
     *
     * <p>The parser is expected to be positioned at the start of a JSON object containing the job
     * configuration fields. Unknown fields are skipped to maintain forward compatibility with newer
     * schema versions.
     *
     * @param parser The XContentParser positioned at the job configuration object.
     * @return A new ContentJobParameter instance populated with the parsed configuration.
     * @throws IOException If an error occurs during parsing or if required fields are missing.
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
                case NAME_FIELD -> name = parser.text();
                case JOB_TYPE_FIELD -> jobType = parser.text();
                    // Delegate schedule parsing to the SPI ScheduleParser
                case SCHEDULE_FIELD -> schedule = ScheduleParser.parse(parser);
                case ENABLED_FIELD -> enabled = parser.booleanValue();
                default -> parser.skipChildren(); // Ignore unknown fields
            }
        }
        return new ContentJobParameter(name, jobType, schedule, enabled, lastUpdateTime, enabledTime);
    }
}
