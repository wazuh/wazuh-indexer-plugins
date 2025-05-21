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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/** Class for the JobScheduler Content Updater tests */
public class ContentUpdaterJobParameterTests extends OpenSearchTestCase {
    private static final Logger log = LogManager.getLogger(ContentUpdaterJobParameterTests.class);
    Instant instant;
    String name;
    Schedule schedule;

    /** Test setup method. */
    @Before
    public void setup() {
        this.instant = Instant.now();
        this.name = "test_job";
        this.schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
    }

    /** Test the default constructor */
    public void testDefaultConstructor() {
        ContentUpdaterJobParameter jobParameter = new ContentUpdaterJobParameter();
        assertNotNull(jobParameter);
        assertNull(jobParameter.getName());
        assertNull(jobParameter.getSchedule());
        assertFalse(jobParameter.isEnabled());
        assertNull(jobParameter.getLastUpdateTime());
        assertNull(jobParameter.getEnabledTime());
    }

    /** Test the constructor with parameters */
    public void testConstructorWithParameters() {
        ContentUpdaterJobParameter jobParameter =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        assertNotNull(jobParameter);
        assertEquals(this.name, jobParameter.getName());
        assertEquals(this.schedule, jobParameter.getSchedule());
    }

    /** Test the getters and setters */
    public void testGettersAndSetters() {
        ContentUpdaterJobParameter jobParameter =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        jobParameter.setName(this.name);
        jobParameter.setSchedule(this.schedule);
        jobParameter.setEnabled(true);
        jobParameter.setLastUpdateTime(Instant.now());
        jobParameter.setEnabledTime(Instant.now());

        assertEquals(this.name, jobParameter.getName());
        assertEquals(this.schedule, jobParameter.getSchedule());
        assertTrue(jobParameter.isEnabled());
        assertNotNull(jobParameter.getLastUpdateTime());
        assertNotNull(jobParameter.getEnabledTime());
    }

    /**
     * Test the toXContent method
     *
     * @throws IOException if an I/O error occurs
     */
    public void testToXContent() throws IOException {
        ContentUpdaterJobParameter jobParameter =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        jobParameter.setEnabled(true);
        jobParameter.setLastUpdateTime(Instant.now());
        jobParameter.setEnabledTime(Instant.now());

        XContentBuilder builder = XContentFactory.jsonBuilder();
        jobParameter.toXContent(builder, ToXContent.EMPTY_PARAMS);
        String json = builder.toString();

        assertTrue(json.contains("\"name\":\"" + this.name + "\""));
        assertTrue(json.contains("\"enabled\":true"));
    }

    /** Test the equals method */
    public void testEquals() {
        ContentUpdaterJobParameter jobParameter1 =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        jobParameter1.setLastUpdateTime(this.instant);
        jobParameter1.setEnabledTime(this.instant);
        ContentUpdaterJobParameter jobParameter2 =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        jobParameter2.setLastUpdateTime(this.instant);
        jobParameter2.setEnabledTime(this.instant);

        assertEquals(jobParameter1, jobParameter2);
    }

    /** Test the hashCode method */
    public void testHashCode() {
        ContentUpdaterJobParameter jobParameter1 =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        jobParameter1.setLastUpdateTime(this.instant);
        jobParameter1.setEnabledTime(this.instant);
        ContentUpdaterJobParameter jobParameter2 =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        jobParameter2.setLastUpdateTime(this.instant);
        jobParameter2.setEnabledTime(this.instant);

        assertEquals(jobParameter1.hashCode(), jobParameter2.hashCode());
    }

    /** Test the toString method */
    public void testToString() {
        ContentUpdaterJobParameter jobParameter =
                new ContentUpdaterJobParameter(this.name, this.schedule);
        jobParameter.setEnabled(true);
        jobParameter.setLastUpdateTime(this.instant);
        jobParameter.setEnabledTime(this.instant);

        String string = jobParameter.toString();
        log.warn(string);
        assertTrue(string.contains("ContentUpdaterJobParameter"));
        assertTrue(string.contains("name=" + "\"" + this.name + "\""));
        assertTrue(string.contains("lastUpdateTime=" + this.instant));
        assertTrue(string.contains("enabledTime=" + this.instant));
        assertTrue(string.contains("schedule=" + schedule));
        assertTrue(string.contains("isEnabled=true"));
    }
}
