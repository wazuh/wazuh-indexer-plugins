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

public class ContentUpdaterJobParameter implements ScheduledJobParameter {
    private String name;
    private Schedule schedule;
    private Instant lastUpdateTime;
    private Instant enabledTime;
    private boolean isEnabled;

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

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return null;
    }
}
