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
package com.wazuh.setup.jobscheduler;

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.Schedule;

import java.io.IOException;
import java.time.Instant;

public class AgentJobParameter implements ScheduledJobParameter {
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
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params)
            throws IOException {
        return null;
    }
}
