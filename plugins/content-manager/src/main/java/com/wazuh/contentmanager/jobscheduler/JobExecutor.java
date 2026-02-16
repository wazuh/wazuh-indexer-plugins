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

import org.opensearch.jobscheduler.spi.JobExecutionContext;

/**
 * Interface that defines the contract for all job executions. Any specific task must implement this
 * interface.
 */
public interface JobExecutor {

    /**
     * Trigger the execution of the job logic.
     *
     * @param context Contains metadata about the job execution (e.g., Job ID).
     */
    void execute(JobExecutionContext context);
}
