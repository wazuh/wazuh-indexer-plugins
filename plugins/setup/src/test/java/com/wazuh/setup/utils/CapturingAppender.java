/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.setup.utils;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.opensearch.common.logging.Loggers;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Collects the events a logger emits so a test can assert on what was logged and at which level.
 * {@code MockLogAppender} from the test framework is not usable here: it rewrites expected logger
 * names with an {@code org.opensearch.} prefix, so it cannot match this plugin's loggers.
 */
public final class CapturingAppender extends AbstractAppender implements AutoCloseable {

    private final List<LogEvent> events = new CopyOnWriteArrayList<>();
    private final Logger logger;

    private CapturingAppender(Logger logger) {
        super("capturing-" + logger.getName(), null, null, true, Property.EMPTY_ARRAY);
        this.logger = logger;
    }

    /**
     * Attaches a new appender to the logger of a class. Close it (try-with-resources) to detach:
     * Log4j configuration is global to the JVM, so a leaked appender would follow later tests.
     *
     * @param clazz the class whose logger is captured.
     * @return the attached appender.
     */
    public static CapturingAppender attach(Class<?> clazz) {
        CapturingAppender appender = new CapturingAppender(LogManager.getLogger(clazz));
        appender.start();
        Loggers.addAppender(appender.logger, appender);
        return appender;
    }

    @Override
    public void append(LogEvent event) {
        this.events.add(event.toImmutable());
    }

    /**
     * Returns the formatted messages of the captured events logged at a level.
     *
     * @param level the level to filter on.
     * @return the messages, in the order they were logged.
     */
    public List<String> messages(Level level) {
        return this.events.stream()
                .filter(event -> event.getLevel() == level)
                .map(event -> event.getMessage().getFormattedMessage())
                .toList();
    }

    @Override
    public void close() {
        Loggers.removeAppender(this.logger, this);
        super.stop();
    }
}
