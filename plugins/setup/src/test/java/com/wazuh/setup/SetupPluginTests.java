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
package com.wazuh.setup;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.wazuh.setup.config.SetupConfig;
import com.wazuh.setup.config.SetupConfigException;
import com.wazuh.setup.index.Index;
import com.wazuh.setup.index.SetupStatusIndex;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** Unit tests for the initialization sequence of {@link SetupPlugin}. */
public class SetupPluginTests extends OpenSearchTestCase {

    private static final String EVENTS_TEMPLATE = "templates/streams/events";
    private static final String SHARDS_KEY =
            "templates.streams.events.settings.index.number_of_shards";

    private Path directory;
    private SetupStatusIndex setupStatusIndex;
    private Index eventsIndex;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.directory = LuceneTestCase.createTempDir();
        this.setupStatusIndex = mock(SetupStatusIndex.class);
        this.eventsIndex = mock(Index.class);
        doReturn("templates/setup-status").when(this.setupStatusIndex).getTemplate();
        doReturn(EVENTS_TEMPLATE).when(this.eventsIndex).getTemplate();
    }

    /**
     * Runs the initialization with a configuration file of the given content.
     *
     * @param yaml content of the configuration file.
     * @throws IOException if the file cannot be written.
     */
    private void initialize(String yaml) throws IOException {
        Files.writeString(this.directory.resolve(SetupConfig.FILE), yaml, StandardCharsets.UTF_8);
        SetupPlugin.initialize(
                List.of(this.setupStatusIndex, this.eventsIndex), this.setupStatusIndex, this.directory);
    }

    /**
     * An invalid configuration file stops the initialization after the setup status index: no other
     * index is initialized, and the error names the key.
     */
    public void testInvalidConfigurationFile() {
        SetupConfigException e =
                LuceneTestCase.expectThrows(
                        SetupConfigException.class, () -> this.initialize(SHARDS_KEY + ": \"three\"\n"));

        Assert.assertTrue(e.getMessage(), e.getMessage().contains("[" + SHARDS_KEY + "]"));
        verify(this.setupStatusIndex).initialize();
        verify(this.eventsIndex, never()).initialize();
    }

    /**
     * The setup status index is initialized first and only once. Every other index gets the
     * configuration before it is initialized.
     *
     * @throws IOException if the file cannot be written.
     */
    public void testValidConfigurationFile() throws IOException {
        this.initialize(SHARDS_KEY + ": 3\n");

        InOrder order = inOrder(this.setupStatusIndex, this.eventsIndex);
        ArgumentCaptor<SetupConfig> config = ArgumentCaptor.forClass(SetupConfig.class);
        order.verify(this.setupStatusIndex).initialize();
        order.verify(this.eventsIndex).setConfig(config.capture());
        order.verify(this.eventsIndex).initialize();
        order.verifyNoMoreInteractions();
        Assert.assertEquals(
                "3", config.getValue().templateOverrides(EVENTS_TEMPLATE).get("index.number_of_shards"));
    }

    /** Without a configuration file, every index is initialized with no overrides. */
    public void testNoConfigurationFile() {
        SetupPlugin.initialize(
                List.of(this.setupStatusIndex, this.eventsIndex), this.setupStatusIndex, this.directory);

        ArgumentCaptor<SetupConfig> config = ArgumentCaptor.forClass(SetupConfig.class);
        verify(this.eventsIndex).setConfig(config.capture());
        verify(this.eventsIndex).initialize();
        Assert.assertTrue(config.getValue().templateOverrides(EVENTS_TEMPLATE).isEmpty());
    }
}
