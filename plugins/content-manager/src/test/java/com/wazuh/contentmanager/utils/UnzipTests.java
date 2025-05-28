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
package com.wazuh.contentmanager.utils;

import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.mockito.Mockito.*;

/** Class to handle unzip tests */
public class UnzipTests extends OpenSearchTestCase {
    private Path tempDestinationDirectory;
    private Path tempZipPath;
    private Path destinationPath;
    private final String testFile = "testfile.txt";
    private final String testFileMessage = "Hello, World!";
    private Environment environment;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Environment set up
        this.tempDestinationDirectory = createTempDir();
        tempZipPath = this.tempDestinationDirectory.resolve("file.zip");
        destinationPath = this.tempDestinationDirectory.resolve("");
        Settings settings =
                Settings.builder()
                        .put("path.home", this.tempDestinationDirectory.toString()) // Required by OpenSearch
                        .putList("path.repo", this.tempDestinationDirectory.toString())
                        .build();
        this.environment = new Environment(settings, this.tempDestinationDirectory);

        try (ZipOutputStream zipOutputStream =
                new ZipOutputStream(Files.newOutputStream(tempZipPath))) {
            ZipEntry entry = new ZipEntry(this.testFile);
            zipOutputStream.putNextEntry(entry);
            zipOutputStream.write(this.testFileMessage.getBytes(StandardCharsets.UTF_8));
            zipOutputStream.closeEntry();
        }
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /** Test valid unzip process */
    public void testValidUnzip() {
        try {
            Unzip.unzip(this.tempZipPath, this.destinationPath);
            Path extractedFilePath = this.tempDestinationDirectory.resolve(this.testFile);
            assertTrue("File should be extracted", Files.exists(extractedFilePath));
            String fileContent = Files.readString(extractedFilePath, StandardCharsets.UTF_8);
            assertEquals("File content should match", this.testFileMessage, fileContent.trim());
        } catch (IOException e) {
            fail("Unexpected IOException: " + e.getMessage());
        }
    }

    /** Test NullPointerException */
    public void testNullPointerException() {
        assertThrows(
                NullPointerException.class, () -> Unzip.unzip(null, this.tempDestinationDirectory));
    }

    /** Test FileNotFoundException */
    public void testFileNotFoundException() {
        assertThrows(
                FileNotFoundException.class,
                () ->
                        Unzip.unzip(environment.tmpDir().resolve("fake.txt"), this.tempDestinationDirectory));
    }
}
