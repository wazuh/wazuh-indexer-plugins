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
package com.wazuh.contentmanager.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

public class UnzipTests extends OpenSearchTestCase {
    private static final Logger log = LogManager.getLogger(UnzipTests.class);

    private Unzip unzipper;
    private Path tempZipPath;
    private Path tempDestinationDirectory;
    private String zipFileName = "test.zip";
    private String testFile = "testfile.txt";
    private String testFileMessage = "Hello, World!";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        Path testHome = createTempDir();
        Settings settings =
                Settings.builder()
                        .put("path.home", testHome.toString()) // Required by OpenSearch
                        .build();

        Environment environment = new Environment(settings, testHome);

        unzipper = new Unzip(environment);
        tempDestinationDirectory = Files.createTempDirectory(testHome, "unzipped");
        tempZipPath = tempDestinationDirectory.resolve(zipFileName);

        try (ZipOutputStream zipOutputStream =
                new ZipOutputStream(Files.newOutputStream(tempZipPath))) {
            ZipEntry entry = new ZipEntry(testFile);
            zipOutputStream.putNextEntry(entry);
            zipOutputStream.write(testFileMessage.getBytes(StandardCharsets.UTF_8));
            zipOutputStream.closeEntry();
        }
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public void testValidUnzip() {
        try {
            unzipper.unzip(tempZipPath.toString(), tempDestinationDirectory.toString());
            Path extractedFilePath = tempDestinationDirectory.resolve(testFile);
            assertTrue("File should be extracted", Files.exists(extractedFilePath));
            String fileContent = Files.readString(extractedFilePath, StandardCharsets.UTF_8);
            assertEquals("File content should match", testFileMessage, fileContent.trim());
        } catch (IOException e) {
            fail("Unexpected IOException: " + e.getMessage());
        }
    }

    public void testNullPointerException() {
        String nullDestinationDirectory = null;
        Exception exception =
                assertThrows(
                        NullPointerException.class,
                        () -> {
                            unzipper.unzip(tempZipPath.toString(), nullDestinationDirectory);
                        });

        String expectedMessage = "Pathname is null: ";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testZipSlip() throws IOException {
        String wrongDestinationDirectory = "../";
        Exception exception =
                assertThrows(
                        NullPointerException.class,
                        () -> {
                            unzipper.unzip(tempZipPath.toString(), wrongDestinationDirectory);
                        });

        String expectedMessage = "Bad zip entry, cannot enter parent directories.";
        String actualMessage = exception.getMessage();
        assertTrue(actualMessage.contains(expectedMessage));
    }
}
