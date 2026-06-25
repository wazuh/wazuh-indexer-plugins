/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.utils;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

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
        this.tempDestinationDirectory = LuceneTestCase.createTempDir();
        this.tempZipPath = this.tempDestinationDirectory.resolve("file.zip");
        this.destinationPath = this.tempDestinationDirectory.resolve("");
        Settings settings =
                Settings.builder()
                        .put("path.home", this.tempDestinationDirectory.toString()) // Required by OpenSearch
                        .putList("path.repo", this.tempDestinationDirectory.toString())
                        .build();
        this.environment = new Environment(settings, this.tempDestinationDirectory);

        try (ZipOutputStream zipOutputStream =
                new ZipOutputStream(Files.newOutputStream(this.tempZipPath))) {
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
            Assert.assertTrue("File should be extracted", Files.exists(extractedFilePath));
            String fileContent = Files.readString(extractedFilePath, StandardCharsets.UTF_8);
            Assert.assertEquals("File content should match", this.testFileMessage, fileContent.trim());
        } catch (IOException e) {
            Assert.fail("Unexpected IOException: " + e.getMessage());
        }
    }

    /** Test NullPointerException */
    public void testNullPointerException() {
        Assert.assertThrows(
                NullPointerException.class, () -> Unzip.unzip(null, this.tempDestinationDirectory));
    }

    /** Test FileNotFoundException */
    public void testFileNotFoundException() {
        Assert.assertThrows(
                FileNotFoundException.class,
                () ->
                        Unzip.unzip(
                                this.environment.tmpDir().resolve("fake.txt"), this.tempDestinationDirectory));
    }

    /**
     * Regression test for the CTI vulnerabilities snapshot failure: large snapshots are ZIP64
     * archives. An archive with more than {@code 0xFFFF} entries forces the writer to emit a ZIP64
     * end-of-central-directory record, which can only be read by traversing the central directory
     * ({@link java.util.zip.ZipFile}). The previous streaming {@code ZipInputStream} implementation
     * could not handle ZIP64 metadata and failed with "invalid entry size" / "Push back buffer is
     * full". This guards against a regression to a streaming reader.
     */
    public void testZip64ArchiveExtraction() throws IOException {
        // Just over the 0xFFFF (65535) entry limit -> forces the writer to emit a ZIP64 EOCD record.
        // The exact count only needs to exceed the limit, so we keep it minimal. Entries are empty
        // except for two sentinels that carry content we assert on, to keep filesystem cost low.
        final int entryCount = 0xFFFF + 1; // 65536
        final int firstSentinel = 0;
        final int lastSentinel = entryCount - 1;
        Path zip = this.tempDestinationDirectory.resolve("zip64.zip");
        try (ZipOutputStream zipOutputStream =
                new ZipOutputStream(new BufferedOutputStream(Files.newOutputStream(zip)))) {
            for (int i = 0; i < entryCount; i++) {
                zipOutputStream.putNextEntry(new ZipEntry("entries/file_" + i + ".txt"));
                if (i == firstSentinel || i == lastSentinel) {
                    zipOutputStream.write(Integer.toString(i).getBytes(StandardCharsets.UTF_8));
                }
                zipOutputStream.closeEntry();
            }
        }

        Path out = this.tempDestinationDirectory.resolve("zip64-out");
        Files.createDirectories(out);
        Unzip.unzip(zip, out);

        Path extractedDir = out.resolve("entries");
        Assert.assertTrue("ZIP64 entries directory should exist", Files.isDirectory(extractedDir));
        // Count only the entries we wrote: the Lucene test filesystem (ExtrasFS) randomly injects
        // "extraN" files/dirs into new directories, so a raw count would be seed-dependent.
        try (Stream<Path> files = Files.list(extractedDir)) {
            long extracted =
                    files.filter(p -> p.getFileName().toString().matches("file_\\d+\\.txt")).count();
            Assert.assertEquals("All ZIP64 entries should be extracted", entryCount, extracted);
        }
        Assert.assertEquals(
                Integer.toString(firstSentinel),
                Files.readString(extractedDir.resolve("file_" + firstSentinel + ".txt")));
        Assert.assertEquals(
                Integer.toString(lastSentinel),
                Files.readString(extractedDir.resolve("file_" + lastSentinel + ".txt")));
    }

    /** Nested directories and multiple files extract with the correct layout and content. */
    public void testNestedDirectoriesAndMultipleFiles() throws IOException {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("root.txt", "root");
        entries.put("dir/", null); // explicit directory entry
        entries.put("dir/child.txt", "child");
        entries.put("dir/sub/deep.txt", "deep"); // parent dirs created implicitly
        Path zip = this.createZip("nested.zip", entries);

        Path out = this.tempDestinationDirectory.resolve("nested-out");
        Files.createDirectories(out);
        Unzip.unzip(zip, out);

        Assert.assertEquals("root", Files.readString(out.resolve("root.txt")));
        Assert.assertTrue(Files.isDirectory(out.resolve("dir")));
        Assert.assertEquals("child", Files.readString(out.resolve("dir/child.txt")));
        Assert.assertEquals("deep", Files.readString(out.resolve("dir/sub/deep.txt")));
    }

    /**
     * Path-traversal ("zip slip") entries must be rejected without writing outside the destination.
     */
    public void testZipSlipEntryIsRejected() throws IOException {
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("../escaped.txt", "evil");
        Path zip = this.createZip("slip.zip", entries);

        Path out = this.tempDestinationDirectory.resolve("slip-out");
        Files.createDirectories(out);

        Assert.assertThrows(IOException.class, () -> Unzip.unzip(zip, out));
        Assert.assertFalse(
                "Traversal entry must not be written outside the destination",
                Files.exists(this.tempDestinationDirectory.resolve("escaped.txt")));
    }

    /**
     * Helper that builds a ZIP file from an ordered map of entry name to content. A {@code null}
     * content value writes a directory entry (the name should end with {@code /}).
     */
    private Path createZip(String zipName, Map<String, String> entries) throws IOException {
        Path zip = this.tempDestinationDirectory.resolve(zipName);
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(Files.newOutputStream(zip))) {
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                zipOutputStream.putNextEntry(new ZipEntry(entry.getKey()));
                if (entry.getValue() != null) {
                    zipOutputStream.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                }
                zipOutputStream.closeEntry();
            }
        }
        return zip;
    }
}
