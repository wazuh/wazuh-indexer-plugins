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

import org.opensearch.env.Environment;
import reactor.util.annotation.NonNull;

import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.StandardOpenOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/*
 * Unzip utility class for extracting ZIP files.
 *
 * Environment will contain the configuration of the enclosed directory where the unzip process will happen.
 */
public class Unzip {

    private static final byte[] BUFFER = new byte[1024];
    private final Environment environment;

    public Unzip(Environment environment) {
        this.environment = environment;
    }

    /*
     * Unzips a ZIP file's content in a specified folder.
     *
     * @param zipFilePath Origin ZIP file path following the format: "path/file.zip".
     * @param destinationDirectory Unzipped files destiny path following the format: "path/".
     */
    public void unzip(@NonNull String zipFilePath, @NonNull String destinationDirectory)
            throws IOException, NullPointerException {
        if (zipFilePath == null || destinationDirectory == null) {
            throw new NullPointerException("Can't have null args");
        }
        Path zipPath = this.environment.resolveRepoFile(zipFilePath);
        if (zipPath == null || !Files.exists(zipPath)) {
            throw new FileNotFoundException("ZIP file does not exist: " + zipFilePath);
        }
        Path destinationPath = this.environment.resolveRepoFile(destinationDirectory);
        try (ZipInputStream zipInputStream = new ZipInputStream(Files.newInputStream(zipPath))) {
            ZipEntry entry;
            while ((entry = zipInputStream.getNextEntry()) != null) {
                Path destinationFile = destinationPath.resolve(entry.getName()).normalize();
                if (!destinationFile.startsWith(destinationPath)) {
                    throw new IOException("Bad zip entry: " + entry.getName());
                }
                extractFile(zipInputStream, destinationFile);
                zipInputStream.closeEntry();
            }
        }
    }

    /*
     * Extracts a file from a ZIP input stream.
     *
     * @param zipInputStream ZIP input stream.
     * @param destinationFile Path (directory) where the file will be extracted.
     */
    public static void extractFile(ZipInputStream zipInputStream, Path destinationFile)
            throws IOException {
        Files.createDirectories(destinationFile.getParent()); // Ensure parent directories exist

        try (BufferedOutputStream bufferedOutputStream =
                new BufferedOutputStream(
                        Files.newOutputStream(
                                destinationFile,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.TRUNCATE_EXISTING))) {
            int size;
            while ((size = zipInputStream.read(BUFFER)) > 0) {
                bufferedOutputStream.write(BUFFER, 0, size);
            }
        } catch (IOException e) {
            throw new IOException(e.getMessage());
        }
    }
}
